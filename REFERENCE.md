# Reference Document about Project Specifics
## Agentic Lateral Movement Detection System
### Neo4j + MCP Servers + LiteLLM + Navigator AI | LANL Cybersecurity Dataset (Days 2–9)

---

## 1. Research Context

### 1.1 Research Question
Can an LLM-orchestrated Knowledge Graph detect lateral movement and host compromise more precisely than traditional relational pipelines using behavioral signals from authentication and process events?

### 1.2 Dataset
- **Source:** LANL Cybersecurity Dataset (https://csr.lanl.gov/data/cyber1/)
- **Ingestion sources:** `auth.txt` and `proc.txt` (days 2–9 only)
- **Ground truth:** `redteam.txt` — used ONLY as an external evaluator, never loaded into Neo4j
- **Excluded:** `flows.txt` (hardware constraint — 16GB RAM laptop)

### 1.3 Key Design Decisions
- `redteam.txt` is a flat file evaluator only. The agent must never see it or know an event is a confirmed compromise.
- All process names, usernames, and host names are anonymized in LANL (e.g., `P131`, `C17`, `U456`). No CVE or CPE enrichment is possible or valid.
- Behavioral anomaly detection is the core signal — patterns over time, not named software.
- Time values are LANL internal integers (elapsed seconds), not Unix epoch timestamps.

---

## 2. Final Neo4j Schema

### 2.1 Node Types

| Node Label | Property |
|------------|----------|
| `User` | `username` (string) — e.g., `U456@DOM1` |
| `Computer` | `name` (string) — e.g., `C17` |

### 2.2 Relationship Types

| Relationship | Direction | Properties                                                                                                                              |
|---|---|-----------------------------------------------------------------------------------------------------------------------------------------|
| `AUTHENTICATED_TO` | User → Computer | `time` (long), `auth_type` (string), `logon_type` (string), `orientation` (string), `status` (string — values are `"Success"` or `"Fail"`) |
| `EXECUTED` | User → Computer | `time` (long), `process_name` (string), `event_type` (string)                                                                           |

### 2.3 Removed From Schema
- **Process nodes** — anonymized names (`P131`) carry no semantic value as standalone nodes
- **HAS_PROCESS relationships** — redundant to `EXECUTED` edge properties
- **OWNS relationships** — derived from `src_device` in auth logs, not true ownership; replaced by dynamic query

### 2.4 .env File Structure
```
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password
NAVIGATOR_API_KEY=your_key
NAVIGATOR_API_BASE=your_university_endpoint
NAVIGATOR_MODEL=gpt-4o
REDTEAM_PATH=data/redteam.txt
```

### 2.5 Project Structure
```
cis6930sp26-project/
├── REFERENCE.md
├── .env
├── uv.lock
├── src/
│   ├── servers/
│   │   ├── behavioral_server.py
│   │   ├── topology_server.py
│   │   └── investigation_server.py
│   ├── agent/
│   │   └── orchestrator.py        # system prompt is built dynamically here
│   ├── evaluation/
│   │   ├── evaluator.py
│   │   ├── baseline_cypher.py
│   │   └── metrics.py
│   └── utils/
│       ├── performance_tracker.py
│       └── distribution_analysis.py
├── data/
│   └── redteam.txt
└── evaluation/
    └── results.json               # written by evaluator.py
```

---

## 3. MCP Server Specifications

Each MCP server is a standalone Python file. Each tool accepts a typed input, executes a Cypher query against Neo4j, and returns structured JSON. The LLM never writes Cypher — it only calls tools by name with parameters.

All Neo4j credentials are loaded via `load_dotenv()` from the `.env` file. No hardcoded credentials anywhere.

---

### Server 1: Behavioral Server (`behavioral_server.py`)

**Purpose:** Answers whether a user or host is behaving abnormally. In the current two-phase architecture, behavioral signals are used in **Phase 1 Discovery** — the orchestrator runs equivalent queries directly against Neo4j (not via LLM tool calls). These tools remain available on the server but are not exposed to the LLM.

---

#### Tool 1: `get_auth_anomalies`

**Purpose:** Detects abnormal authentication patterns — failure rates, unique target counts, auth type changes.

**Input Schema:**
```json
{
  "username": "string",
  "start_time": "int",
  "end_time": "int"
}
```

**Cypher Query:**
```cypher
MATCH (u:User {username: $username})-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time >= $start_time AND a.time <= $end_time
WITH u,
     count(a) as total_attempts,
     sum(CASE WHEN a.status = "Success" THEN 1 ELSE 0 END) as failed_attempts,
     collect(DISTINCT c.name) as target_computers,
     collect(DISTINCT a.auth_type) as auth_types_used
RETURN u.username as username,
       total_attempts,
       failed_attempts,
       round(toFloat(failed_attempts)/total_attempts * 100, 2) as failure_rate_pct,
       size(target_computers) as unique_targets,
       target_computers,
       auth_types_used
```

**Rationale:** High `failure_rate_pct` combined with many `unique_targets` is a classic credential stuffing / lateral movement signal. `auth_types_used` detects protocol downgrade attacks (e.g., NTLM appearing on a Kerberos account).

---

#### Tool 2: `get_first_time_authentications`

**Purpose:** Finds user-computer pairs where no prior authentication existed before the investigation window. One of the strongest lateral movement indicators.

**Input Schema:**
```json
{
  "username": "string",
  "start_time": "int",
  "end_time": "int"
}
```

**Cypher Query:**
```cypher
MATCH (u:User {username: $username})-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time >= $start_time AND a.time <= $end_time
AND a.status = "Success"
WITH u, c, min(a.time) as first_seen_in_window
WHERE NOT EXISTS {
    MATCH (u)-[a2:AUTHENTICATED_TO]->(c)
    WHERE a2.time < $start_time
    AND a2.status = "Success"
}
RETURN u.username as username,
       c.name as computer,
       first_seen_in_window as first_auth_time
ORDER BY first_auth_time ASC
```

**Rationale:** A red team actor using compromised credentials will almost always authenticate to machines that account has never touched before. This query surfaces new relationships that did not exist prior to the window — the structural fingerprint of lateral movement.

---

#### Tool 3: `get_process_anomalies`

**Purpose:** Identifies processes executed by a user on a specific host that they have never run there before the investigation window.

**Input Schema:**
```json
{
  "username": "string",
  "computer": "string",
  "start_time": "int",
  "end_time": "int"
}
```

**Cypher Query:**
```cypher
MATCH (u:User {username: $username})-[e:EXECUTED]->(c:Computer {name: $computer})
WHERE e.time >= $start_time AND e.time <= $end_time
WITH u, c, collect(DISTINCT e.process_name) as processes_in_window
MATCH (u)-[e2:EXECUTED]->(c)
WHERE e2.time < $start_time
WITH u, c, processes_in_window,
     collect(DISTINCT e2.process_name) as historical_processes
WITH u, c,
     [p IN processes_in_window WHERE NOT p IN historical_processes] as new_processes,
     size(processes_in_window) as total_in_window
RETURN u.username as username,
       c.name as computer,
       new_processes,
       size(new_processes) as new_process_count,
       total_in_window
```

**Rationale:** Novel process execution on a newly accessed host is a second-layer corroboration signal. Process names are anonymized but behavioral novelty is still meaningful. Note: this tool returns sparse results in practice — process events are sparser than auth events in the LANL dataset.

---

### Server 2: Topology Server (`topology_server.py`)

**Purpose:** Answers how connected and structurally significant a host is. Called in **Phase 2** by the LLM. This is where the Knowledge Graph demonstrably outperforms SQL — expressing network reachability and pivot point identification through graph traversal.

---

#### Tool 4: `get_host_centrality`

**Purpose:** Approximates betweenness centrality by counting distinct users authenticating to a host. High counts indicate pivot point hosts.

**Input Schema:**
```json
{
  "computer": "string",
  "start_time": "int",
  "end_time": "int"
}
```

**Cypher Query:**
```cypher
MATCH (u:User)-[a:AUTHENTICATED_TO]->(c:Computer {name: $computer})
WHERE a.time >= $start_time AND a.time <= $end_time
WITH c,
     count(DISTINCT u) as unique_users,
     count(a) as total_auth_events,
     sum(CASE WHEN a.status = "Fail" THEN 1 ELSE 0 END) as failed_auths,
     collect(DISTINCT u.username) as users
RETURN c.name as computer,
       unique_users,
       total_auth_events,
       failed_auths,
       users
ORDER BY unique_users DESC
```

**Rationale:** Full GDS Betweenness Centrality over 54M edges is computationally infeasible on a 16GB laptop. This approximation captures the same insight: a host with many distinct authenticating users is structurally critical. Compromising it grants access to many credentials.

---

#### Tool 5: `get_lateral_movement_path`

**Purpose:** Reconstructs the chronological sequence of hosts a user authenticated to within the investigation window. In the LANL dataset, `src_host` from `redteam.txt` represents the attacker's originating machine and does not appear as an authentication *destination* in auth logs — so movement chains are reconstructed from sequential auth events to destination hosts.

**Input Schema:**
```json
{
  "username": "string",
  "start_time": "int",
  "end_time": "int"
}
```

**Cypher Query:**
```cypher
MATCH (u:User {username: $username})-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time >= $start_time AND a.time <= $end_time
AND a.status = "Success"
RETURN u.username as username,
       c.name as computer,
       a.time as auth_time,
       a.auth_type as auth_type
ORDER BY a.time ASC
```

**Returns:** Ordered authentication chain for the user (`chain` list of `{computer, auth_time, auth_type}`).

**Rationale:** A rapid sequence of authentications to multiple distinct hosts is a strong lateral movement indicator. The `time_delta` between consecutive hops is the key signal — short deltas (under 300 seconds) indicate automated or scripted movement.

---

#### Tool 6: `get_host_neighbors` *(commented out — performance issue)*

**Status:** Disabled. The query is implemented but commented out in `topology_server.py` due to timeout issues on large windows. It is not registered as an MCP tool and is not available to the LLM.

**Original purpose:** Returns all computers reachable from a given host within one authentication hop — defines the blast radius of a compromised host.

**Cypher Query (disabled):**
```cypher
MATCH (src:Computer {name: $computer})<-[a1:AUTHENTICATED_TO]-(u:User)
      -[a2:AUTHENTICATED_TO]->(dst:Computer)
WHERE a1.time >= $start_time AND a1.time <= $end_time
AND a2.time >= $start_time AND a2.time <= $end_time
AND dst.name <> $computer
AND a1.status = "Success"
RETURN DISTINCT dst.name as reachable_computer,
       collect(DISTINCT u.username) as via_users,
       count(DISTINCT u) as user_count
ORDER BY user_count DESC
```

---

### Server 3: Investigation Server (`investigation_server.py`)

**Purpose:** Aggregates evidence once suspicious activity is already identified. Called in **Phase 2** by the LLM. Outputs directly feed the Explainability Score metric and the agent's natural language justification.

---

#### Tool 7: `get_user_timeline`

**Purpose:** Returns a full chronological event timeline for a user, interleaving authentication and process events.

**Input Schema:**
```json
{
  "username": "string",
  "start_time": "int",
  "end_time": "int"
}
```

**Cypher Query:**
```cypher
MATCH (u:User {username: $username})
OPTIONAL MATCH (u)-[a:AUTHENTICATED_TO]->(c1:Computer)
WHERE a.time >= $start_time AND a.time <= $end_time
OPTIONAL MATCH (u)-[e:EXECUTED]->(c2:Computer)
WHERE e.time >= $start_time AND e.time <= $end_time
WITH u,
     collect(DISTINCT {
         event_type: 'AUTH',
         time: a.time,
         computer: c1.name,
         success: a.status,
         auth_type: a.auth_type,
         detail: a.logon_type
     }) as auth_events,
     collect(DISTINCT {
         event_type: 'PROCESS',
         time: e.time,
         computer: c2.name,
         process_name: e.process_name,
         event_type_detail: e.event_type
     }) as process_events
RETURN u.username as username,
       auth_events,
       process_events,
       size(auth_events) as total_auth_events,
       size(process_events) as total_process_events
```

**Rationale:** Gives the LLM a complete narrative of what a user did during the investigation window. Interleaving auth and process events enables sequence reasoning — e.g., authenticated to host `C17` at `T=5000`, then executed new process `P445` at `T=5003` is a much stronger signal than either event alone.

---

#### Tool 8: `get_host_activity_summary`

**Purpose:** Returns all activity on a given host within the investigation window — all users, all processes, all auth events.

**Input Schema:**
```json
{
  "computer": "string",
  "start_time": "int",
  "end_time": "int"
}
```

**Cypher Query:**
```cypher
MATCH (c:Computer {name: $computer})
OPTIONAL MATCH (u:User)-[a:AUTHENTICATED_TO]->(c)
WHERE a.time >= $start_time AND a.time <= $end_time
OPTIONAL MATCH (u2:User)-[e:EXECUTED]->(c)
WHERE e.time >= $start_time AND e.time <= $end_time
WITH c,
     count(DISTINCT u) as unique_auth_users,
     count(a) as total_auths,
     sum(CASE WHEN a.status = "Success" THEN 1 ELSE 0 END) as failed_auths,
     collect(DISTINCT u.username) as auth_users,
     count(DISTINCT u2) as unique_exec_users,
     collect(DISTINCT e.process_name) as processes_executed,
     count(e) as total_executions
RETURN c.name as computer,
       unique_auth_users,
       total_auths,
       failed_auths,
       auth_users,
       unique_exec_users,
       processes_executed,
       total_executions
```

**Rationale:** Answers who was on this machine and what was running — essential for blast radius assessment and scoping the full impact of a compromise.

---

#### Tool 9: `get_concurrent_sessions`

**Purpose:** Finds other users who were active on the same host at approximately the same time as the suspicious event.

**Input Schema:**
```json
{
  "computer": "string",
  "time": "int",
  "window": "int"
}
```

**Cypher Query:**
```cypher
MATCH (u:User)-[a:AUTHENTICATED_TO]->(c:Computer {name: $computer})
WHERE a.time >= ($time - $window)
AND a.time <= ($time + $window)
AND a.status = "Success"
RETURN u.username as username,
       a.time as auth_time,
       a.auth_type as auth_type,
       abs(a.time - $time) as time_delta_from_event
ORDER BY time_delta_from_event ASC
```

**Rationale:** Detects whether a compromise event coincided with other unusual access. Multiple users authenticating to the same host within seconds of a red team event indicates either a coordinated attack or a high-value shared resource. Recommend `window = 300`.

---

## 4. Agent Orchestration

### 4.1 Architecture Overview — Two-Phase Blind Investigation

The orchestrator (`orchestrator.py`) uses a **two-phase blind investigation** approach. No usernames or hostnames are ever given as inputs — the agent discovers suspicious entities from behavioral signals alone.

```
investigate_window(start_time, end_time) -> dict
```

**Phase 1 — Discovery (orchestrator-level, no LLM):**
Three Cypher queries run directly against Neo4j to surface candidate suspicious users from behavioral signals only. The LLM never sees this phase.

**Phase 2 — Investigation (LLM-driven, entity-centric):**
The top-3 ranked candidates from Phase 1 are injected into the system prompt. The LLM selects which topology and investigation tools to call per candidate and produces a final structured verdict.

---

### 4.2 Phase 1 — Discovery Queries

The orchestrator runs these three queries directly against Neo4j (not via MCP tools):

**Query 1: Auth Anomaly Discovery** — users with high failure rate (>30%) or many distinct targets (≥4):
```cypher
MATCH (u:User)-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time >= $start_time AND a.time <= $end_time
WITH u,
     count(a) AS total_attempts,
     sum(CASE WHEN a.status = 'Fail' THEN 1 ELSE 0 END) AS failed_attempts,
     count(DISTINCT c) AS unique_targets
WITH u, total_attempts, failed_attempts, unique_targets,
     CASE WHEN total_attempts > 0
          THEN round(toFloat(failed_attempts) / toFloat(total_attempts) * 100, 2)
          ELSE 0.0 END AS failure_rate_pct
WHERE failure_rate_pct > 30.0 OR unique_targets >= 4
RETURN u.username AS username, total_attempts, failed_attempts,
       failure_rate_pct, unique_targets
ORDER BY failure_rate_pct DESC, unique_targets DESC
LIMIT 20
```

**Query 2: First-Time Auth Discovery** — users who successfully authenticated to hosts they had never accessed before:
```cypher
MATCH (u:User)-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time >= $start_time AND a.time <= $end_time AND a.status = 'Success'
WITH u, c, min(a.time) AS first_seen_in_window
WHERE NOT EXISTS {
    MATCH (u)-[prev:AUTHENTICATED_TO]->(c)
    WHERE prev.time < $start_time AND prev.status = 'Success'
}
WITH u, count(c) AS new_host_count
WHERE new_host_count >= 1
RETURN u.username AS username, new_host_count
ORDER BY new_host_count DESC
LIMIT 20
```

**Query 3: Process Anomaly Discovery** — users who authenticated to hosts in the window that they had never accessed historically:
```cypher
MATCH (u:User)-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time < 150000 AND a.status = 'Success'
WITH u, collect(DISTINCT c.name) AS historical_hosts
MATCH (u)-[b:AUTHENTICATED_TO]->(c2:Computer)
WHERE b.time >= 150000 AND b.time <= 157200 AND b.status = 'Success'
WITH u, historical_hosts, collect(DISTINCT c2.name) AS window_hosts
WITH u,
     [h IN window_hosts WHERE NOT h IN historical_hosts] AS new_hosts
WHERE size(new_hosts) >= 1
RETURN u.username AS username, size(new_hosts) AS new_host_count
ORDER BY new_host_count DESC
LIMIT 20
```

**Candidate ranking:** Each query contributes a list of usernames. A `Counter` tallies cross-query frequency. The top-3 by frequency become the `ranked_candidates` passed to Phase 2.

If zero candidates are found, Phase 2 is skipped entirely and the result is returned immediately with `severity = LOW`.

---

### 4.3 Phase 2 — LLM Investigation

**Tools available to the LLM (Phase 2 only):**

| Tool | Server |
|------|--------|
| `get_lateral_movement_path` | `topology_server.py` |
| `get_host_centrality` | `topology_server.py` |
| `get_user_timeline` | `investigation_server.py` |
| `get_host_activity_summary` | `investigation_server.py` |
| `get_concurrent_sessions` | `investigation_server.py` |

Behavioral tools (`get_auth_anomalies`, `get_first_time_authentications`, `get_process_anomalies`) are **not** exposed to the LLM — they are Phase 1 only.
`get_host_neighbors` is excluded (disabled).

**Tool dispatch:** The orchestrator calls server functions directly (not via subprocess MCP protocol):
```python
_TOOL_DISPATCH = {
    "get_lateral_movement_path": topology_server.get_lateral_movement_path,
    "get_host_centrality": topology_server.get_host_centrality,
    "get_user_timeline": investigation_server.get_user_timeline,
    "get_host_activity_summary": investigation_server.get_host_activity_summary,
    "get_concurrent_sessions": investigation_server.get_concurrent_sessions,
}
```

**Hard limits:**
- `_MAX_ITERATIONS = 20` — max total tool calls (Phase 1 + Phase 2 combined)
- `MAX_RESULT_CHARS = 2000` — tool result truncation limit
- Context limit guard: raises `RuntimeError` if estimated tokens exceed 50,000

**LLM config:**
- Model: `openai/{NAVIGATOR_MODEL}` via LiteLLM
- `base_url`: `NAVIGATOR_API_BASE` env var
- `temperature=0`, `max_tokens=1000`
- Token estimation via `tiktoken` (gpt-4o encoding)

---

### 4.4 System Prompt (Dynamic)

The system prompt is built at runtime by `_build_system_prompt(candidates, start_time, end_time)` in `orchestrator.py`. There is no separate `system_prompt.py`.

```
You are a security investigator. You will first call discovery tools to identify
suspicious entities from behavioral signals alone. Only after discovery will you
investigate specific entities. Never assume who is suspicious — let the data tell you.

Phase 1 discovery is already complete. Never call Phase 2 tools before Phase 1 is complete.

The following candidate users were identified from behavioral signals (high authentication
failure rates, first-time authentications to new hosts, novel process executions):

CANDIDATES: {candidate_str}

---

PHASE 2 — INVESTIGATION

Investigate each candidate using the available tools. Use start_time={start_time} and
end_time={end_time} for all tool calls that require a time window.

RULES:
- Do not call all tools on every candidate blindly — use judgment about which tools add signal.
- Do not repeat tool calls with identical parameters.
- Time values are LANL internal integers, not Unix timestamps.
- A rapid sequence of authentications to multiple hosts = strong lateral movement signal.
- If a tool returns empty results, note it and move on.
- You have a limited tool call budget. Prioritize the most informative tools.

---

FINAL OUTPUT FORMAT

After investigation, produce exactly this structure — nothing before it:

SEVERITY: HIGH / MEDIUM / LOW
FLAGGED_USERS: comma-separated list of suspicious usernames (or NONE)
FLAGGED_HOSTS: comma-separated list of suspicious host names (or NONE)
NARRATIVE: [one to three paragraphs — summarize evidence, attack path if found, and reasoning]
```

---

### 4.5 Output Parsing

The orchestrator parses the LLM's final text output with three regex patterns:
- `SEVERITY\s*:\s*(HIGH|MEDIUM|LOW)` → `severity`
- `FLAGGED_USERS\s*:\s*([^\n]+)` → `flagged_users` (list)
- `FLAGGED_HOSTS\s*:\s*([^\n]+)` → `flagged_hosts` (list)

If no `SEVERITY` match is found, defaults to `LOW`.

**Return dict from `investigate_window()`:**
```json
{
  "window":          {"start": int, "end": int},
  "flagged_users":   ["U456@DOM1", ...],
  "flagged_hosts":   ["C17", ...],
  "verdict":         "free-text LLM narrative",
  "severity":        "HIGH / MEDIUM / LOW",
  "tool_calls_made": int
}
```

**`investigate_event(username, dst_host, timestamp)` — used by entity evaluator:**

Accepts a known entity from a redteam event. Builds a ±3600 s window around `timestamp`, injects the single username as the sole candidate into `_build_system_prompt`, then runs Phase 2 (LLM tool loop) only. The agent receives no label — it determines severity from behavioral signals alone.

```json
{
  "event":           {"username": str, "dst_host": str, "timestamp": int},
  "flagged_users":   ["U456@DOM1", ...],
  "flagged_hosts":   ["C17", ...],
  "verdict":         "free-text LLM narrative",
  "severity":        "HIGH / MEDIUM / LOW",
  "tool_calls_made": int
}
```

---

### 4.6 Time Windows
- Phase 1 discovery queries use the full `[start_time, end_time]` window passed in
- Phase 2 LLM tool calls use the same `start_time` / `end_time` injected via system prompt
- `get_concurrent_sessions` uses a tighter `window = 300` (±300 seconds around event time)

---

## 5. Evaluation Design

### 5.1 Evaluation Modes (`evaluator.py`)

Two modes, selected via `--mode` CLI flag:

**`window` mode (recall-only, default):**
```
Parse redteam.txt for timestamps only (user/host columns ignored).
Filter to fixed window [763200, 764600].
Call investigate_event(username, dst_host, timestamp) for each event sequentially.
Score: severity in {HIGH, MEDIUM} → TP; severity == LOW → FN.
Output: evaluation/results_YYYYMMDD_HHMMSS.json
```

**`entity` mode (precision + recall + F1, concurrent):**
```
Stage 1 — Case construction:
    Parse redteam.txt. Filter to fixed window [763200, 764600].
    Shuffle and cap at --sample-size (default 20) → TP cases.
    Query Neo4j for control candidates from CONTROL_WINDOW_START=767000
    to CONTROL_WINDOW_END=770400 (quiet post-attack window, no redteam events).
    Control filters: exclude machine accounts ($), ANONYMOUS users, and any
    username appearing anywhere in redteam.txt.
    Build balanced case list: TP cases + equal number of FP control cases.

Stage 2 — Concurrent investigation:
    Run investigate_event() on all cases via ThreadPoolExecutor(max_workers=3).
    MAX_CONCURRENT_INVESTIGATIONS = 3 (stays within 120 RPM Navigator limit;
    3 concurrent × ~4 LLM calls each ≈ 12 calls/min peak).
    Results arrive via as_completed() and are flushed to disk after each case.
    HTTP 429 from Navigator: sleep 10 s, record case as error, no retry.
    elapsed_seconds per case = individual wall time for that investigation.
    total_elapsed_seconds in meta = executor wall time (submit → last future done).

Stage 3 — Scoring:
    is_redteam=True  + severity in {HIGH,MEDIUM} → TP
    is_redteam=True  + severity == LOW            → FN
    is_redteam=False + severity in {HIGH,MEDIUM}  → FP
    is_redteam=False + severity == LOW            → TN
    Compute precision, recall, F1. Print summary.
Output: evaluation/entity_results_YYYYMMDD_HHMMSS.json
```

**Helper functions extracted from `run_entity_evaluation()`:**
- `_flush_results(results, output_path)` — incremental JSON write after each completed future
- `_score_result(result)` — returns `"TP"/"TN"/"FP"/"FN"` from `is_redteam` + `severity`

**Entry point:**
```bash
uv run python -m src.evaluation.evaluator --mode window
uv run python -m src.evaluation.evaluator --mode entity --sample-size 20
```

### 5.2 Metrics

| Metric | Definition |
|--------|------------|
| Precision | `TP / (TP + FP)` — of all flagged windows, how many had real redteam activity |
| Recall | `TP / (TP + FN)` — of all windows with redteam activity, how many were caught |
| F1 | Harmonic mean of precision and recall |

True Positive definition: `flagged_users ∩ redteam_users ≠ ∅` OR `flagged_hosts ∩ redteam_hosts ≠ ∅` in the same window.

### 5.3 Baselines

| Baseline | File | Approach |
|----------|------|----------|
| Baseline A (SQL) | *(external)* | Join auth table: flag users with `failure_rate > threshold` across N distinct hosts within window. No graph traversal. |
| Baseline B (Static Cypher) | `src/evaluation/baseline_cypher.py` | Fixed Cypher query: find users who authenticated to a new host within the window. No LLM reasoning, no multi-tool orchestration. |

Both baselines evaluate against the same `redteam.txt` events using the same precision/recall methodology.

---

## 6. Build Order

Follow this exact order. Do not begin the orchestrator until all MCP servers are independently tested.

| Step | Task |
|------|------|
| 1 | Build `behavioral_server.py` — all three tools. Test each Cypher query in Neo4j browser before wiring up. |
| 2 | Build `topology_server.py` — two active tools (`get_host_centrality`, `get_lateral_movement_path`). |
| 3 | Build `investigation_server.py` — all three tools. |
| 4 | Build `orchestrator.py` — Phase 1 discovery queries + Phase 2 LLM loop. Test with `investigate_window(763200, 770000)`. System prompt is built dynamically inside this file — no separate `system_prompt.py`. |
| 5 | Build `evaluator.py` — iterate over `redteam.txt` windows, collect verdicts, score. |
| 6 | Build `metrics.py` — compute precision, recall, F1. |
| 7 | Build `baseline_cypher.py` — static Cypher baseline for comparison. |

---

## 7. Critical Constraints

- **Hardware:** 16GB RAM. Never run full GDS Betweenness Centrality — use `get_host_centrality` approximation instead.
- **redteam.txt:** Never load into Neo4j. Never expose to the agent. Flat file evaluator only.
- **Time:** All timestamps are LANL internal integers. Do not convert to Unix time. Use relative arithmetic only.
- **Process names:** Anonymized (`P131`). No CVE or CPE mapping. Behavioral novelty only.
- **Tool calling:** Verify Navigator AI model supports tool/function calling before building orchestrator. GPT-4o recommended over Llama variants for reliability.
- **Credentials:** Always load via `load_dotenv()` from `.env`. No hardcoded keys anywhere.
- **Blind investigation:** The orchestrator never accepts usernames or hostnames as input — only a time window. Entity discovery is purely signal-driven.
- **`get_host_neighbors` disabled:** Do not re-enable without adding a LIMIT or index hint — the two-hop query is unresponsive on large windows.
- **Phase 1 process anomaly query:** Uses hardcoded time boundaries (`150000`, `157200`) — update these if evaluating different day windows.
