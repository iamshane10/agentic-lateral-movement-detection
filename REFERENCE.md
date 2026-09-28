# Reference Document — Agentic Lateral Movement Detection System
### Neo4j + MCP Servers + LiteLLM + Navigator AI | LANL Cybersecurity Dataset

---

## 1. Research Context

### 1.1 Research Question
To what extent does an LLM-orchestrated Knowledge Graph (KG) improve the precision and recall of lateral movement detection compared to a static rule-based Cypher baseline, using only behavioral signals from authentication and process execution logs?

### 1.2 Research Direction
**Direction B — Comparative Analysis:** Agentic AI vs. Traditional Data Pipeline.

The core claim is that a two-phase AI agent, reasoning over a graph schema, can identify lateral movement events more accurately than a fixed detection rule applied to the same graph. Behavioral novelty (new relationships, new hosts, new processes) is the only signal — no CVE enrichment, no named-software heuristics.

### 1.3 Dataset
- **Source:** LANL Publicly Available Computer Network Dataset — https://csr.lanl.gov/data/cyber1/
- **Files used:** `auth.txt` (authentication events), `proc.txt` (process execution events)
- **File excluded:** `flows.txt` — hardware constraint (16GB RAM laptop)
- **Ground truth:** `redteam.txt` — format: `timestamp,username,src_host,dst_host`, one event per line
- **Anonymization:** All usernames (`U456@DOM1`), computer names (`C17`), and process names (`P131`) are anonymized in the dataset. No CVE or CPE mapping is valid.
- **Time encoding:** LANL internal integers (elapsed seconds since dataset start), **not** Unix epoch timestamps.

### 1.4 Key Design Decisions
- `redteam.txt` is the evaluation oracle only. It is never loaded into Neo4j and never exposed to the agent.
- Behavioral anomaly detection is the sole detection mechanism — patterns over time, not named software or CVEs.
- The agent investigates blind: it receives no entity identities as inputs in `investigate_window()`, and receives no label in `investigate_event()`.
- Two time windows are used: a **hot window** `[763200, 770400]` containing confirmed red team events (TP cases), and a **cold window** `[633600, 640800]` (pre-attack, no red team activity) that provides prior authentication history. Control cases are sampled from `[767000, 770400]` (inside the hot window period) so they have the same prior history depth as red team cases.

---

## 2. Stack and Dependencies

| Component | Technology |
|-----------|------------|
| Graph DB | Neo4j (bolt://localhost:7687) |
| LLM integration | LiteLLM + Navigator AI (GPT-4o endpoint) |
| ETL engine | DuckDB (in-memory) |
| MCP framework | `mcp` with FastMCP |
| Package manager | `uv` (Python ≥ 3.14 required) |
| Language | Python 3.14+ |
| Key packages | `duckdb`, `litellm`, `mcp[cli]`, `neo4j`, `psutil`, `python-dotenv`, `tiktoken` |

### 2.1 Required `.env` File
```
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password
NAVIGATOR_API_KEY=your_key
NAVIGATOR_API_BASE=your_university_endpoint
NAVIGATOR_MODEL=gpt-4o
AUTH_DATASET_PATH=/path/to/auth.txt
PROC_DATASET_PATH=/path/to/proc.txt
REDTEAM_PATH=data/redteam.txt
```

### 2.2 Project Structure
```
cis6930sp26-project/
├── REFERENCE.md
├── CLAUDE.md
├── README.md
├── pyproject.toml
├── .env
├── uv.lock
├── data/
│   ├── users.csv                   # ETL output — Neo4j node import
│   ├── computers.csv               # ETL output — Neo4j node import
│   ├── authentications.csv         # ETL output — Neo4j relationship import
│   ├── process_events.csv          # ETL output — Neo4j relationship import
│   ├── cold_events.txt             # Control cases (generate_cold_events.py output)
│   ├── eval_cases.txt              # Fixed balanced case list (generate_eval_cases.py output) — grading file
│   └── redteam.txt                 # Ground truth — NEVER load into Neo4j
├── src/
│   ├── pipeline/
│   │   └── etl.py                  # DuckDB ETL → 4 Neo4j-ready CSVs
│   ├── servers/
│   │   ├── behavioral_server.py    # Phase 1 tools (orchestrator-only)
│   │   ├── topology_server.py      # Phase 2 tools: centrality, path
│   │   └── investigation_server.py # Phase 2 tools: timeline, activity, sessions
│   ├── agent/
│   │   └── orchestrator.py         # Two-phase agent: investigate_window(), investigate_event()
│   ├── evaluation/
│   │   ├── evaluator.py            # Window mode + entity mode evaluation
│   │   ├── baseline_evaluator.py   # Static 3-signal Cypher baseline
│   │   ├── metrics.py              # Precision / recall / F1 + comparison table
│   │   └── generate_cold_events.py # One-time control case generation
│   └── utils/
│       ├── performance_tracker.py  # ETL timing and memory tracking
│       └── distribution_analysis.py
├── evaluation/
│   └── (results written here at runtime)
└── proposal/
    └── proposal.md
```

---

## 3. ETL Pipeline (`src/pipeline/etl.py`)

### 3.1 Overview
Reads raw LANL `auth.txt` and `proc.txt` via DuckDB in-memory, filters to two time windows, and exports 4 Neo4j-ready CSVs. Performance metrics (timing, memory, row counts) are tracked by `PerformanceTracker` and saved to `data/etl_report.md` and `data/etl_metrics.json`.

### 3.2 Time Windows
| Window | Start | End | Purpose |
|--------|-------|-----|---------|
| Hot (attack) | 763200 | 770400 | Contains confirmed red team events — TP cases |
| Cold (history) | 633600 | 640800 | Pre-attack quiet period — prior history for all cases |

Both windows are retained in the exported CSVs. The ETL is a union filter:
```sql
WHERE (time >= 763200 AND time <= 770400)
   OR (time >= 633600 AND time <= 640800)
```

### 3.3 Node Construction
- **`users.csv`:** `DISTINCT` union of `src_user`, `dst_user` (from auth) and `user_domain` (from proc). Header: `username:ID(User)`
- **`computers.csv`:** `DISTINCT` union of `src_device`, `dst_device` (from auth) and `computer` (from proc). Header: `name:ID(Computer)`

Node tables include **all** users and computers across the entire dataset (not just the two windows) to preserve full historical context for baseline lookups.

### 3.4 Relationship Construction
- **`authentications.csv`:** Columns: `time`, `src_user` → `:START_ID(User)`, `dst_device` → `:END_ID(Computer)`, `auth_type`, `logon_type`, `orientation`, `status`. Filtered to the two windows only.
- **`process_events.csv`:** Columns: `time`, `user_domain` → `:START_ID(User)`, `computer` → `:END_ID(Computer)`, `process_name`, `event_type`. Filtered to the two windows only.

### 3.5 Neo4j Import Command
Run with Neo4j stopped. Requires 6GB+ Java heap:
```powershell
$env:JAVA_OPTS="-Xmx6G -Xms6G --add-opens=java.base/java.nio=ALL-UNNAMED"
.\bin\neo4j-admin database import full `
  --nodes=User=<path>\data\users.csv `
  --nodes=Computer=<path>\data\computers.csv `
  --relationships=AUTHENTICATED_TO=<path>\data\authentications.csv `
  --relationships=EXECUTED=<path>\data\process_events.csv `
  --overwrite-destination=true `
  --skip-duplicate-nodes=true `
  --multiline-fields=true `
  --skip-bad-relationships=true `
  --bad-tolerance=1000 `
  --ignore-empty-strings=true `
  --threads=4
```
Expected import time: ~12 minutes. Install Neo4j Graph Data Science plugin after import.

---

## 4. Neo4j Schema

### 4.1 Node Types
| Label | Property | Example |
|-------|----------|---------|
| `User` | `username` (string) | `U456@DOM1` |
| `Computer` | `name` (string) | `C17` |

### 4.2 Relationship Types
| Relationship | Direction | Properties |
|---|---|---|
| `AUTHENTICATED_TO` | User → Computer | `time` (long), `auth_type` (string), `logon_type` (string), `orientation` (string), `status` (string: `"Success"` or `"Fail"`) |
| `EXECUTED` | User → Computer | `time` (long), `process_name` (string), `event_type` (string) |

### 4.3 Removed From Schema
- **Process nodes** — anonymized names (`P131`) carry no semantic value as standalone nodes
- **HAS_PROCESS relationships** — redundant to `EXECUTED` edge properties
- **OWNS relationships** — derived from `src_device` in auth logs, not true ownership; replaced by dynamic query

---

## 5. MCP Server Specifications

Three standalone Python files in `src/servers/`. Each file is fully self-contained — no shared state across servers. All credentials loaded via `load_dotenv()`. All tools return structured JSON strings. The LLM never writes Cypher — it only calls named tools.

**Tool dispatch in the orchestrator calls server functions directly (in-process), not via subprocess MCP protocol:**
```python
_TOOL_DISPATCH = {
    "get_lateral_movement_path": topology_server.get_lateral_movement_path,
    "get_host_centrality":       topology_server.get_host_centrality,
    "get_user_timeline":         investigation_server.get_user_timeline,
    "get_host_activity_summary": investigation_server.get_host_activity_summary,
    "get_concurrent_sessions":   investigation_server.get_concurrent_sessions,
    "get_user_historical_baseline": investigation_server.get_user_historical_baseline,
}
```

---

### Server 1: Behavioral Server (`behavioral_server.py`)

**Purpose:** Phase 1 discovery — detects anomalous authentication and process execution. These tools are called by the orchestrator directly (not by the LLM). They are not exposed to the LLM in Phase 2.

---

#### Tool 1: `get_auth_anomalies`

**Purpose:** Detects abnormal authentication patterns — failure rates, unique target counts, auth type changes.

**Input:** `username: str`, `start_time: int`, `end_time: int`

**Cypher:**
```cypher
MATCH (u:User {username: $username})-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time >= $start_time AND a.time <= $end_time
WITH u,
     count(a) as total_attempts,
     sum(CASE WHEN a.status = "Fail" THEN 1 ELSE 0 END) as failed_attempts,
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

**Signal:** High `failure_rate_pct` with many `unique_targets` = credential stuffing / lateral movement. `auth_types_used` detects protocol downgrade (NTLM appearing on a Kerberos account).

---

#### Tool 2: `get_first_time_authentications`

**Purpose:** Finds user-computer pairs where no prior successful authentication existed before the investigation window. Strongest lateral movement structural signal.

**Input:** `username: str`, `start_time: int`, `end_time: int`

**Cypher:**
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

**Signal:** A red team actor using compromised credentials will almost always authenticate to machines that account has never touched before — the structural fingerprint of lateral movement.

---

#### Tool 3: `get_process_anomalies`

**Purpose:** Identifies processes executed by a user on a specific host that they have never run there before.

**Input:** `username: str`, `computer: str`, `start_time: int`, `end_time: int`

**Cypher:**
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

**Signal:** Novel process execution on a newly accessed host is second-layer corroboration. Returns sparse results in practice — process events are sparser than auth events in the LANL dataset.

---

### Server 2: Topology Server (`topology_server.py`)

**Purpose:** Answers how connected and structurally significant a host is. This is where the KG demonstrably outperforms SQL — expressing network reachability and pivot point identification through graph traversal. Tools are available to the LLM in **Phase 2**.

---

#### Tool 4: `get_host_centrality`

**Purpose:** Approximates betweenness centrality by counting distinct users authenticating to a host. High counts indicate pivot point hosts.

**Input:** `computer: str`, `start_time: int`, `end_time: int`

**Cypher:**
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

**Rationale:** Full GDS Betweenness Centrality over 54M+ edges is infeasible on 16GB RAM. This approximation captures the same insight: a host with many distinct authenticating users is structurally critical. **Do not substitute full GDS Betweenness Centrality.**

---

#### Tool 5: `get_lateral_movement_path`

**Purpose:** Reconstructs the chronological authentication chain for a user. The `src_host` from `redteam.txt` represents the attacker's origin and does not appear as an auth *destination* — chains are reconstructed from sequential auth events to destination hosts.

**Input:** `username: str`, `start_time: int`, `end_time: int`

**Cypher:**
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

**Returns:** Ordered `chain` list of `{computer, auth_time, auth_type}`.

**Signal:** A rapid sequence of authentications to multiple distinct hosts is a strong lateral movement indicator. Short time deltas between consecutive hops (under 300 seconds) indicate automated or scripted movement.

---

#### Tool 6: `get_host_neighbors` *(disabled — performance)*

**Status:** Commented out in `topology_server.py`. Timeout on large windows — not registered as an MCP tool and not available to the LLM. Do not re-enable without adding a `LIMIT` clause or index hint.

**Original purpose:** Returns all computers reachable from a given host within one authentication hop (blast radius).

**Disabled Cypher:**
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

**Purpose:** Aggregates evidence once suspicious activity is identified. Called by the LLM in **Phase 2**. Outputs directly feed the agent's natural language justification and the Explainability Score metric.

---

#### Tool 7: `get_user_timeline`

**Purpose:** Returns a full chronological event timeline for a user, interleaving authentication and process events.

**Input:** `username: str`, `start_time: int`, `end_time: int`

**Cypher:**
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

**Signal:** Interleaving auth and process events enables sequence reasoning — auth to `C17` at `T=5000`, then novel process `P445` at `T=5003` is a much stronger compound signal than either event alone.

---

#### Tool 8: `get_host_activity_summary`

**Purpose:** Returns all activity on a given host — all users, all processes, all auth events. Essential for blast radius assessment.

**Input:** `computer: str`, `start_time: int`, `end_time: int`

**Cypher:**
```cypher
MATCH (c:Computer {name: $computer})
OPTIONAL MATCH (u:User)-[a:AUTHENTICATED_TO]->(c)
WHERE a.time >= $start_time AND a.time <= $end_time
WITH c,
     count(DISTINCT u) as unique_auth_users,
     count(a) as total_auths,
     sum(CASE WHEN a.status = "Fail" THEN 1 ELSE 0 END) as failed_auths,
     collect(DISTINCT u.username) as auth_users
OPTIONAL MATCH (u2:User)-[e:EXECUTED]->(c)
WHERE e.time >= $start_time AND e.time <= $end_time
WITH c, unique_auth_users, total_auths, failed_auths, auth_users,
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

Auth events are aggregated to a single row before process events are matched, so the two `OPTIONAL MATCH` clauses do not form a Cartesian product.

---

#### Tool 9: `get_concurrent_sessions`

**Purpose:** Finds other users active on the same host at approximately the same time as the suspicious event.

**Input:** `computer: str`, `time: int`, `window: int = 300`

**Cypher:**
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

**Signal:** Multiple users authenticating to the same host within seconds of a red team event indicates either a coordinated attack or a high-value shared resource. Use `window=300`.

---

#### Tool 10: `get_user_historical_baseline`

**Purpose:** Gives the agent the user's authentication history from **before** the investigation window, so it can judge what is normal for this user. The only Phase 2 tool that looks outside the window.

**Input:** `username: str`, `window_start: int` (pass the investigation `start_time`), `dst_host: str | None = None`

**Cypher:**
```cypher
MATCH (u:User {username: $username})-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time < $window_start
AND a.status = 'Success'
RETURN count(a) as total_prior_auths,
       count(DISTINCT c) as distinct_hosts_visited,
       collect(DISTINCT c.name)[0..50] as historical_hosts,
       count(DISTINCT a.time / 86400) as distinct_days,
       sum(CASE WHEN c.name = $dst_host THEN 1 ELSE 0 END) as dst_host_prior_auths
```

**Returns:** `total_prior_auths`, `distinct_hosts_visited`, `historical_hosts` (max 50), `distinct_days`, `avg_daily_auths` (`total_prior_auths / distinct_days`), and — when `dst_host` is given — `dst_host_prior_auths` and `dst_host_seen_before`.

**Notes:**
- `dst_host_seen_before` answers "has this user logged into this host before the window?" exactly; `historical_hosts` is capped at 50 and can omit the host.
- History in the graph is the cold window plus the part of the hot window before `window_start`. Days are `time // 86400` (LANL elapsed seconds, not epoch), so `distinct_days` is usually 1–2 and `avg_daily_auths` is approximate.
- For red team users, "history" includes their own earlier attack activity in the hot window — the same limitation the UA baseline has.

---

## 6. Agent Orchestration (`src/agent/orchestrator.py`)

### 6.1 Architecture Overview — Two-Phase Blind Investigation

The orchestrator uses a **two-phase blind investigation** approach:
- **Phase 1 (Discovery):** The orchestrator runs three Cypher queries directly against Neo4j to surface candidate suspicious users. No entity identities are provided as inputs. The LLM never sees this phase.
- **Phase 2 (Investigation):** Top-3 candidates from Phase 1 are injected into the system prompt. The LLM selects which tools to call per candidate and produces a final structured verdict.

**Entry points:**
```python
investigate_window(start_time: int, end_time: int) -> dict
investigate_event(username: str, dst_host: str, timestamp: int) -> dict
```

### 6.2 Phase 1 — Discovery Queries

Three Cypher queries run directly against Neo4j (not via MCP tools). Parameters: `{start_time, end_time}` only.

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

**Query 2: First-Time Auth Discovery** — users who successfully authenticated to hosts they had never accessed before the window:
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

**Query 3: Process Anomaly Discovery** — users who accessed hosts in the window that they had no prior history with. **Note: this query uses hardcoded time boundaries `150000` and `157200`** (not the parametric `start_time`/`end_time`). Update these if evaluating windows outside this range:
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

**Candidate ranking:** A `Counter` tallies cross-query frequency. Top-3 by frequency become `ranked_candidates` for Phase 2. If zero candidates are found, Phase 2 is skipped and `severity=LOW` is returned immediately.

### 6.3 Phase 2 — LLM Investigation

**Tools available to the LLM (Phase 2 only):**

| Tool | Server | Parameters |
|------|--------|------------|
| `get_lateral_movement_path` | `topology_server.py` | `username`, `start_time`, `end_time` |
| `get_host_centrality` | `topology_server.py` | `computer`, `start_time`, `end_time` |
| `get_user_timeline` | `investigation_server.py` | `username`, `start_time`, `end_time` |
| `get_host_activity_summary` | `investigation_server.py` | `computer`, `start_time`, `end_time` |
| `get_concurrent_sessions` | `investigation_server.py` | `computer`, `time`, `window=300` |
| `get_user_historical_baseline` | `investigation_server.py` | `username`, `window_start`, `dst_host` (optional) |

Behavioral tools (`get_auth_anomalies`, `get_first_time_authentications`, `get_process_anomalies`) are **not** exposed to the LLM. `get_host_neighbors` is excluded (disabled).

**Hard limits:**
- `_MAX_ITERATIONS = 20` — max total LLM tool calls in Phase 2
- `MAX_RESULT_CHARS = 2000` — tool result truncation limit
- Context guard: raises `RuntimeError` if estimated tokens exceed 50,000

**LLM config:**
- Model: `openai/{NAVIGATOR_MODEL}` via LiteLLM
- `base_url`: `NAVIGATOR_API_BASE` env var
- `temperature=0`, `max_tokens=1000`
- Token estimation via `tiktoken` (gpt-4o encoding)

### 6.4 System Prompt (Dynamic)

Built at runtime by `_build_system_prompt(candidates, start_time, end_time, event_mode=False)`. No separate `system_prompt.py` file. The severity criteria only reference signals the Phase 2 tools can observe. `get_user_historical_baseline` is the only tool that looks before the investigation window; all others cover the window only. The framing block depends on the entry point:

- `investigate_window()` (`event_mode=False`): candidates came from Phase 1, so the prompt says so and lists them as `CANDIDATES:`.
- `investigate_event()` (`event_mode=True`): neutral framing — the case has not been pre-flagged, so the prompt must not claim it was. Listed as `USER UNDER REVIEW:`.

```
You are a security investigator. Never assume who is suspicious — let the data tell you.

[event_mode=True]
Each case is a (username, host, timestamp) tuple drawn from the active network window. Your job is to determine from the evidence whether this specific authentication event is consistent with legitimate user behavior or indicative of lateral movement.

USER UNDER REVIEW: {candidate_str}

[event_mode=False]
Phase 1 discovery is already complete. The following candidate users were identified from behavioral signals (high authentication failure rates, first-time authentications to new hosts, novel process executions):

CANDIDATES: {candidate_str}

---

INVESTIGATION

Investigate using the available tools. Use start_time={start_time} and end_time={end_time} for all tool calls that require a time window.

Always call get_user_historical_baseline first (with window_start={start_time}, and dst_host set to the host under review when there is one) to establish what is normal for this user before interpreting activity in the investigation window.

RULES:
- Do not call all tools blindly — use judgment about which tools add signal.
- Do not repeat tool calls with identical parameters.
- Time values are LANL internal integers, not Unix timestamps.
- A rapid sequence of authentications to multiple hosts is worth examining, but on its own it is not evidence of lateral movement (see severity criteria below).
- If a tool returns empty results, note it and move on.
- You have a limited tool call budget. Prioritize the most informative tools.

---

FINAL OUTPUT FORMAT

Severity criteria:
- HIGH: Clear evidence of lateral movement in the investigation window — the user authenticated to multiple hosts in rapid succession AND this is corroborated by other signals in the tool results (authentication to hosts absent from the user's historical baseline, a high proportion of failed authentications, process execution on a destination host shortly after authenticating to it, or a burst that departs sharply from the rest of the user's activity in the window), OR the host shows failure spikes that cannot be explained by normal activity.
- MEDIUM: Ambiguous — some suspicious signals present but insufficient to confirm lateral movement. Requires analyst review.
- LOW: No meaningful evidence of lateral movement. Single-host activity, low event volume, or behavior consistent with normal operations.

Important: multi-host authentication alone is NOT sufficient for HIGH or MEDIUM. Many legitimate users authenticate to multiple hosts during normal operations. Elevation requires corroborating signals visible in the tool results, such as authentication to hosts absent from the user's historical baseline, a high proportion of failed authentications, process execution following an authentication, or an abrupt change in the user's activity within the window. Authenticating to a host the user has used before is weak evidence on its own. get_user_historical_baseline is the only tool that looks before the investigation window — all other tools cover the window only.

After investigation, produce exactly this structure — nothing before it:

SEVERITY: HIGH / MEDIUM / LOW
FLAGGED_USERS: comma-separated list of suspicious usernames (or NONE)
FLAGGED_HOSTS: comma-separated list of suspicious host names (or NONE)
NARRATIVE: [one to three paragraphs — summarize evidence, attack path if found, and reasoning]
```

### 6.5 Output Parsing

Three regex patterns parse the LLM's final text:
- `SEVERITY\s*:\s*(HIGH|MEDIUM|LOW)` → `severity` (defaults to `LOW` on no match)
- `FLAGGED_USERS\s*:\s*([^\n]+)` → `flagged_users` list
- `FLAGGED_HOSTS\s*:\s*([^\n]+)` → `flagged_hosts` list

**`investigate_window()` return schema:**
```json
{
  "window":          {"start": int, "end": int},
  "flagged_users":   ["U456@DOM1", ...],
  "flagged_hosts":   ["C17", ...],
  "verdict":         "free-text LLM narrative",
  "severity":        "HIGH | MEDIUM | LOW",
  "tool_calls_made": int
}
```

**`investigate_event(username, dst_host, timestamp)` — used by entity evaluator:**

Builds a `±3600s` window around `timestamp`, injects the single username as the sole candidate into `_build_system_prompt`, runs Phase 2 (LLM tool loop) only. The agent receives no label — it determines severity from behavioral signals alone.

```json
{
  "event":           {"username": str, "dst_host": str, "timestamp": int},
  "flagged_users":   ["U456@DOM1", ...],
  "flagged_hosts":   ["C17", ...],
  "verdict":         "free-text LLM narrative",
  "severity":        "HIGH | MEDIUM | LOW",
  "tool_calls_made": int
}
```

### 6.6 Time Windows
- `investigate_window()` Phase 1 and Phase 2 use the full `[start_time, end_time]` passed in
- `investigate_event()` uses `start_time = timestamp - 3600`, `end_time = timestamp + 3600`
- `get_concurrent_sessions` always uses `window=300` (±300 seconds around event time)

---

## 7. Control Case Generation (`src/utils/generate_cold_events.py`)

**Purpose:** One-time data preparation script. Generates `data/cold_events.txt` — a curated set of clean control (non-red-team) authentication events from the cold window. This file is committed as a research artifact. The evaluator loads from it at runtime and **does not** query Neo4j for control sampling.

**Control sampling window:** `[767000, 770400]` — inside the hot window period, so control cases have the full cold window (633600–640800) as prior history, the same as red team cases. (Previously `[635020, 640800]`, which left many controls with little or no prior history; that set is kept as `data/cold_events_old.txt`.)

**Filtering pipeline (5 filters):**
1. **Filter 1:** Exclude machine accounts (`$`), ANONYMOUS logons, and Windows built-in service identities (`NETWORK SERVICE`, `LOCAL SERVICE`, `ANONYMOUS LOGON`)
2. **Filter 2:** Exclude any username appearing anywhere in `redteam.txt` (whole file)
3. **Filter 3:** Low-centrality hosts only (`< 50` distinct authenticating users in the control sampling window)
4. **Filter 4:** Exclude rapid multi-hop users (`> 3` distinct hosts in any 300s sliding window). Bulk query — skipped gracefully on timeout.
5. **Filter 5:** Successful authentications only (`a.status = 'Success'`)

**Output format:** Same as `redteam.txt`: `timestamp,username,src_host,dst_host` (no header, one event per line). Since cold events have no origin concept, `src_host = dst_host`.

**Deduplication:** One event per unique username. Capped at the number of hot-window red team events (93), so evaluation can be balanced 1:1. The candidate query samples up to 5000 random events before deduplication.

**Usage:**
```bash
uv run python -m src.utils.generate_cold_events
```

### 7.1 Fixed Evaluation Case List (`src/utils/generate_eval_cases.py`)

Builds `data/eval_cases.txt`, the single case list read by `evaluator.py` entity mode **and** every baseline, so all methods score exactly the same cases.

- Red team cases: every `redteam.txt` event in the hot window `[763200, 770400]` (93 events, from 17 distinct users).
- Control cases: every event in `data/cold_events.txt` (93 events, 93 distinct users).
- Balanced 1:1 at the largest size available (currently 93 + 93 = 186 cases).
- Order shuffled with a fixed seed (`SEED = 42`). `--sample-size N` on any evaluator keeps the first N red team and first N control cases in file order — a reproducible random subset.
- **Tune / test split:** each label is split in half by file order — 46 red team + 46 control in `tune`, 47 + 47 in `test`. Adjust the agent's prompt using `--split tune` only; report final numbers from `--split test`, so they are not tuned to the cases they are measured on. Red team events are split at the event level, so most red team users appear in both halves (14 of 17 in each).
- Format: `timestamp,username,src_host,dst_host,label,split` (`label` = `redteam` or `control`, `split` = `tune` or `test`; `#` lines are comments).
- Contains ground-truth labels: a grading file like `redteam.txt`. Evaluators pass only `(username, dst_host, timestamp)` to the agent.

Regenerate only after `cold_events.txt` changes:
```bash
uv run python -m src.utils.generate_eval_cases
```

---

## 8. Evaluation Design (`src/evaluation/evaluator.py`)

Two modes, selected via `--mode` CLI flag:

### 8.1 Window Mode (recall-only)

```bash
uv run python -m src.evaluation.evaluator --mode window
```

**Flow:**
1. Parse `redteam.txt`. Filter to fixed window `[763200, 764600]`.
2. Call `investigate_event(username, dst_host, timestamp)` for each event **sequentially**.
3. Score: `severity in {HIGH, MEDIUM}` → TP; `severity == LOW` → FN.
4. Output: `evaluation/results_YYYYMMDD_HHMMSS.json`

**Metrics output:** Recall only (TP/FN). No control cases → precision/F1 not applicable.

---

### 8.2 Entity Mode (precision + recall + F1)

```bash
uv run python -m src.evaluation.evaluator --mode entity                  # all 186 cases
uv run python -m src.evaluation.evaluator --mode entity --split tune     # tuning half (92 cases)
uv run python -m src.evaluation.evaluator --mode entity --split test     # held-out half (94 cases)
uv run python -m src.evaluation.evaluator --mode entity --sample-size 15 # first 15 + 15
```

**Stage 1 — Case construction:**
- Load the fixed case list from `data/eval_cases.txt` (see §7.1). No random sampling at runtime.
- `--split tune|test` (optional) keeps only that half; output file becomes `entity_results_{split}_YYYYMMDD_HHMMSS.json`.
- `--sample-size N` (optional) keeps the first N red team and first N control cases (within the split, if given); default is all.
- All baselines accept the same `--split` and `--sample-size` flags; with `--split`, their output file gets a `_{split}` suffix (e.g. `ua_baseline_results_test.json`).

**Stage 2 — Concurrent investigation:**
- Run `investigate_event()` on all cases via `ThreadPoolExecutor(max_workers=3)`.
- `MAX_CONCURRENT_INVESTIGATIONS = 3` — stays within Navigator 120 RPM limit (3 concurrent × ~4 LLM calls each ≈ 12 calls/min peak). Do not increase without verifying RPM headroom.
- Results arrive via `as_completed()` and are flushed to disk after each case.
- HTTP 429: sleep 10s, record case as error, no retry.
- `elapsed_seconds` per case = individual wall time for that investigation.
- `total_elapsed_seconds` in meta = executor wall time (submit → last future done).

**Stage 3 — Scoring:**
```
is_redteam=True  + severity in {HIGH,MEDIUM} → TP
is_redteam=True  + severity == LOW           → FN
is_redteam=False + severity in {HIGH,MEDIUM} → FP
is_redteam=False + severity == LOW           → TN
```
Compute precision, recall, F1. Print summary.
Output: `evaluation/entity_results_YYYYMMDD_HHMMSS.json`

### 8.3 Output Schema (entity mode JSON)
```json
{
  "meta": {
    "mode": "entity",
    "run_timestamp": "YYYYMMDD_HHMMSS",
    "hot_window_start": 763200,
    "hot_window_end": 770400,
    "cold_window_start": 767000,
    "cold_window_end": 770400,
    "max_concurrent": 3,
    "total_cases": int,
    "total_tool_calls": int,
    "true_positives": int,
    "true_negatives": int,
    "false_positives": int,
    "false_negatives": int,
    "precision": float,
    "recall": float,
    "f1": float,
    "total_elapsed_seconds": float
  },
  "results": [...]
}
```

---

## 9. Baseline Evaluator (`src/evaluation/baseline_evaluator.py`)

Static, deterministic, rule-based detector. No LLM. No tool calls. Serves as the comparison baseline against the agent. Reads the same `data/eval_cases.txt` case list as entity mode, so it scores exactly the same cases.

### 9.1 Three-Signal Scoring

Each case is scored by three independent Cypher signals. Time window: `[timestamp - 3600, timestamp + 3600]`.

| Signal | Condition | Points |
|--------|-----------|--------|
| Signal 1 — Auth anomaly | `failure_rate_pct > 30.0` OR `unique_targets >= 4` | +2 |
| Signal 2 — First-time auth | Any Success auth to a host with no pre-window Success auth | +2 |
| Signal 3 — Historical novelty | Any window host absent from user's pre-window history | +1 |

**Severity escalation:**
- `score >= 3` → run path query (`count DISTINCT hosts in window`) → `HIGH` if `distinct_hosts >= 3`, `MEDIUM` otherwise
- `score < 3` → `LOW`

**Signal queries are the parameterized, per-user versions of the Phase 1 discovery queries:**

Signal 1 (per-user auth anomaly):
```cypher
MATCH (u:User {username: $username})-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time >= $start_time AND a.time <= $end_time
WITH u,
     count(a) AS total_attempts,
     sum(CASE WHEN a.status = 'Fail' THEN 1 ELSE 0 END) AS failed_attempts,
     count(DISTINCT c) AS unique_targets
WITH u, total_attempts, failed_attempts, unique_targets,
     CASE WHEN total_attempts > 0
          THEN round(toFloat(failed_attempts) / toFloat(total_attempts) * 100, 2)
          ELSE 0.0 END AS failure_rate_pct
RETURN failure_rate_pct, unique_targets
```

Signal 2 (per-user first-time auth):
```cypher
MATCH (u:User {username: $username})-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time >= $start_time AND a.time <= $end_time
AND a.status = 'Success'
WITH u, c, min(a.time) AS first_seen_in_window
WHERE NOT EXISTS {
    MATCH (u)-[prev:AUTHENTICATED_TO]->(c)
    WHERE prev.time < $start_time AND prev.status = 'Success'
}
RETURN count(c) AS new_host_count
```

Signal 3 (per-user historical novelty):
```cypher
MATCH (u:User {username: $username})-[b:AUTHENTICATED_TO]->(c2:Computer)
WHERE b.time >= $start_time AND b.time <= $end_time
AND b.status = 'Success'
WITH u, collect(DISTINCT c2.name) AS window_hosts
OPTIONAL MATCH (u)-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time < $start_time AND a.status = 'Success'
WITH u, window_hosts, collect(DISTINCT c.name) AS historical_hosts
WITH u, window_hosts, historical_hosts,
     [h IN window_hosts WHERE NOT h IN historical_hosts] AS new_hosts
RETURN size(new_hosts) AS new_host_count
```

Severity path query:
```cypher
MATCH (u:User {username: $username})-[a:AUTHENTICATED_TO]->(c:Computer)
WHERE a.time >= $start_time AND a.time <= $end_time
AND a.status = 'Success'
RETURN count(DISTINCT c) AS distinct_hosts
```

### 9.2 Running the Baseline
```bash
uv run python -m src.evaluation.baseline_evaluator
```
Output: `evaluation/baseline_results.json`

---

## 10. Metrics (`src/evaluation/metrics.py`)

Computes and prints a side-by-side comparison table of agent vs. baseline results.

```bash
uv run python -m src.evaluation.metrics
uv run python -m src.evaluation.metrics --agent-only
uv run python -m src.evaluation.metrics --baseline-only
```

### 10.1 Metric Definitions

| Metric | Formula | Notes |
|--------|---------|-------|
| Precision | `TP / (TP + FP)` | Of all flagged cases, how many had real redteam activity |
| Recall | `TP / (TP + FN)` | Of all redteam cases, how many were caught |
| F1 | `2 × P × R / (P + R)` | Harmonic mean of precision and recall |
| Chain Accuracy | `paths_found / TP_count` | Agent only: fraction of TPs where `get_lateral_movement_path` returned a non-empty chain |
| Sequence Completeness | `full_seq / total` | Agent only: fraction of events where all 9 tools were called (legacy metric) |

### 10.2 TP Definition (entity mode)
`is_redteam=True` + `severity in {"HIGH", "MEDIUM"}` → TP

**Note:** `metrics.py` uses `verdict == "HIGH"` for TP classification, while `evaluator.py` uses `severity in {"HIGH", "MEDIUM"}`. For research paper reporting, use the evaluator.py definition (severity-based).

### 10.3 Input Files
- Agent results: `evaluation/results.json` (produced by `evaluator.py` window mode) or `evaluation/entity_results_*.json` (entity mode)
- Baseline results: `evaluation/baseline_results.json` (produced by `baseline_evaluator.py`)

---

## 11. Build Order

Follow this exact order. Do not begin the orchestrator until all MCP servers are independently tested.

| Step | Task |
|------|------|
| 1 | Run ETL: `uv run python -m src.pipeline.etl`. Verify 4 CSVs in `data/`. |
| 2 | Import CSVs into Neo4j via `neo4j-admin database import full`. Verify node/edge counts in Neo4j browser. |
| 3 | Build `behavioral_server.py` — test all three Cypher queries in Neo4j browser before wiring up. |
| 4 | Build `topology_server.py` — test `get_host_centrality` and `get_lateral_movement_path`. |
| 5 | Build `investigation_server.py` — test all three tools. |
| 6 | Build `orchestrator.py` — Phase 1 + Phase 2. Test: `investigate_window(763200, 770000)`. |
| 7 | Generate control cases: `uv run python -m src.utils.generate_cold_events`, then the fixed case list: `uv run python -m src.utils.generate_eval_cases`. Verify `data/cold_events.txt` and `data/eval_cases.txt`. |
| 8 | Build `evaluator.py` — test window mode first, then entity mode. |
| 9 | Build `baseline_evaluator.py` — run same sample against static signals. |
| 10 | Run `metrics.py` to generate comparison table. |

---

## 12. Running Commands

```bash
# Install dependencies
uv sync

# Run ETL
uv run python -m src.pipeline.etl

# Generate control cases, then the fixed evaluation case list (run once)
uv run python -m src.utils.generate_cold_events
uv run python -m src.utils.generate_eval_cases

# Run agent manually
uv run python src/agent/orchestrator.py

# Run evaluation — window mode (recall only)
uv run python -m src.evaluation.evaluator --mode window

# Run evaluation — entity mode (precision + recall + F1), all cases in data/eval_cases.txt
uv run python -m src.evaluation.evaluator --mode entity
# ...or only the held-out half, for final reported numbers (add --split test to baselines too)
uv run python -m src.evaluation.evaluator --mode entity --split test

# Run baselines (same cases)
uv run python -m src.evaluation.baseline_evaluator
uv run python -m src.evaluation.ua_baseline_evaluator
uv run python -m src.evaluation.fl_baseline_evaluator

# Compute metrics comparison
uv run python -m src.evaluation.metrics
```

---

## 13. Critical Constraints

- **`redteam.txt`:** Never load into Neo4j. Never expose to the agent. Flat file evaluator oracle only.
- **Hardware:** 16GB RAM — never run full GDS Betweenness Centrality. Use `get_host_centrality` approximation only.
- **Timestamps:** LANL internal integers (elapsed seconds). Do not convert to Unix time. Use relative arithmetic only.
- **Process/user/host names:** Anonymized (`P131`, `U456`, `C17`). No CVE or CPE mapping. Behavioral novelty only.
- **Credentials:** Always load via `load_dotenv()` from `.env`. No hardcoded keys anywhere.
- **Blind investigation:** `investigate_window()` never accepts entity identities — only a time window. Entity discovery is purely signal-driven.
- **Phase 1 is fixed, Phase 2 is LLM-chosen:** Phase 1 always runs the same 3 discovery queries. Phase 2 lets the LLM choose which tools to call per candidate — do not hard-code a sequence.
- **GPT-4o recommended** over Llama variants for reliable tool/function calling via Navigator AI.
- **Concurrent evaluation:** `MAX_CONCURRENT_INVESTIGATIONS = 3`. Do not increase without verifying Navigator gateway RPM headroom.
- **`get_host_neighbors` disabled:** Do not re-enable without adding `LIMIT` or index hint — the two-hop query is unresponsive on large windows.
- **Phase 1 process anomaly query:** Uses hardcoded time boundaries (`150000`, `157200`) — update these if evaluating different day windows.
- **Each server file is fully standalone:** No shared state between servers.
- **Cold events:** `data/cold_events.txt` is a committed research artifact. Do not regenerate during evaluation runs — only regenerate it intentionally by running `generate_cold_events.py` manually.
- **Eval cases:** `data/eval_cases.txt` is the single case list for the agent and all baselines. Do not add per-evaluator sampling — every method must score the same cases. Regenerate (`generate_eval_cases.py`) only after `cold_events.txt` changes, and re-run every method afterwards.
- **Tune / test discipline:** prompt or tool changes are evaluated on `--split tune` only. Final reported metrics come from `--split test`, run once per final configuration.
