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

| Relationship | Direction | Properties                                                                                                                             |
|---|---|----------------------------------------------------------------------------------------------------------------------------------------|
| `AUTHENTICATED_TO` | User → Computer | `time` (long), `auth_type` (string), `logon_type` (string), `orientation` (string), `status` (string -> values are "Success" or "Fail") |
| `EXECUTED` | User → Computer | `time` (long), `process_name` (string), `event_type` (string)                                                                          |

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
NAVIGATOR_BASE_URL=your_university_endpoint
NAVIGATOR_MODEL=gpt-4o
```

### 2.5 Project Structure
```
cis6930sp26-project/
├── REFERENCE.md
├── .env
├── uv.lock
├── src
│   ├── servers/
│       ├── behavioral_server.py
│       ├── topology_server.py
│       └── investigation_server.py
│   ├── agent/
│       ├── orchestrator.py
│       └── system_prompt.py
│   ├── evaluation/
│   │   ├── evaluator.py
│       └── metrics.py
└── data/
    └── redteam.txt
```

---

## 3. MCP Server Specifications

Each MCP server is a standalone Python file. Each tool accepts a typed input, executes a Cypher query against Neo4j, and returns structured JSON. The LLM never writes Cypher — it only calls tools by name with parameters.

All Neo4j credentials are loaded via `load_dotenv()` from the `.env` file. No hardcoded credentials anywhere.

---

### Server 1: Behavioral Server (`behavioral_server.py`)

**Purpose:** Answers whether a user or host is behaving abnormally. Always the first server called in an investigation. Operates on authentication failure rates, new user-host relationships, and novel process execution patterns.

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
     sum(CASE WHEN a.status = false THEN 1 ELSE 0 END) as failed_attempts,
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

**Rationale:** Called after `get_first_time_authentications` confirms suspicious access. Novel process execution on a newly accessed host is a second-layer corroboration signal. Process names are anonymized but behavioral novelty is still meaningful.

---

### Server 2: Topology Server (`topology_server.py`)

**Purpose:** Answers how connected and structurally significant a host is. Operates on graph structure rather than individual events. This is where the Knowledge Graph demonstrably outperforms SQL — expressing network reachability and pivot point identification through graph traversal.

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
     sum(CASE WHEN a.status = false THEN 1 ELSE 0 END) as failed_auths,
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

**Purpose:** Reconstructs the authentication chain between source and destination host via shared users. Core tool for attack path reconstruction.

**Input Schema:**
```json
{
  "source_computer": "string",
  "target_computer": "string",
  "start_time": "int",
  "end_time": "int"
}
```

**Cypher Query:**
```cypher
MATCH path = (src:Computer {name: $source_computer})
      <-[a1:AUTHENTICATED_TO]-(u:User)
      -[a2:AUTHENTICATED_TO]->(dst:Computer {name: $target_computer})
WHERE a1.time >= $start_time AND a1.time <= $end_time
AND a2.time >= $start_time AND a2.time <= $end_time
AND a2.time >= a1.time
AND a1.status = "Success"
AND a2.status = "Success"
RETURN u.username as pivot_user,
       src.name as source_computer,
       a1.time as auth_from_source_time,
       dst.name as target_computer,
       a2.time as auth_to_target_time,
       (a2.time - a1.time) as time_delta
ORDER BY time_delta ASC
LIMIT 20
```

**Rationale:** Finds users who authenticated FROM source then TO target in chronological order. A small `time_delta` (under 300 seconds) is a strong lateral movement indicator. Directly maps to what `redteam.txt` validates: source host to destination host transitions.

---

#### Tool 6: `get_host_neighbors`

**Purpose:** Returns all computers reachable from a given host within one authentication hop. Defines blast radius of a compromised host.

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

**Rationale:** Replaces the original Reachability Server without requiring `flows.txt`. Reachability is defined by authentication paths rather than network ports — valid given `redteam.txt` validates at host level, not port level.

---

### Server 3: Investigation Server (`investigation_server.py`)

**Purpose:** Aggregates evidence once suspicious activity is already identified. Called last in the investigation sequence. Outputs directly feed the Explainability Score metric and the agent's natural language justification.

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
         status: a.status,
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
     sum(CASE WHEN a.status = false THEN 1 ELSE 0 END) as failed_auths,
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

**Rationale:** First tool called when investigating a suspicious destination host. Answers who else was on this machine and what was running — essential for blast radius assessment and scoping the full impact of a compromise.

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

### 4.1 How Tool Calling Works
1. Tool schemas are registered with LiteLLM at session start
2. LLM receives an investigation prompt and returns a `tool_call` request (JSON)
3. `orchestrator.py` intercepts the request and routes it to the correct MCP server
4. MCP server runs Cypher against Neo4j and returns structured JSON
5. Result is appended to the conversation and sent back to the LLM
6. Loop continues until the LLM stops calling tools and produces a final verdict

### 4.2 Investigation Trigger

For each event in `redteam.txt`, extract: `timestamp, username, source_host, destination_host`

Pass to the agent as:
```
Investigate potential suspicious activity involving user {username}
between host {source_host} and host {destination_host}
around time {timestamp}.
```

**The agent must never be told the event is a confirmed compromise.** `redteam.txt` is the grading key, not the investigation input.

### 4.3 Time Windows
- All tool calls use: `start_time = T - 3600`, `end_time = T + 3600`
- `get_concurrent_sessions` uses a tighter window: `window = 300`

### 4.4 System Prompt (`system_prompt.py`)

```
You are an expert cybersecurity investigator analyzing authentication
and process execution logs from an enterprise network. Your goal is
to determine whether a given user and host combination shows evidence
of lateral movement or compromise.

You have access to a knowledge graph of network behavior via tools.
You MUST always use tools to support your conclusions.
Never speculate or infer without querying the graph first.

---

INVESTIGATION SEQUENCE

You must follow this exact sequence for every investigation:

PHASE 1 - BEHAVIORAL ANALYSIS
1. get_auth_anomalies
2. get_first_time_authentications
3. get_process_anomalies

PHASE 2 - TOPOLOGY ANALYSIS
4. get_lateral_movement_path
5. get_host_centrality
6. get_host_neighbors

PHASE 3 - INVESTIGATION SUMMARY
7. get_user_timeline
8. get_host_activity_summary
9. get_concurrent_sessions

---

REASONING RULES

- Complete all three phases before producing a verdict
- If a tool returns empty results, note it explicitly and continue
- Do not repeat tool calls with identical parameters
- Time values are LANL internal integers, not Unix timestamps
- time_delta under 300 in get_lateral_movement_path = strong lateral movement signal
- High failure_rate_pct combined with many unique_targets = strong compromise signal
- New auth relationships coinciding with new process execution = high confidence signal

---

FINAL OUTPUT FORMAT

After completing all three phases, produce your verdict in exactly
this structure:

VERDICT: [HIGH / MEDIUM / LOW]

EVIDENCE SUMMARY:
- Behavioral signals: [summarize key findings from phase 1]
- Topology signals: [summarize key findings from phase 2]
- Timeline narrative: [plain English sequence of events from phase 3]

ATTACK PATH:
User X authenticated from Host A at time T1,
then to Host B at time T2 (delta: N seconds)
[or: No direct authentication chain reconstructed]

CONFIDENCE REASONING:
[One paragraph citing specific numbers from tool outputs]
```

---

## 5. Evaluation Design

### 5.1 Evaluation Loop (`evaluator.py`)
```
for each event in redteam.txt:
    1. Extract {timestamp, username, src_host, dst_host}
    2. Send investigation prompt to agent via LiteLLM
    3. Agent calls tools, produces verdict
    4. Parse VERDICT field from agent output
    5. Label as True Positive if VERDICT == HIGH
    6. Log full tool call sequence and raw output for explainability scoring
```

### 5.2 Metrics

| Metric | Definition |
|--------|------------|
| Precision / Recall | Computed against `redteam.txt`. True Positive = agent correctly labels a red team event as HIGH risk. |
| Lateral Movement Chain Accuracy | Did `get_lateral_movement_path` reconstruct a valid src→dst auth chain for confirmed red team events? |
| Explainability Score | Does the agent's CONFIDENCE REASONING cite specific tool output values? Scored manually per investigation. |

### 5.3 Baselines

| Baseline | Approach |
|----------|----------|
| Baseline A (SQL) | Join auth table: flag users with `failure_rate > threshold` across N distinct hosts within window. No graph traversal. |
| Baseline B (Static Cypher) | Fixed Cypher query: find users who authenticated to a new host within the window. No LLM reasoning, no multi-tool orchestration. |

Both baselines evaluate against the same `redteam.txt` events using the same precision/recall methodology.

---

## 6. Build Order

Follow this exact order. Do not begin the orchestrator until all MCP servers are independently tested.

| Step | Task |
|------|------|
| 1 | Build `behavioral_server.py` — all three tools. Test each Cypher query in Neo4j browser before wiring up. |
| 2 | Build `topology_server.py` — all three tools. |
| 3 | Build `investigation_server.py` — all three tools. |
| 4 | Build `orchestrator.py` — wire LiteLLM to all servers. Test with a single hardcoded redteam event first. |
| 5 | Build `system_prompt.py` — paste exact prompt from Section 4.4. |
| 6 | Build `evaluator.py` — iterate over `redteam.txt`, collect verdicts. |
| 7 | Build `metrics.py` — compute precision, recall, chain accuracy. |
| 8 | Build SQL and Static Cypher baselines for comparison. |

---

## 7. Critical Constraints

- **Hardware:** 16GB RAM. Never run full GDS Betweenness Centrality — use `get_host_centrality` approximation instead.
- **redteam.txt:** Never load into Neo4j. Never expose to the agent. Flat file evaluator only.
- **Time:** All timestamps are LANL internal integers. Do not convert to Unix time. Use relative arithmetic only.
- **Process names:** Anonymized (`P131`). No CVE or CPE mapping. Behavioral novelty only.
- **Tool calling:** Verify Navigator AI model supports tool/function calling before building orchestrator. GPT-4o recommended over Llama variants for reliability.
- **Credentials:** Always load via `load_dotenv()` from `.env`. No hardcoded keys anywhere.
- **Tool call sequence:** The system prompt enforces a fixed 9-tool sequence for every investigation. Do not let the LLM choose its own order — reproducibility is required for evaluation.