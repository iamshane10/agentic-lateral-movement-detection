# Code Checkpoint — Progress Report
## Agentic Knowledge Graphs for Lateral Movement Detection
### LANL Cybersecurity Dataset | Neo4j + MCP Servers + Agentic AI

---
## Team Members
- Shane George Thomas

## What Has Been Completed

### Data Processing & Ingestion
The full ETL pipeline for the LANL Cybersecurity Dataset has been implemented and executed. Raw `auth.txt` and `proc.txt` data was filtered to days 2–9 (LANL internal time range: ~150,000–900,000 elapsed seconds), which was determined to be the evaluable window after verifying that all 338 confirmed red team events within scope fall in this range. The ETL uses DuckDB for preprocessing and outputs CSV files formatted for Neo4j bulk import.

### Knowledge Graph Construction
The Neo4j Knowledge Graph has been fully constructed with the following finalized schema:

- **Node types:** `User` (username property) and `Computer` (name property)
- **Relationship types:**
    - `AUTHENTICATED_TO` (User → Computer): properties — `time`, `auth_type`, `logon_type`, `orientation`, `status` ("Success" / "Fail")
    - `EXECUTED` (User → Computer): properties — `time`, `process_name`, `event_type`

Several schema decisions were made and implemented during this phase: `Process` nodes, `HAS_PROCESS` relationships, and `OWNS` relationships were deliberately removed from the final schema after analysis showed they were either redundant, semantically invalid given the dataset's anonymization, or derived from unreliable source data.

The graph contains approximately 54.6 million `EXECUTED` edges and covers authentication and process execution events across days 2–9.

### MCP Servers
Three MCP servers have been implemented, each exposing tools that connect to the Neo4j instance and execute Cypher queries, returning structured JSON output:

**Behavioral Server** (`behavioral_server.py`) — 3 tools implemented:
- `get_auth_anomalies`: Returns authentication failure rates, unique target counts, and auth types used for a given user within a time window. Verified to return meaningful output.
- `get_first_time_authentications`: Identifies user-host authentication pairs with no prior history before the investigation window. Verified to return meaningful output.
- `get_process_anomalies`: Identifies processes executed by a user on a specific host that have no prior execution history before the window. Verified to return meaningful output. Cypher query refinement is ongoing (see In Progress).

**Topology Server** (`topology_server.py`) — 3 tools implemented:
- `get_host_centrality`: Returns unique user counts, total auth events, and failed auth counts for a given host. Verified to return meaningful output after correcting a `status` field bug (was incorrectly filtering for "Success" when counting failures).
- `get_lateral_movement_path`: Reconstructed and redesigned after dataset analysis revealed that `src_host` in `redteam.txt` represents the attacker's originating machine and does not appear as an authentication destination in auth logs. The tool now reconstructs the sequential authentication chain for a given user across all hosts visited within the window, ordered chronologically. Verified to return meaningful output.
- `get_host_neighbors`: Returns computers reachable from a given host via shared authenticating users. Performance and scope improvements are ongoing (see In Progress).

**Investigation Server** (`investigation_server.py`) — 3 tools implemented:
- `get_user_timeline`: Returns interleaved auth and process events for a user within a window.
- `get_host_activity_summary`: Returns all user and process activity on a given host within a window.
- `get_concurrent_sessions`: Returns users who authenticated to a given host within a configurable time window (default ±300 seconds) around a specific event.

### Agent — First Iteration
A first iteration of the LLM agent has been implemented using LiteLLM connected to Navigator AI (university-hosted API gateway). The agent registers all 9 MCP tools as callable schemas and follows a structured 3-phase investigation sequence: behavioral analysis, topology analysis, and investigation summary. The agent produces a structured verdict (HIGH / MEDIUM / LOW) with a natural language justification citing tool outputs.

### Unit Tests
Unit tests have been implemented for the Behavioral Server and Topology Server. Tests verify Neo4j connectivity and confirm that each tool executes its Cypher query and returns a non-error response. Additional logical validation tests are planned (see Remaining).

---

## What Is In Progress

### Cypher Query Refinement — Behavioral Server
Several Cypher queries in `behavioral_server.py` are being refined to more accurately capture cybersecurity-relevant signals. Specifically, the behavioral anomaly thresholds and the historical comparison logic in `get_process_anomalies` and `get_first_time_authentications` are being reviewed to ensure they produce actionable output across the full range of 338 evaluable red team events, rather than only a subset.

### `get_host_neighbors` — Topology Server
The `get_host_neighbors` tool is returning results but its scope and performance are being improved. The current query can be slow on high-centrality hosts due to the volume of authentication edges. Query optimization and result limiting strategies are being evaluated.

### Agent Investigation Strategy — Design Decision Pending
A key design decision remains unresolved regarding how the agent is triggered during evaluation. Two approaches are under consideration:

- **Approach A:** Feed the agent a known suspicious username and ask it to assess threat level using behavioral and topology tools.
- **Approach B:** Feed the agent a timestamp range and have it scan for high-threat activity autonomously without a pre-identified user.

Approach A is more controlled and directly comparable to the baselines. Approach B is more realistic operationally but introduces feasibility and performance concerns on available hardware. The decision will be made based on empirical testing of both approaches against a sample of red team events.

---

## What Remains To Be Done

### Baseline Systems
Neither baseline has been implemented yet. Both are well-scoped and are expected to be straightforward given that all data processing infrastructure is already in place:

- **Baseline A (SQL):** A DuckDB query over `auth.txt` that flags users exceeding a failure rate threshold across a minimum number of unique target hosts within the investigation window. No graph traversal or LLM reasoning.
- **Baseline B (Static Cypher):** A fixed Neo4j Cypher query that identifies users authenticating to previously unvisited hosts within the investigation window. No LLM reasoning or multi-tool orchestration.

Both baselines will be evaluated against the same 338 red team events using the same precision/recall methodology as the agent.

### Evaluator and Metrics
`evaluator.py` and `metrics.py` have not yet been implemented. The evaluator will iterate over the 338 in-scope red team events, invoke the agent for each, parse the VERDICT field from agent output, and log results to JSON. The metrics module will compute Precision, Recall, Lateral Movement Chain Accuracy, and Explainability Score across agent and baseline results.

### Unit Tests — Logical Validation
Current unit tests verify connectivity and query execution only. Additional tests are planned that validate the logical correctness of query outputs — for example, confirming that `get_first_time_authentications` returns zero results for a user-host pair with known prior history, and non-zero results for a confirmed new pair.

### Final Agent Tuning
Once the investigation strategy decision is resolved and baselines are implemented, the agent's system prompt and tool call loop will be tuned based on initial evaluation results before the final metrics run.

## How to Run
### Processing the LANL Cybersecurity Dataset
- Download the auth.txt and proc.txt dataset files from: https://csr.lanl.gov/data/cyber1/
- Run the etl.py file by including the necessary environment variables, `AUTH_DATASET_PATH` and `PROC_DATASET_PATH`. These are the paths to where auth.txt and proc.txt are stored. Then, run:
```
 uv sync
 uv run python src/pipeline/etl.py
```
- The processed csv files will be written to `/data`.

### Steps to create the Knowledge Graph on Neo4J

1. Download the Neo4J Desktop app. (https://neo4j.com/download/)
2. Open the app, and create a new instance.
3. Stop running the instance (as imports can only be done when the instance is stopped).
4. Open a Windows Powershell terminal.
5. Increase Java heap space to allow huge dataset to be imported.
```
PS path-to-neo4j-instance> $env:JAVA_OPTS="-Xmx6G -Xms6G --add-opens=java.base/java.nio=ALL-UNNAMED"
```
6. cd into the Neo4J instance path, and run neo4j-admin's import command, as this is much faster than the GUI import feature (list of nodes and relationships used here can be found in the REFERENCE.md file)<BR>
```
PS path-to-neo4j-instance> .\bin\neo4j-admin database import full --nodes=User=<path>\cis6930sp26-project\data\users.csv --nodes=Computer=<path>\cis6930sp26-project\data\computers.csv --relationships=AUTHENTICATED_TO=<path>\cis6930sp26-project\data\authentications.csv --relationships=EXECUTED=<path>\cis6930sp26-project\data\process_events.csv --overwrite-destination=true --skip-duplicate-nodes=true --multiline-fields=true --skip-bad-relationships=true --bad-tolerance=1000 --ignore-empty-strings=true --threads=4
```

This will then result in the output:
```
Flush completed in 14s 66ms
IMPORT DONE in 12m 4s 96ms.
```
7. Install the Neo4J Graph Data Science plugin onto the local instance.
8. Run the instance, and open the 'Query' tab on Neo4J to execute a few Cypher queries.

### Running the Anomaly Detection Agent
Update your .env file using the following structure:
```
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password
NAVIGATOR_API_KEY=your_key
NAVIGATOR_BASE_URL=your_university_endpoint
NAVIGATOR_MODEL=gpt-4o
```

```
uv sync
uv run python .\src\agent\orchestrator.py
```