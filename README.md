# Agentic Lateral Movement Detection for Cybersecurity
### LLM-Orchestrated Knowledge Graph vs. Static Cypher Baseline · LANL Cybersecurity Dataset

---

> **Agent — F1: 0.747 · Recall: 0.978 · Precision: 0.605**  
> **Baseline — F1: 0.732**  
> Evaluated on 338 red-team events · 30 balanced cases × 3 runs · LANL dataset

---

## What This Is

A research system that replaces fixed detection rules with a **two-phase AI agent** that reasons over a Neo4j knowledge graph to identify lateral movement in enterprise network logs — and measures whether it outperforms a traditional static pipeline.

**Research question:** Does an LLM-orchestrated Knowledge Graph improve precision and recall of lateral movement detection compared to a static rule-based Cypher baseline?

---

## What I Built

### Two-Phase Blind Investigation Agent
- **Phase 1 (orchestrator-driven):** Three Cypher discovery queries rank candidate users by behavioral signal — auth failure rate, first-time host access, novel process execution. No entity labels provided.
- **Phase 2 (LLM-driven):** GPT-4o selects from 5 graph tools per candidate and produces a structured verdict: `SEVERITY / FLAGGED_USERS / FLAGGED_HOSTS / NARRATIVE`.
- Hard cap: 20 tool calls, 50K token context guard, output parsed via regex.

### Knowledge Graph Schema (Neo4j)
- **Nodes:** `User`, `Computer`
- **Relationships:** `AUTHENTICATED_TO` (time, auth_type, logon_type, status), `EXECUTED` (time, process_name, event_type)
- Imported via `neo4j-admin` bulk loader — 54M+ edges, ~12 min import

### 3 MCP Servers (Model Context Protocol)
| Server | Tools | Role |
|--------|-------|------|
| `behavioral_server.py` | auth anomalies, first-time auths, process novelty | Phase 1 — orchestrator only |
| `topology_server.py` | host centrality, lateral movement path | Phase 2 — LLM callable |
| `investigation_server.py` | user timeline, host activity, concurrent sessions | Phase 2 — LLM callable |

### ETL Pipeline (DuckDB → Neo4j)
- Reads raw `auth.txt` + `proc.txt` (LANL dataset) via **DuckDB in-memory SQL**
- Filters to two time windows: attack window `[763200–770400]` and control window `[633600–640800]`
- Exports 4 Neo4j-ready CSVs — nodes and relationships

### Evaluation Framework
- **Window mode:** Sequential recall evaluation over confirmed red team events
- **Entity mode:** Balanced TP/FP cases, **concurrent via `ThreadPoolExecutor(max_workers=3)`**, produces precision + recall + F1
- **Static baseline:** 3-signal Cypher scorer (auth anomaly + first-time auth + historical novelty), no LLM — direct comparison target
- Incremental JSON write after each case; 429-rate-limit handling built in

---

## Stack

| | |
|--|--|
| **Graph DB** | Neo4j (Cypher, GDS) |
| **LLM** | GPT-4o via LiteLLM + Navigator AI |
| **ETL Engine** | DuckDB (in-memory) |
| **Agent Protocol** | MCP (Model Context Protocol, FastMCP) |
| **Language** | Python 3.14 |
| **Dataset** | [LANL Cybersecurity Dataset](https://csr.lanl.gov/data/cyber1/) — `auth.txt`, `proc.txt`, `redteam.txt` |

---

## Key Design Decisions

- **Blind investigation** — agent receives no entity identities; it surfaces suspects from behavioral signals alone
- **Behavioral novelty as the only signal** — no CVE enrichment, no named software; everything is anonymized (`U456`, `C17`, `P131`)
- **Graph over SQL** — lateral movement path reconstruction and pivot point identification via graph traversal, not joins
- **Centrality approximation** — full GDS Betweenness Centrality infeasible on 16GB RAM; approximated by counting distinct authenticating users per host
- **redteam.txt is evaluation-only** — never loaded into Neo4j, never exposed to the agent; used exclusively as ground truth oracle

---

## Results

Evaluated on 338 red-team events from the LANL dataset. 30 balanced TP/FP cases per run, averaged across 3 runs.

| | F1 | Recall | Precision |
|--|--|--|-----------|
| **Agent (GPT-4o + KG)** | **0.747** | **0.978** | **0.605** |
| Baseline (static Cypher) | 0.732 | 1.000 | 0.577     |

The agent achieves **near-perfect recall (0.978)** — catching almost every red-team event — while raising F1 by +0.015 over the static baseline. The precision gap reflects the LLM's tendency to flag borderline cases rather than miss them, which is the correct trade-off for a security detection system.

See [`evaluation/`](evaluation/) for full run artifacts and [`src/evaluation/metrics.py`](src/evaluation/metrics.py) for the comparison table generator.

---

## Project Structure

```
src/
├── pipeline/etl.py                  # DuckDB ETL → 4 Neo4j CSVs
├── servers/
│   ├── behavioral_server.py         # Phase 1: discovery tools
│   ├── topology_server.py           # Phase 2: centrality + path
│   └── investigation_server.py      # Phase 2: timeline + sessions
├── agent/orchestrator.py            # Two-phase agent
└── evaluation/
    ├── evaluator.py                 # Window + entity evaluation
    ├── baseline_evaluator.py        # Static Cypher baseline
    ├── metrics.py                   # Precision / recall / F1 comparison
    └── generate_cold_events.py      # Control case generation (run once)
```

---

## Steps to Run

### 1. Install dependencies
```bash
uv sync
```

### 2. Configure environment
Create a `.env` file:
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

### 3. Run ETL
Download `auth.txt` and `proc.txt` from [https://csr.lanl.gov/data/cyber1/](https://csr.lanl.gov/data/cyber1/), then:
```bash
uv run python -m src.pipeline.etl
```
Outputs 4 CSVs to `data/`.

### 4. Import into Neo4j
Download [Neo4j Desktop](https://neo4j.com/download/). Stop the instance, then run with 6GB heap:
```powershell
$env:JAVA_OPTS="-Xmx6G -Xms6G --add-opens=java.base/java.nio=ALL-UNNAMED"
.\bin\neo4j-admin database import full `
  --nodes=User=<path>\data\users.csv `
  --nodes=Computer=<path>\data\computers.csv `
  --relationships=AUTHENTICATED_TO=<path>\data\authentications.csv `
  --relationships=EXECUTED=<path>\data\process_events.csv `
  --overwrite-destination=true --skip-duplicate-nodes=true `
  --multiline-fields=true --skip-bad-relationships=true `
  --bad-tolerance=1000 --ignore-empty-strings=true --threads=4
```
Expected: ~12 minutes. Install the **Graph Data Science** plugin after import.

### 5. Generate control cases (once)
```bash
uv run python -m src.evaluation.generate_cold_events
```

### 6. Run the agent
```bash
uv run python src/agent/orchestrator.py
```

### 7. Run evaluation
```bash
# Entity mode — precision + recall + F1
uv run python -m src.evaluation.evaluator --mode entity --sample-size 12

# Window mode — recall only
uv run python -m src.evaluation.evaluator --mode window

# Static baseline
uv run python -m src.evaluation.baseline_evaluator --sample-size 12

# Comparison table
uv run python -m src.evaluation.metrics
```
