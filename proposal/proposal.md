# Project Proposal: Agentic Knowledge Graphs for Context-Aware Vulnerability Analysis

Direction B - Comparative Analysis of Agentic AI vs. Traditional Data Pipelines in Cybersecurity

## 1. Executive Summary
   Modern cybersecurity operations are overwhelmed by "alert fatigue," where thousands of vulnerabilities (CVEs) are identified, but only a fraction are actually reachable or pose a significant threat. This project proposes a novel agentic data pipeline that utilizes a Knowledge Graph (KG) and Model Context Protocol (MCP) servers to autonomously reason about the Attack Surface and Blast Radius of a network. We will evaluate this system against traditional tabular data engineering approaches using the LANL Cybersecurity Dataset.

## 2. Research Question
   To what extent does an LLM-orchestrated Agentic Graph system improve the precision of vulnerability analysis compared to traditional relational data pipelines?

#### Importance for Data Engineering
Current data engineering in security focuses on ETL (Extract, Transform, Load) for storage. This research shifts the focus to ETE (Extract, Transform, Explain). It demonstrates how data engineers can move beyond simple joins to build "reasoning engines" that preserve semantic relationships, significantly reducing the manual triage workload for security analysts.

## 3. Project Direction & Dataset
   Direction: B (Compare LLM vs. Traditional Technologies). This direction was chosen to provide a rigorous, quantifiable baseline for the performance gains offered by Agentic AI.

Dataset: The LANL Publicly Available Computer Network Dataset (https://csr.lanl.gov/data/cyber1/). This is a multi-source dataset containing:

- Network Flows: Traffic between hosts and ports.

- Authentication: User logins and lateral movement.

- Processes: Software execution events.

- Red Team: Ground truth of known compromise events.

## 4. Initial Design & Architecture
### System Architecture
   The pipeline consists of four layers:

- Ingestion Layer: Parses LANL CSV/JSON into a Neo4j Graph Database.

- Semantic Layer (MCP Servers): A set of specialized Python-based tools that allow the LLM to "query" the graph for complex security logic.

- Orchestration Layer: An LLM Agent (using Navigator AI) that acts as a lead investigator.

- Output Layer: A prioritized risk report with natural language justifications.

#### MCP Server Specifications
We will implement three custom MCP servers:

- Inventory Server: Maps anonymized ProcessIDs to CPE strings and queries the National Vulnerability Database (NVD) for CVE enrichment.

- Topology Server: Computes graph metrics such as Shortest Path and Betweenness Centrality to identify "Choke Points."

- Reachability Server: Correlates flows.txt with CVE requirements (e.g., if a CVE requires Port 445, it checks if that port is active on the host).

## 5. Evaluation Plan
###   Metrics
   We will evaluate the system using three primary dimensions:

Precision & Recall: Using the redteam.txt data file to identify if the system correctly flagged compromised hosts as "High Risk."

Alert Reduction Rate: The percentage of "Noise" (CVEs on unreachable ports) removed by the Agent compared to the baseline.

Explainability Score: A qualitative assessment of the Agent's reasoning compared to the "Logic" of a static SQL query.

### Baselines for Comparison
Baseline A (Tabular/SQL): A traditional relational approach where proc.txt is joined directly to a CVE table.

Baseline B (Static Cypher): A graph approach using fixed, non-AI queries to find port/host matches.

Ground Truth Collection
Ground truth is established via the Red Team compromise events provided in the LANL dataset. We will also utilize community-vetted process-to-CPE mappings to ensure our software inventory is technically accurate.

## 6. Timeline
- Project Proposal	- Mon, Feb 23 - Initial design with research question (Completed)
- Design Review	- Mon, Mar 2 - Detailed architecture, evaluation plan
- Code Checkpoint -	Mon, Mar 30 - 	Initial working prototype (includes +1 week than given on website)
- Draft Paper - Mon, Apr 6	- Complete draft for feedback
- Final Paper -	Mon, Apr 13	- Polished paper with full evaluation
- Presentation - Week of Apr 20 - 10-minute presentation + Q&A

## 7. Conclusion
   By the end of this project, we aim to prove that Agentic AI is not just a wrapper for queries, but a superior method for handling the relational complexity of cybersecurity data. This architecture provides a scalable blueprint for the next generation of Security Data Engineering.
