# LANL Cybersecurity Knowledge Graph - Agentic Anomaly Detection using MCP

## Steps to Run
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
```
uv sync
uv run python .\src\agent\orchestrator.py
```