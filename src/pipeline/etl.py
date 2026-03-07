import duckdb
import os
import sys
from dotenv import load_dotenv

def run_etl():
    load_dotenv()
    auth_path = os.getenv('AUTH_DATASET_PATH')
    proc_path = os.getenv('PROC_DATASET_PATH')

    if not auth_path or not proc_path:
        print("Error: Please set AUTH_DATASET_PATH and PROC_DATASET_PATH environment variables.")
        sys.exit(1)

    try:
        con = duckdb.connect(database=':memory:')
        print("--- Starting LANL Data ETL Process ---")

        # Register Views for the Compressed Files
        con.execute(f"""
            CREATE VIEW raw_auth AS 
            SELECT * FROM read_csv_auto('{auth_path}', 
                names=['time', 'src_user', 'dst_user', 'src_device', 'dst_device', 'auth_type', 'logon_type', 'orientation', 'status'],
                nullstr='?');
        """)

        con.execute(f"""
            CREATE VIEW raw_proc AS 
            SELECT * FROM read_csv_auto('{proc_path}', 
                names=['time', 'user_domain', 'computer', 'process_name', 'event_type'],
                nullstr='?');
        """)

        # Node tables
        print("Creating 'computers' node table...")
        con.execute("""
                    CREATE TABLE computers AS
                    SELECT DISTINCT name FROM (
                                                  SELECT src_device AS name FROM raw_auth WHERE src_device IS NOT NULL
                                                  UNION
                                                  SELECT dst_device FROM raw_auth WHERE dst_device IS NOT NULL
                                                  UNION
                                                  SELECT computer FROM raw_proc WHERE computer IS NOT NULL
                                              );
                    """)

        print("Creating 'users' node table...")
        con.execute("""
                    CREATE TABLE users AS
                    SELECT DISTINCT username FROM (
                                                      SELECT src_user AS username FROM raw_auth WHERE src_user IS NOT NULL
                                                      UNION
                                                      SELECT dst_user FROM raw_auth WHERE dst_user IS NOT NULL
                                                      UNION
                                                      SELECT user_domain FROM raw_proc WHERE user_domain IS NOT NULL
                                                  );
                    """)

        print("Creating 'processes' node table...")
        con.execute("""
            CREATE TABLE processes AS 
            SELECT DISTINCT process_name FROM raw_proc WHERE process_name IS NOT NULL;
        """)

        # --- Static Edge Tables ---
        print("Creating 'user_owns_computer' edge table...")
        con.execute("""
                    CREATE TABLE user_owns_computer AS
                    SELECT DISTINCT username, computer_name FROM (
                                                                     SELECT src_user AS username, src_device AS computer_name FROM raw_auth
                                                                     UNION
                                                                     SELECT user_domain, computer FROM raw_proc
                                                                 ) WHERE username IS NOT NULL AND computer_name IS NOT NULL;
                    """)

        print("Creating 'computer_has_process' edge table...")
        con.execute("""
            CREATE TABLE computer_has_process AS 
            SELECT DISTINCT computer, process_name FROM raw_proc 
            WHERE computer IS NOT NULL AND process_name IS NOT NULL;
        """)

        # Temporal Event Tables (These are large, and contribute to 95% of the data stored) ---
        print("Creating 'authentications' event table (Temporal)...")
        con.execute("""
            CREATE TABLE authentications AS 
            SELECT time, src_user, dst_device, auth_type, logon_type, orientation 
            FROM raw_auth 
            WHERE status = 'Success' AND src_user IS NOT NULL AND dst_device IS NOT NULL;
        """)

        print("Creating 'process_events' event table (Temporal)...")
        con.execute("""
            CREATE TABLE process_events AS 
            SELECT time, user_domain, computer, process_name, event_type 
            FROM raw_proc
            WHERE user_domain IS NOT NULL AND computer IS NOT NULL AND process_name IS NOT NULL;
        """)

        # Export to CSV
        os.makedirs('data', exist_ok=True)

        tables = [
            'computers', 'users', 'processes',
            'user_owns_computer', 'computer_has_process',
            'authentications', 'process_events'
        ]

        for table in tables:
            print(f"Exporting {table} to data/{table}.csv...")

            # Header is set to True so Neo4j Data Importer can identify columns
            con.execute(f"COPY {table} TO 'data/{table}.csv' (HEADER, DELIMITER ',');")

        print("--- ETL Completed Successfully! ---")

    except Exception as e:
        print(f"ERROR: {type(e).__name__} occurred.\nDetails: {e}")

if __name__ == "__main__":
    run_etl()