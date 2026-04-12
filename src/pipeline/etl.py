import os
import sys

import duckdb
from dotenv import load_dotenv

from ..utils.performance_tracker import PerformanceTracker


def run_etl():
    load_dotenv()
    auth_path = os.getenv('AUTH_DATASET_PATH')
    proc_path = os.getenv('PROC_DATASET_PATH')

    # Define our "Interest Window" based on redteam.txt
    START_TIME_COLD = 633600
    END_TIME_COLD   = 640800
    START_TIME_HOT  = 763200
    END_TIME_HOT    = 770400

    print(f"Hot Window (red team): {START_TIME_HOT} to {END_TIME_HOT}")
    print(f"Cold Window (control): {START_TIME_COLD} to {END_TIME_COLD}")

    if not auth_path or not proc_path:
        print("Error: Please set AUTH_DATASET_PATH and PROC_DATASET_PATH environment variables.")
        sys.exit(1)

    tracker = PerformanceTracker()

    try:
        print("=" * 70)
        print("LANL DATASET ETL PIPELINE WITH PERFORMANCE TRACKING")
        print("=" * 70)
        print(f"\nTime Window: Hot - {START_TIME_HOT} to {END_TIME_HOT}, Cold - {START_TIME_COLD} to {END_TIME_COLD}")
        print(f"Authentication Dataset: {auth_path}")
        print(f"Process Dataset: {proc_path}")

        # Initialize DuckDB
        tracker.start_step("Database Initialization")
        con = duckdb.connect(database=':memory:')
        tracker.end_step("Database Initialization")

        # Register Views
        tracker.start_step("Loading Raw Data Views")
        con.execute(
            f"CREATE VIEW raw_auth AS SELECT * FROM read_csv_auto('{auth_path}', names=['time', 'src_user', 'dst_user', 'src_device', 'dst_device', 'auth_type', 'logon_type', 'orientation', 'status'], nullstr='?');")
        con.execute(
            f"CREATE VIEW raw_proc AS SELECT * FROM read_csv_auto('{proc_path}', names=['time', 'user_domain', 'computer', 'process_name', 'event_type'], nullstr='?');")

        auth_size = tracker.record_dataset_size(con, 'raw_auth', 'Raw authentication events')
        proc_size = tracker.record_dataset_size(con, 'raw_proc', 'Raw process events')
        tracker.end_step("Loading Raw Data Views", {
            'auth_events': auth_size,
            'process_events': proc_size
        })

        # --- NODES ---
        tracker.start_step("Creating Node Tables")
        print("\nNode Counts:")
        con.execute(
            "CREATE TABLE computers AS SELECT DISTINCT name FROM (SELECT src_device AS name FROM raw_auth UNION SELECT dst_device FROM raw_auth UNION SELECT computer FROM raw_proc) WHERE name IS NOT NULL;")
        con.execute(
            "CREATE TABLE users AS SELECT DISTINCT username FROM (SELECT src_user AS username FROM raw_auth UNION SELECT dst_user FROM raw_auth UNION SELECT user_domain FROM raw_proc) WHERE username IS NOT NULL;")

        tracker.record_node_count(con, 'computers', 'Computers')
        tracker.record_node_count(con, 'users', 'Users')
        tracker.end_step("Creating Node Tables")

        # --- TEMPORAL EVENTS ---
        tracker.start_step("Filtering Temporal Events")
        print("\nTemporal Event Reduction:")

        con.execute(f"""
            CREATE TABLE authentications AS 
            SELECT time, src_user, dst_device, auth_type, logon_type, orientation, status 
            FROM raw_auth 
            WHERE (
                (time >= 763200 AND time <= 770400)
                OR
                (time >= 633600 AND time <= 640800)
            )
            AND src_user IS NOT NULL AND dst_device IS NOT NULL;
        """)

        con.execute(f"""
            CREATE TABLE process_events AS 
            SELECT time, user_domain, computer, process_name, event_type 
            FROM raw_proc
            WHERE (
                (time >= 763200 AND time <= 770400)
                OR
                (time >= 633600 AND time <= 640800)
            )
            AND user_domain IS NOT NULL AND computer IS NOT NULL AND process_name IS NOT NULL;
        """)

        tracker.record_temporal_reduction(con, 'raw_auth', 'authentications', 'Authentications')
        tracker.record_temporal_reduction(con, 'raw_proc', 'process_events', 'Process Events')
        tracker.end_step("Filtering Temporal Events")

        # Export with Neo4j-Ready Headers
        tracker.start_step("Exporting to CSV")
        os.makedirs('data', exist_ok=True)

        export_configs = {
            'computers': 'name:ID(Computer)',
            'users': 'username:ID(User)',
            'authentications': 'time:LONG,:START_ID(User),:END_ID(Computer),auth_type,logon_type,orientation,status',
            'process_events': 'time:LONG,:START_ID(User),:END_ID(Computer),process_name,event_type'
        }

        for table, header in export_configs.items():
            csv_path = f'data/{table}.csv'
            temp_path = f'data/{table}_temp.csv'

            # 1. Export from DuckDB without headers
            con.execute(f"COPY (SELECT * FROM {table}) TO '{csv_path}' (HEADER FALSE, DELIMITER ',');")

            # 2. Stream to a new file to insert the header (Memory Safe)
            with open(csv_path, 'r', encoding='utf-8') as f_in:
                with open(temp_path, 'w', encoding='utf-8', newline='') as f_out:
                    f_out.write(header + '\n')
                    # This loop is a generator; it only keeps one line in RAM at a time
                    for line in f_in:
                        f_out.write(line)

            # 3. Swap the files
            os.replace(temp_path, csv_path)

            file_size_mb = os.path.getsize(csv_path) / 1024 / 1024
            print(f"  Exported {table}.csv ({file_size_mb:.2f} MB)")

        tracker.end_step("Exporting to CSV")

        # Finalize and save reports
        tracker.finalize()
        tracker.print_summary()
        tracker.save_to_json()
        tracker.save_to_markdown()

        print("\n✓ ETL Pipeline Completed Successfully!")

    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    run_etl()
