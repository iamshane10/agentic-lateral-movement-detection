"""
conftest.py — pytest session-level configuration.

Sets required environment variables before any test module is imported.
This is critical for orchestrator.py, which validates NAVIGATOR_MODEL
at module import time and raises RuntimeError if it is absent.
"""

import os

# Set sentinel values before any src module is imported.
# These do NOT connect to real services — tests mock all external I/O.
os.environ.setdefault("NAVIGATOR_MODEL", "gpt-4o")
os.environ.setdefault("NAVIGATOR_API_BASE", "http://localhost:8000")
os.environ.setdefault("NEO4J_URI", "bolt://localhost:7687")
os.environ.setdefault("NEO4J_USER", "neo4j")
os.environ.setdefault("NEO4J_PASSWORD", "test_password")
os.environ.setdefault("REDTEAM_PATH", "data/redteam.txt")
