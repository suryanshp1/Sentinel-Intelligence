"""Compatibility entry point for the production PostgreSQL/Valkey integration suite."""
import pathlib
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parents[1]
sys.exit(subprocess.call(["node", "scripts/test-production.mjs"], cwd=root))
