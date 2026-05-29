"""
Launch script for Streamlit UI.
Run this file to start the web interface.
"""
import subprocess
import sys

if __name__ == "__main__":
    subprocess.run([
        sys.executable,
        "-m",
        "streamlit",
        "run",
        "app/ui/streamlit_app.py",
        "--server.port=8501",
        "--server.address=localhost",
    ])
