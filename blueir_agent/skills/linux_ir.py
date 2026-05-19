import re

from blueir_agent.agent.state import AnalysisState, Finding
from blueir_agent.tools import extract_timestamp


class LinuxIRSkill:
    name = "linux_ir"
    description = "Analyze pasted Linux incident response evidence for suspicious logins, processes, ports, and persistence."

    TERMS = [
        "uid=0",
        "accepted password",
        "failed password",
        "sudo",
        "crontab",
        "authorized_keys",
        "/dev/tcp/",
        "bash -i",
        "nc -e",
        "python -c",
        "curl ",
        "wget ",
        "chmod +x",
    ]

    def score(self, state: AnalysisState) -> int:
        text = state.input_text.lower()
        return sum(2 for term in self.TERMS if term in text)

    def run(self, state: AnalysisState) -> None:
        suspicious_lines = []
        for line in state.input_text.splitlines():
            lowered = line.lower()
            if any(term in lowered for term in self.TERMS):
                suspicious_lines.append(line[:500])
                timestamp = extract_timestamp(line)
                if timestamp:
                    state.add_timeline(
                        timestamp=timestamp,
                        title="Suspicious Linux IR evidence",
                        source=self.name,
                        evidence=line[:500],
                        confidence="medium",
                    )

        if not suspicious_lines:
            return

        state.incident_type = "linux_ir_triage"
        ports = set(re.findall(r"/dev/tcp/[^/\s]+/(\d{2,5})", state.input_text, re.IGNORECASE))
        ports.update(re.findall(r"\bport\s+(\d{2,5})\b", state.input_text, re.IGNORECASE))
        listening_ports = sorted(ports, key=int)
        evidence = suspicious_lines[:12]
        evidence.extend(f"Observed listening or connected port: {port}" for port in listening_ports[:10])
        state.findings.append(
            Finding(
                title="Suspicious Linux host activity",
                severity="high" if any("bash -i" in line.lower() or "nc -e" in line.lower() for line in suspicious_lines) else "medium",
                evidence=evidence,
                recommendation=(
                    "Preserve shell history and authentication logs, confirm suspicious processes and persistence, "
                    "review SSH keys and cron/systemd entries, and contain the host only after approval."
                ),
            )
        )
        state.attack_mapping.append(
            {
                "tactic": "Execution / Persistence",
                "technique": "Command and Scripting Interpreter / Scheduled Task",
                "id": "T1059 / T1053",
            }
        )
