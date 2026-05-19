import collections
import re

from blueir_agent.agent.state import AnalysisState, Finding
from blueir_agent.tools import extract_timestamp


class WindowsLogonSkill:
    name = "windows_logon"
    description = "Analyze Windows logon events for brute-force and suspicious successful logons."

    EVENT_IDS = {
        "4624": "successful logon",
        "4625": "failed logon",
        "4648": "explicit credential logon",
        "4672": "special privileges assigned",
        "4720": "user account created",
        "4728": "member added to privileged group",
        "7045": "service installed",
    }

    def score(self, state: AnalysisState) -> int:
        text = state.input_text
        return sum(3 for event_id in self.EVENT_IDS if event_id in text)

    def run(self, state: AnalysisState) -> None:
        text = state.input_text
        event_counts = {event_id: len(re.findall(rf"\b{event_id}\b", text)) for event_id in self.EVENT_IDS}
        failed = event_counts.get("4625", 0)
        success = event_counts.get("4624", 0)
        explicit = event_counts.get("4648", 0)
        source_ips = collections.Counter(state.iocs.get("ipv4", []))
        accounts = collections.Counter(re.findall(r"(?:Account|TargetUserName|UserName)=([\w.$@-]+)", text, re.IGNORECASE))
        logon_types = collections.Counter(re.findall(r"LogonType=([0-9]+)", text, re.IGNORECASE))

        if failed or success or explicit:
            state.incident_type = "windows_logon_triage"
            evidence = [
                f"Event {event_id} ({label}): {count}"
                for event_id, label in self.EVENT_IDS.items()
                if (count := event_counts[event_id])
            ]
            evidence.extend(f"Observed source IP: {ip} ({count} occurrence)" for ip, count in source_ips.most_common(10))
            evidence.extend(f"Observed account: {account} ({count} occurrence)" for account, count in accounts.most_common(10))
            evidence.extend(f"Observed LogonType: {logon_type} ({count} occurrence)" for logon_type, count in logon_types.most_common(10))
            severity = "high" if failed >= 5 and success >= 1 else "medium"
            state.findings.append(
                Finding(
                    title="Suspicious Windows authentication activity",
                    severity=severity,
                    evidence=evidence,
                    recommendation=(
                        "Correlate failed and successful logons by account, source IP, host, and logon type. "
                        "Force password reset and review privileged activity if a brute-force success is confirmed."
                    ),
                )
            )
            state.attack_mapping.append(
                {
                    "tactic": "Credential Access",
                    "technique": "Brute Force",
                    "id": "T1110",
                }
            )
            if explicit or event_counts.get("7045", 0):
                state.attack_mapping.append(
                    {
                        "tactic": "Lateral Movement / Persistence",
                        "technique": "Valid Accounts or System Services",
                        "id": "T1078 / T1543",
                    }
                )
            for line in state.input_text.splitlines():
                timestamp = extract_timestamp(line)
                event_match = re.search(r"\b(4624|4625|4648|4672|4720|4728|7045)\b", line)
                if timestamp and event_match:
                    event_id = event_match.group(1)
                    state.add_timeline(
                        timestamp=timestamp,
                        title=f"Windows event {event_id}: {self.EVENT_IDS.get(event_id, 'security event')}",
                        source=self.name,
                        evidence=line[:500],
                        confidence="high",
                    )
