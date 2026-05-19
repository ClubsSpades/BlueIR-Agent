from blueir_agent.agent.state import AnalysisState, Finding


class FileEvidenceSkill:
    name = "file_evidence"
    description = "Summarize uploaded binary or special forensic files such as pcap, pcapng, and evtx."

    def score(self, state: AnalysisState) -> int:
        if "BLUEIR_FILE_ANALYSIS" in state.input_text:
            return 3
        if any(item.evidence_type in {"pcap", "pcapng", "evtx", "binary"} for item in state.evidence_items):
            return 3
        return 0

    def run(self, state: AnalysisState) -> None:
        for item in state.evidence_items:
            if item.evidence_type not in {"pcap", "pcapng", "evtx", "binary"}:
                continue
            metadata = item.metadata
            detected = str(metadata.get("detected_type", item.evidence_type))
            state.incident_type = f"{detected}_file_triage"
            evidence = [
                f"File: {item.source}",
                f"Detected type: {detected}",
                f"Size: {metadata.get('size_bytes', '-')}",
                f"SHA256: {metadata.get('sha256', '-')}",
            ]
            if detected == "pcap":
                evidence.extend(
                    [
                        f"PCAP version: {metadata.get('pcap_version', '-')}",
                        f"Packets sampled: {metadata.get('pcap_packet_count_sampled', '-')}",
                        f"First timestamp epoch: {metadata.get('pcap_first_ts_epoch', '-')}",
                        f"Last timestamp epoch: {metadata.get('pcap_last_ts_epoch', '-')}",
                    ]
                )
                flows = metadata.get("pcap_ipv4_flows", [])
                if flows:
                    evidence.append("IPv4 flows:")
                    evidence.extend(f"  {flow}" for flow in flows[:20])
            if metadata.get("parser_note"):
                evidence.append(str(metadata["parser_note"]))

            state.findings.append(
                Finding(
                    title=f"Uploaded {detected.upper()} evidence processed",
                    severity="info",
                    evidence=evidence,
                    recommendation=_recommendation_for_type(detected),
                )
            )


def _recommendation_for_type(detected: str) -> str:
    if detected == "pcap":
        return (
            "Review extracted flows and IOC first. For full protocol reconstruction, run tshark/Zeek/Suricata "
            "and upload the exported logs back into BlueIR-Agent."
        )
    if detected == "pcapng":
        return "Convert pcapng to pcap or export tshark/Zeek logs for deeper parsing in a future workflow."
    if detected == "evtx":
        return "Export EVTX to CSV/XML with Windows Event Viewer, EvtxECmd, or wevtutil, then analyze the exported file."
    return "Treat this as binary evidence. Preserve the original file and upload extracted text/log output for deeper triage."
