import hashlib
import ipaddress
import struct
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FileAnalysisResult:
    text: str
    evidence_type: str
    metadata: dict[str, object] = field(default_factory=dict)


def analyze_file_bytes(filename: str, data: bytes) -> FileAnalysisResult:
    suffix = Path(filename).suffix.lower()
    metadata = {
        "filename": filename,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

    detected = _detect_file_type(data, suffix)
    metadata["detected_type"] = detected

    if detected == "text":
        return FileAnalysisResult(
            text=data.decode("utf-8", errors="replace"),
            evidence_type="text",
            metadata=metadata,
        )
    if detected == "pcap":
        summary = _summarize_pcap(data)
        metadata.update(summary)
        return FileAnalysisResult(
            text=_render_binary_summary(metadata, _extract_printable_strings(data)),
            evidence_type="pcap",
            metadata=metadata,
        )
    if detected == "pcapng":
        metadata["parser_note"] = "pcapng detected; v3 records metadata and strings only. Convert to pcap or add tshark/pyshark later for full flow parsing."
        return FileAnalysisResult(
            text=_render_binary_summary(metadata, _extract_printable_strings(data)),
            evidence_type="pcapng",
            metadata=metadata,
        )
    if detected == "evtx":
        metadata["parser_note"] = "EVTX detected; v3 records metadata and visible strings only. Export to CSV/XML for detailed event parsing."
        return FileAnalysisResult(
            text=_render_binary_summary(metadata, _extract_printable_strings(data, min_len=5)),
            evidence_type="evtx",
            metadata=metadata,
        )

    metadata["parser_note"] = "Unknown or unsupported binary file; v3 records metadata and visible strings only."
    return FileAnalysisResult(
        text=_render_binary_summary(metadata, _extract_printable_strings(data)),
        evidence_type="binary",
        metadata=metadata,
    )


def _detect_file_type(data: bytes, suffix: str) -> str:
    if data.startswith(b"\xd4\xc3\xb2\xa1") or data.startswith(b"\xa1\xb2\xc3\xd4") or data.startswith(b"\x4d\x3c\xb2\xa1") or data.startswith(b"\xa1\xb2\x3c\x4d"):
        return "pcap"
    if data.startswith(b"\x0a\x0d\x0d\x0a"):
        return "pcapng"
    if data.startswith(b"ElfFile\x00") or suffix == ".evtx":
        return "evtx"
    if suffix in {".txt", ".log", ".csv", ".json", ".xml", ".md"} or _looks_like_text(data):
        return "text"
    return "binary"


def _looks_like_text(data: bytes) -> bool:
    if not data:
        return True
    sample = data[:4096]
    blocked = sum(1 for byte in sample if byte == 0 or (byte < 9 or (13 < byte < 32)))
    return blocked / max(len(sample), 1) < 0.08


def _summarize_pcap(data: bytes) -> dict[str, object]:
    magic = data[:4]
    endian = "<" if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"} else ">"
    ns_resolution = magic in {b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
    summary: dict[str, object] = {"pcap_resolution": "nanosecond" if ns_resolution else "microsecond"}
    if len(data) < 24:
        summary["pcap_error"] = "File too small for a classic pcap global header."
        return summary

    try:
        version_major, version_minor, _tz, _sigfigs, snaplen, network = struct.unpack(endian + "HHIIII", data[4:24])
    except struct.error:
        summary["pcap_error"] = "Unable to parse pcap global header."
        return summary

    summary.update(
        {
            "pcap_version": f"{version_major}.{version_minor}",
            "pcap_snaplen": snaplen,
            "pcap_linktype": network,
        }
    )
    offset = 24
    packet_count = 0
    ipv4_flows: set[str] = set()
    first_ts = ""
    last_ts = ""

    while offset + 16 <= len(data) and packet_count < 5000:
        try:
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(endian + "IIII", data[offset : offset + 16])
        except struct.error:
            break
        offset += 16
        packet = data[offset : offset + incl_len]
        offset += incl_len
        if len(packet) < incl_len:
            break
        packet_count += 1
        timestamp = f"{ts_sec}.{ts_frac:09d}" if ns_resolution else f"{ts_sec}.{ts_frac:06d}"
        first_ts = first_ts or timestamp
        last_ts = timestamp
        if network == 1:
            flow = _extract_ethernet_ipv4_flow(packet)
            if flow:
                ipv4_flows.add(flow)

    summary["pcap_packet_count_sampled"] = packet_count
    summary["pcap_first_ts_epoch"] = first_ts or "-"
    summary["pcap_last_ts_epoch"] = last_ts or "-"
    summary["pcap_ipv4_flows"] = sorted(ipv4_flows)[:50]
    return summary


def _extract_ethernet_ipv4_flow(packet: bytes) -> str:
    if len(packet) < 34:
        return ""
    ethertype = struct.unpack("!H", packet[12:14])[0]
    if ethertype != 0x0800:
        return ""
    ip_start = 14
    version_ihl = packet[ip_start]
    if version_ihl >> 4 != 4:
        return ""
    ihl = (version_ihl & 0x0F) * 4
    if len(packet) < ip_start + ihl + 4:
        return ""
    proto = packet[ip_start + 9]
    src = str(ipaddress.ip_address(packet[ip_start + 12 : ip_start + 16]))
    dst = str(ipaddress.ip_address(packet[ip_start + 16 : ip_start + 20]))
    if proto in {6, 17} and len(packet) >= ip_start + ihl + 4:
        src_port, dst_port = struct.unpack("!HH", packet[ip_start + ihl : ip_start + ihl + 4])
        proto_name = "TCP" if proto == 6 else "UDP"
        return f"{proto_name} {src}:{src_port} -> {dst}:{dst_port}"
    return f"IP {src} -> {dst} proto={proto}"


def _extract_printable_strings(data: bytes, min_len: int = 6, limit: int = 80) -> list[str]:
    strings: list[str] = []
    current = bytearray()
    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
        else:
            if len(current) >= min_len:
                strings.append(current.decode("ascii", errors="ignore"))
                if len(strings) >= limit:
                    break
            current = bytearray()
    if len(current) >= min_len and len(strings) < limit:
        strings.append(current.decode("ascii", errors="ignore"))
    return strings


def _render_binary_summary(metadata: dict[str, object], strings: list[str]) -> str:
    lines = ["BLUEIR_FILE_ANALYSIS", "File metadata:"]
    for key, value in metadata.items():
        lines.append(f"- {key}: {value}")
    if strings:
        lines.extend(["", "Printable strings sample:"])
        lines.extend(f"- {item}" for item in strings[:80])
    return "\n".join(lines)
