import re

from blueir_agent.agent.state import IOC

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:com|net|org|cn|io|ru|top|xyz|info|biz|cc|me|site)\b")
TIMESTAMP_RE = re.compile(
    r"(?P<iso>\b20\d{2}[-/]\d{1,2}[-/]\d{1,2}[ T]\d{1,2}:\d{2}:\d{2}\b)|"
    r"(?P<apache>\[\d{1,2}/[A-Za-z]{3}/20\d{2}:\d{1,2}:\d{2}:\d{2} [+-]\d{4}\])"
)


def _uniq(values: list[str]) -> list[str]:
    return sorted(set(value.strip(".,;)]}") for value in values if value.strip()))


def extract_iocs(text: str) -> dict[str, list[str]]:
    urls = _uniq(URL_RE.findall(text))
    return {
        "ipv4": _uniq(IPV4_RE.findall(text)),
        "urls": urls,
        "domains": _uniq([domain for domain in DOMAIN_RE.findall(text) if not any(domain in url for url in urls)]),
        "emails": _uniq(EMAIL_RE.findall(text)),
        "hashes": _uniq(HASH_RE.findall(text)),
    }


def extract_structured_iocs(text: str, source: str = "input") -> list[IOC]:
    raw = extract_iocs(text)
    structured = []
    for ioc_type, values in raw.items():
        for value in values:
            structured.append(
                IOC(
                    value=value,
                    ioc_type=ioc_type.rstrip("s"),
                    source=source,
                    confidence="high" if ioc_type in {"ipv4", "urls", "hashes"} else "medium",
                    first_seen=_first_seen_for_value(text, value),
                )
            )
    return structured


def extract_timestamp(line: str) -> str:
    match = TIMESTAMP_RE.search(line)
    if not match:
        return ""
    return match.group(0).strip("[]")


def _first_seen_for_value(text: str, value: str) -> str:
    for line in text.splitlines():
        if value in line:
            return extract_timestamp(line)
    return ""
