# Security Policy

BlueIR-Agent is designed for defensive, human-in-the-loop incident response
analysis.

## Secret Handling

- Do not commit real API keys, tokens, logs from production systems, or incident
  evidence that contains sensitive data.
- Configure model credentials through environment variables such as
  `DEEPSEEK_API_KEY`.
- Rotate any key that has been shared in chat, screenshots, issues, commits, or
  logs.

## Safe Use

- The agent is read-only by default.
- It must not automatically delete files, clear logs, isolate hosts, block IPs,
  exploit services, or scan public targets.
- Treat containment and eradication steps as recommendations requiring human
  approval.

## Reporting Issues

For competition or classroom usage, report security issues privately to the
project owner before publishing details.
