# BlueIR-Agent

BlueIR-Agent is a small blue-team incident response assistant for competition demos.
It focuses on defensive analysis: alert triage, IOC extraction, web log review,
Windows logon brute-force analysis, MITRE ATT&CK mapping, and Markdown report
generation.

The MVP uses a single DeepSeek provider today, but the code is structured around a
provider interface so more model APIs can be added later.

## Safety Position

- Read-only analysis by default.
- No automatic deletion, blocking, isolation, exploitation, or public scanning.
- High-risk response actions are returned as human-reviewed recommendations only.
- Tool outputs are structured before they are sent to the model.

## Quick Start

```bash
cd /Users/spadesclubs/Agent/blueir-agent
export DEEPSEEK_API_KEY="your_api_key_here"
python3 -m blueir_agent.cli --text "2026-05-19 failed login from 8.8.8.8 for admin then success"
```

Start the lightweight Web UI:

```bash
cd /Users/spadesclubs/Agent/blueir-agent
export DEEPSEEK_API_KEY="your_api_key_here"
python3 -m blueir_agent.web
```

Then open:

```txt
http://127.0.0.1:8765
```

If `DEEPSEEK_API_KEY` is missing, the agent still runs in local heuristic mode so
you can test the workflow without spending tokens.

## Configuration

Environment variables:

```txt
DEEPSEEK_API_KEY      Required for model calls.
BLUEIR_MODEL          Optional. Default: deepseek-v4-pro.
BLUEIR_BASE_URL       Optional. Default: https://api.deepseek.com.
BLUEIR_TIMEOUT        Optional seconds. Default: 60.
```

## Project Layout

```txt
blueir_agent/
  agent/              Orchestrator, state, guardrails, model router.
  providers/          LLM provider abstraction and DeepSeek implementation.
  skills/             Defensive analysis skills.
  tools/              Read-only local analysis helpers.
  web/                Standard-library Web UI.
examples/             Sample logs for testing.
reports/              Generated reports.
tests/                Lightweight smoke tests.
```

## MVP Capabilities

- IOC extraction for IPv4, domains, URLs, hashes, and emails.
- Webshell-oriented web log triage.
- Windows logon brute-force triage for common event IDs.
- Initial ATT&CK mapping from observed evidence.
- Markdown incident report generation.
- Optional DeepSeek summarization and reasoning.

## Competition Narrative

BlueIR-Agent is a human-in-the-loop blue-team assistant. It combines structured
security skills, read-only evidence tools, and model reasoning to produce
auditable incident reports. Its model provider layer is designed for future
multi-model routing across DeepSeek, Qwen, Kimi, Zhipu, OpenAI-compatible
providers, and local Ollama models.
