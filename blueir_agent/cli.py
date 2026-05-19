import argparse
from pathlib import Path

from blueir_agent.agent import BlueIRAgent


def _read_input(args: argparse.Namespace) -> str:
    if args.file:
        return Path(args.file).read_text(encoding="utf-8", errors="replace")
    if args.text:
        return args.text
    raise SystemExit("Provide --text or --file.")


def main() -> None:
    parser = argparse.ArgumentParser(description="BlueIR-Agent MVP")
    parser.add_argument("--text", help="Alert or log text to analyze.")
    parser.add_argument("--file", help="Path to a log/text file.")
    parser.add_argument("--case-id", help="Optional case ID.")
    parser.add_argument("--title", default="", help="Optional case title.")
    parser.add_argument("--incident-type", default="auto", help="auto, webshell, windows, linux, or generic.")
    parser.add_argument("--out", help="Optional Markdown report output path.")
    args = parser.parse_args()

    agent = BlueIRAgent()
    source = args.file or "cli_text"
    state = agent.analyze(
        _read_input(args),
        case_id=args.case_id,
        title=args.title,
        incident_type=args.incident_type,
        source=source,
    )

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(state.report_markdown, encoding="utf-8")
        print(f"Wrote report: {out}")
    else:
        print(state.report_markdown)


if __name__ == "__main__":
    main()
