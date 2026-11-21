"""output formatting."""

import json
from pathlib import Path


class Reporter:
    def __init__(self, results):
        self.results = results

    def write_json(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.results, indent=2, default=str))

    def pretty_print(self):
        try:
            from rich.console import Console
            from rich.table import Table
            from rich.panel import Panel
        except ImportError:
            print(json.dumps(self.results, indent=2, default=str))
            return

        console = Console()

        # scan mode
        if "idor_candidates" in self.results:
            console.rule(f"[bold]IDOR scan — {self.results['target']}")
            console.print(
                f"baseline={self.results['baseline_id']} "
                f"status={self.results['baseline_status']} "
                f"scanned={self.results['scanned']}"
            )
            candidates = self.results["idor_candidates"]
            if not candidates:
                console.print("[green]no IDOR candidates found[/green]")
                return

            table = Table(show_header=True, header_style="bold magenta")
            for c in ("id", "status", "length", "similarity", "sensitive"):
                table.add_column(c)
            for c in candidates:
                table.add_row(
                    str(c["id"]),
                    str(c["status"]),
                    str(c["length"]),
                    str(c.get("comparison", {}).get("similarity", "")),
                    ", ".join(c.get("sensitive", {}).keys()) or "-",
                )
            console.print(table)

            # show bypass successes if present
            for c in candidates:
                if c.get("bypass_successes"):
                    console.print(Panel(
                        "\n".join(
                            f"{b['technique']} -> {b['status']} ({b.get('verdict')})"
                            for b in c["bypass_successes"]
                        ),
                        title=f"[yellow]bypass successes for id={c['id']}",
                    ))
            return

        # bypass mode
        if "attempts" in self.results:
            console.rule(f"[bold]IDOR bypass — id={self.results['target_id']}")
            console.print(
                f"attempts={len(self.results['attempts'])} "
                f"successes={len(self.results['successes'])}"
            )
            table = Table(show_header=True, header_style="bold magenta")
            for col in ("technique", "status", "verdict", "success", "sensitive"):
                table.add_column(col)
            for a in self.results["attempts"]:
                if a.get("error"):
                    table.add_row(a["technique"], "ERR", a["error"], "", "")
                    continue
                table.add_row(
                    a["technique"],
                    str(a.get("status", "")),
                    a.get("verdict", ""),
                    "[green]YES[/green]" if a.get("success") else "no",
                    ", ".join(a.get("sensitive", {}).keys()) or "-",
                )
            console.print(table)
            return

        console.print(json.dumps(self.results, indent=2, default=str))