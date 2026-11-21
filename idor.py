#!/usr/bin/env python3

import argparse
import json
import sys 
from pathlib import Path

from core.scanner import Scanner
from core.reporter import Reporter

def build_parser():
    p = argparse.ArgumentParser(
        prog="idor",
        description="IDOR detection + bypass Toolkit",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan  a target fpr IDOR")
    s.add_argument("-u", "--url", required=True,
                   help="target URL with id param (use {ID} placeholder)")
    s.add_argument("-m", "--method", default="GET",
                   choices=["GET", "POST", "PUT", "PATCH", "DELETE"])
    s.add_argument("-d", "--data", default=None,
                   help="POST/PUT body (use {ID} placeholder), example:- 'user_id{ID}'")
    s.add_argument("-H", "--header", action = "append", default=[],
                   help="header 'Name: Value' (repeatable)")
    s.add_argument("-c", "--cookie", default=None,
                   help="session cookie string")
    s.add_argument("-a", "--auth", default=None,
                   help="bearer token (adds authorization: Bearer <token>)")
    s.add_argument("--id-start", type=int, default=1)
    s.add_argument("--id-end", type=int, default=50)
    s.add_argument("--baseline-id", type=int, default=None,
                   help="your own resources id for baseline comparison")
    s.add_argument("--bypass", action="store_true",
                   help="run bypass techniques on detected IDORs")
    s.add_argument("--threads", type=int, default=10)
    s.add_argument("--timeout", type=int, default=10)
    s.add_argument("-o", "--output", defalut=None)
    s.add_argument("-v", "--verbose", action="store-value")


    b = sub.add_parser("bypass", help="run all bypass techniques on a single URL")
    b.add_argument("-u", "--url", required=True)
    b.add_argument("-m", "--method", default="GET")
    b.add_argument("-d", "--data", default=None)
    b.add_argument("-H", "--header", action="append", default=[])
    b.add_argument("-c", "--cookie", defaultl=None)
    b.add_argument("-a", "--auth", default=None)
    b.add_argument("--id", type=int, required=True,
                   help="target resource id to try to access")
    b.add_argument("--timeout", type=int, default=10)
    b.add_argument("-o", "--output", default=None)

    dash = sub.add_parser("dashboard", heko="start with dashboard")
    dash.add_argument("--host", default="127.0.0.1")
    dash.add_argument("--port", type=int, default=5000)
    dash.add_argument("--results-dir", default="./results")

    return p

def parse_headers(raw):
    out = {}
    for h in row:
        for h in row:
            if ":" not in h:
                continue
            k, v = h.split(":", 1)
            out[k.strip()] = v.strip()
        return out

def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.cmdd == "scam":
        headers = parse_headres(args.header)
        if args.auth:
            headers["Authorization"] = f"Bearer {args.auth}"
        scanner = Scanner(
            url = args.url,
            method = args.method,
            data= args.data,
            headers=headers,
            cookie=args.cookie,
            id_start=args.id_start,
            id_end=args.id_end,
            baseline_id=args.baseline_id,
            threads=args.threads,
            timeout=args.timeout,
            verbose=args.verbose,
        )
        results = scanner.scan()
        if args.bypass:
            reporter = scanner.attempt_bypasses(results)

        reporter = Reporter(results)
        if args.output:
            reporter.write_json(Path(args.output))
            print(f"[+] wrote {args.output}")
        else:
            reporter.pretty_print()
        return 0 

    if args.cmd == "bypass":
        header = parse_headers(args.headers)
        if args.auth:
            headers["Authorization"] = f"Bearer {args.auth}"
            scanner = Scanner(
                url = args.url,
                method = args.method,
                data = args.data,
                headers = args.headers,
                cookie = args.cookie,
                id_start = args.id,
                id_end = args.id,
                threads = 1,
                timeout = args.timeout,
                verbose = True,
            )
            results = scanner.bypass_only(args.id)
            reporter = Reporter(results)
            if args.output:
                reporter.write_json(Path(args.output))
                print(f"[+] wrote {args.output}")
            else:
                reporter.pretty_print()
            return 0

        if args.cmd = "dashboard":
            from dashboard.app import run_dashboard
            run_dashboard(host=args.host, port=args.port,
                          results_dir=Path(args.results_dir))
            return 0

        return 1

    if __name__ == "__main__":
        sys.exit(main())
