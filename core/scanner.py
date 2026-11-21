"""orchestrator — runs detection then bypasses."""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

from .detector import Detector, find_sensitive_patterns
from .bypass import BypassEngine


class Scanner:
    def __init__(self, url, method="GET", data=None, headers=None, cookie=None,
                 id_start=1, id_end=50, baseline_id=None, threads=10,
                 timeout=10, verbose=False):
        if id_start > id_end:
            raise ValueError("id-start cannot be greater than id-end")
        if threads < 1:
            raise ValueError("threads must be at least 1")
        if timeout < 1:
            raise ValueError("timeout must be at least 1")
        self.url = url
        self.method = method.upper()
        self.data = data
        self.headers = headers or {}
        self.cookie = cookie
        self.id_start = id_start
        self.id_end = id_end
        self.baseline_id = baseline_id
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose

        self.session = requests.Session()
        if cookie:
            self.session.headers["Cookie"] = cookie
        for k, v in self.headers.items():
            self.session.headers[k] = v

    # --- helpers ---

    def _url_for_id(self, id_value):
        return self.url.replace("{ID}", str(id_value))

    def _data_for_id(self, id_value):
        if not self.data:
            return None
        return self.data.replace("{ID}", str(id_value))

    def _request(self, detector, id_value):
        url = self._url_for_id(id_value)
        body = self._data_for_id(id_value)
        res = detector.fetch(self.method, url, data=body, headers=self.headers)
        res["id"] = id_value
        res["url"] = url
        return res

    # --- detection ---

    def scan(self):
        if self.verbose:
            print(f"[*] scanning {self.url} ids {self.id_start}-{self.id_end}")

        detector = Detector(self.session, self.timeout, self.verbose)
        baseline_id = self.baseline_id if self.baseline_id is not None else self.id_start
        baseline = self._request(detector, baseline_id)
        if "error" in baseline:
            return {"error": baseline["error"], "target": self.url}

        if self.verbose:
            print(f"[*] baseline id={baseline_id} status={baseline['status']} "
                  f"len={baseline['length']}")

        candidates = [i for i in range(self.id_start, self.id_end + 1)
                      if i != baseline_id]

        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._request, detector, i): i for i in candidates}
            for fut in as_completed(futures):
                r = fut.result()
                if "error" in r:
                    continue
                comparison = detector.compare(baseline, r)
                r["comparison"] = comparison
                if comparison.get("verdict") == "distinct":
                    r["sensitive"] = find_sensitive_patterns(r["body"])
                    results.append(r)
                    if self.verbose:
                        print(f"[!] IDOR candidate id={r['id']} "
                              f"status={r['status']} len={r['length']}")

        return {
            "target": self.url,
            "method": self.method,
            "baseline_id": baseline_id,
            "baseline_status": baseline["status"],
            "scanned": len(candidates),
            "idor_candidates": sorted(results, key=lambda x: x["id"]),
        }

    # --- bypass ---

    def attempt_bypasses(self, scan_results):
        """for every IDOR candidate, try bypass techniques."""
        candidates = scan_results.get("idor_candidates", [])
        if not candidates:
            return scan_results

        detector = Detector(self.session, self.timeout, self.verbose)
        baseline_id = scan_results["baseline_id"]

        enriched = []
        for cand in candidates[:5]:  # cap to keep it sane
            cand_id = cand["id"]
            bypasses = self._run_bypass_matrix(detector, cand_id, baseline_id)
            cand["bypass_attempts"] = bypasses
            cand["bypass_successes"] = [b for b in bypasses if b.get("success")]
            enriched.append(cand)

        scan_results["idor_candidates"] = enriched + candidates[5:]
        return scan_results

    def bypass_only(self, target_id):
        """run every bypass on a single id — used by the bypass subcommand."""
        detector = Detector(self.session, self.timeout, self.verbose)
        baseline_id = self.baseline_id or 1
        baseline = self._request(detector, baseline_id)
        attempts = self._run_bypass_matrix(detector, target_id, baseline_id)
        return {
            "target": self.url,
            "method": self.method,
            "target_id": target_id,
            "baseline_id": baseline_id,
            "attempts": attempts,
            "successes": [a for a in attempts if a.get("success")],
        }

    def _run_bypass_matrix(self, detector, id_value, baseline_id):
        attempts = []
        baseline = self._request(detector, baseline_id)

        def add(label, url, method, data, headers, cookie=None):
            hdrs = dict(headers)
            if cookie is not None:
                hdrs["Cookie"] = cookie
            res = detector.fetch(method, url, data=data, headers=hdrs)
            if "error" in res:
                attempts.append({"technique": label, "error": res["error"]})
                return
            comp = detector.compare(baseline, res)
            success = comp.get("verdict") == "distinct"
            attempts.append({
                "technique": label,
                "url": url,
                "method": method,
                "status": res["status"],
                "length": res["length"],
                "similarity": comp.get("similarity"),
                "verdict": comp.get("verdict"),
                "success": success,
                "sensitive": find_sensitive_patterns(res["body"]) if success else {},
            })

        base_url = self._url_for_id(id_value)
        base_body = self._data_for_id(id_value)

        # 1. header bypasses
        for name, value in BypassEngine.header_bypasses():
            hdrs = {**self.headers, name: value}
            add(f"header {name}: {value}", base_url, self.method, base_body, hdrs)

        # 2. path bypasses
        for v in BypassEngine.path_bypasses(base_url):
            add(f"path {v}", v, self.method, base_body, self.headers)

        # 3. id mutations (in url and body)
        for mut in BypassEngine.id_mutations(id_value):
            url = self._url_for_id(mut) if "{ID}" in self.url else base_url
            body = self._data_for_id(mut) if self.data and "{ID}" in (self.data or "") else base_body
            add(f"id-mutation {mut}", url, self.method, body, self.headers)

        # 4. query param injection
        for v in BypassEngine.query_params_bypasses(base_url):
            add(f"query {v}", v, self.method, base_body, self.headers)

        # 5. method swap
        for m in BypassEngine.http_method_bypasses(self.method):
            add(f"method {m}", base_url, m, base_body, self.headers)

        # 6. content-type swaps
        for k, v in BypassEngine.content_type_bypasses():
            hdrs = {**self.headers, k: v}
            add(f"content-type {v}", base_url, self.method, base_body, hdrs)

        # 7. auth strip / downgrade
        for label, hdrs in BypassEngine.auth_strip_bypasses(self.headers):
            add(f"auth {label}", base_url, self.method, base_body, hdrs)

        # 8. cookie mutations
        if self.cookie:
            for label, ck in BypassEngine.cookie_bypasses(self.cookie):
                add(f"cookie {label}", base_url, self.method, base_body,
                    self.headers, cookie=ck)

        return attempts