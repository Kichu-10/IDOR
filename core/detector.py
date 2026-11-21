"""detection engine — compares responses across ids to spot IDOR."""

import hashlib
import re
import requests
from difflib import SequenceMatcher


class Detector:
    def __init__(self, session, timeout=10, verbose=False):
        self.session = session
        self.timeout = timeout
        self.verbose = verbose

    def fetch(self, method, url, data=None, headers=None):
        try:
            r = self.session.request(
                method=method.upper(),
                url=url,
                data=data,
                headers=headers or {},
                timeout=self.timeout,
                allow_redirects=False,
            )
            return {
                "status": r.status_code,
                "length": len(r.content),
                "body": r.text,
                "headers": dict(r.headers),
                "hash": hashlib.sha256(r.content).hexdigest()[:16],
            }
        except requests.RequestException as e:
            return {"error": str(e)}

    def compare(self, baseline, test):
        """return similarity + verdict dict"""
        if "error" in baseline or "error" in test:
            return {"verdict": "error"}

        status_match = baseline["status"] == test["status"]
        length_diff = abs(baseline["length"] - test["length"])
        length_pct = length_diff / max(baseline["length"], 1)

        # fuzzy similarity
        sim = SequenceMatcher(
            None, baseline["body"][:5000], test["body"][:5000]
        ).ratio()

        if test["hash"] == baseline["hash"]:
            verdict = "identical"
        elif status_match and sim > 0.95 and length_pct < 0.05:
            verdict = "identical"
        elif status_match and sim > 0.7:
            verdict = "similar"
        elif status_match and 200 <= test["status"] < 300 and length_diff > 100:
            verdict = "distinct"
        elif test["status"] in (401, 403):
            verdict = "denied"
        elif test["status"] == 404:
            verdict = "not_found"
        elif 200 <= test["status"] < 300:
            verdict = "distinct"
        else:
            verdict = "other"

        return {
            "verdict": verdict,
            "status": test["status"],
            "length": test["length"],
            "length_diff": length_diff,
            "similarity": round(sim, 3),
            "hash": test["hash"],
        }

    def is_idor(self, comparison):
        """a response that's 200 + distinct from baseline = likely IDOR"""
        return comparison.get("verdict") == "distinct"


def find_sensitive_patterns(body):
    """scan body for PII-ish markers"""
    patterns = {
        "email": r"[\w.+-]+@[\w-]+\.[\w.-]+",
        "phone": r"\+?\d[\d\s().-]{7,}\d",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
        "api_key": r"(?i)(api[_-]?key|token|secret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})",
        "jwt": r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "aws_key": r"AKIA[0-9A-Z]{16}",
    }
    hits = {}
    for name, pat in patterns.items():
        matches = re.findall(pat, body)
        if matches:
            hits[name] = len(matches)
    return hits