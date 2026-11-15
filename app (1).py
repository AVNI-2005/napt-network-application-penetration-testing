"""app.py  -  Web Application Security Assessment Tool (single file)

HOW TO RUN
    1. Save this file as app.py
    2. Run it:   python app.py      (or press the Run button in VS Code)
    3. Your browser opens at http://127.0.0.1:8000

Everything is in this one file: Python code, HTML pages and CSS.
Only the Python standard library is used (Python 3.8 or newer).

Options:  python app.py --port 9000
          python app.py --allow-private   (test your own localhost sites)

ETHICS: scan only websites you own or have written permission to test.
This tool is passive: it loads one page like a browser and reports on HTTPS,
security headers, cookies and forms. Findings need manual verification.
"""

import threading
import webbrowser

# ==========================================================================
# PART 1: HTML AND CSS (the web pages)
# ==========================================================================

STYLE_CSS = r"""/* Web Application Security Assessment Tool: styles (no external files, works offline). */
:root{--bg:#eef2f6;--surface:#fff;--ink:#102033;--muted:#5a6b7d;--line:#d0d9e2;
--navy:#0d2438;--navy-2:#1b3b5a;--accent:#f59f00;--accent-ink:#1a1200;--radius:10px;
--serif:Georgia,"Iowan Old Style","Palatino Linotype",serif;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;
--mono:ui-monospace,Consolas,"Liberation Mono",monospace}
.sev-high{--sev:#b42318;--sev-bg:#fdecea}.sev-medium{--sev:#b45309;--sev-bg:#fef1e0}
.sev-low{--sev:#8a6a00;--sev-bg:#fff6d6}.sev-info{--sev:#1d5fa8;--sev-bg:#e5f0fb}
.sev-pass{--sev:#1e7b4b;--sev-bg:#e3f4ea}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:1rem/1.55 var(--sans)}
.wrap{max-width:60rem;margin:0 auto;padding:0 1.25rem}
h1,h2,h3{font-family:var(--serif);line-height:1.2;margin:0}
h1{font-size:clamp(1.9rem,5vw,3rem);overflow-wrap:anywhere}
h2{font-size:1.6rem;margin-bottom:.4rem}h3{font-size:1.2rem}
p{margin:0 0 1rem;max-width:68ch}a{color:#0b6e75}
a:focus-visible,button:focus-visible,input:focus-visible,summary:focus-visible{outline:3px solid var(--accent);outline-offset:2px}

/* Hero (both pages) */
.hero{background:var(--navy);color:#fff;padding:3rem 0 3.25rem}
.hero a{color:#ffd8a8}
.hero .back{margin-bottom:1.25rem}.hero .back a{color:#ffd8a8}
.hero h1{margin-bottom:1rem;max-width:18ch}
.hero-result h1{max-width:none;font-size:clamp(1.5rem,4vw,2.3rem)}
.lede{font-size:1.15rem;color:#c5d3e0;max-width:56ch}
.kicker{color:#9fb4c8;margin:0 0 .25rem;font-size:.95rem}
.sub{color:#9fb4c8;margin:.5rem 0 0}

/* Block strip: one block per finding, also used as the brand motif */
.bar{display:flex;gap:3px;height:1.1rem}
.seg{flex:1 1 0;min-width:3px;background:var(--sev);border-radius:2px}
.bar-hero{max-width:26rem;height:.8rem;margin:0 0 1.75rem}

/* Scan form */
.scan-form{background:var(--navy-2);border-radius:var(--radius);padding:1.4rem;margin-top:1.75rem;max-width:44rem}
.scan-form>label{display:block;font-weight:600;margin-bottom:.5rem}
.row{display:flex;gap:.75rem;flex-wrap:wrap}
.scan-form input[type=text]{flex:1 1 16rem;min-width:0;padding:.85rem 1rem;font:inherit;border:0;border-radius:8px;background:#fff;color:var(--ink)}
button{padding:.85rem 1.6rem;font:inherit;font-weight:700;background:var(--accent);color:var(--accent-ink);border:0;border-radius:8px;cursor:pointer}
button:hover{background:#ffb02e}
.consent{display:flex;align-items:flex-start;gap:.6rem;margin-top:1rem;color:#c5d3e0;font-weight:400}
.consent input{margin-top:.3rem;width:1.1rem;height:1.1rem;flex:none}
.error{background:#fdecea;color:#7a1710;border-left:5px solid #b42318;padding:.75rem 1rem;margin:1.25rem 0 0;border-radius:0 8px 8px 0;max-width:44rem}

/* Start page sections */
.section{padding:2.75rem 0 0}.section>.wrap>p{color:var(--muted)}
.detect-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:1rem;margin-top:1.5rem}
.dcard{background:var(--surface);border:1px solid var(--line);border-top:6px solid var(--cat);border-radius:var(--radius);padding:1.25rem}
.cat-https{--cat:#0b7285}.cat-headers{--cat:#5f3dc4}.cat-cookies{--cat:#e67700}.cat-forms{--cat:#2b8a3e}
.dcard h3{margin-bottom:.35rem}.dcard>p{color:var(--muted);font-size:.95rem;margin-bottom:.9rem}
.dcard ul{list-style:none;margin:0;padding:0;display:grid;gap:.55rem}
.dcard li{display:flex;gap:.6rem;align-items:baseline;font-size:.95rem}
.chip{flex:none;min-width:4.4rem;text-align:center;background:var(--sev-bg);color:var(--sev);border-radius:4px;font-size:.8rem;font-weight:700;padding:0 .4rem}
.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-top:1.25rem;counter-reset:s;padding:0;list-style:none}
.steps li{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:1.1rem 1.25rem;counter-increment:s}
.steps li::before{content:counter(s);display:inline-grid;place-items:center;width:1.9rem;height:1.9rem;border-radius:50%;background:var(--navy);color:#fff;font-weight:700;margin-bottom:.5rem}
.steps b{display:block}.steps span{color:var(--muted);font-size:.95rem}
.limits{background:var(--surface);border:1px solid var(--line);border-left:6px solid #b45309;border-radius:var(--radius);padding:1.25rem;margin:2.75rem 0 3rem}
.limits h2{font-size:1.25rem}.limits p{margin:0;color:var(--muted)}

/* Results page */
.headline{display:flex;justify-content:space-between;align-items:center;gap:1.5rem}
.score{text-align:center;flex:none}
.grade{display:grid;place-items:center;width:5.5rem;height:5.5rem;border-radius:50%;border:6px solid var(--g);background:#fff;color:var(--g);font:700 2.6rem/1 var(--serif);margin:0 auto .4rem}
.points{color:#c5d3e0;font-size:.95rem}
.grade-a,.grade-b{--g:#2f9e63}.grade-c{--g:#e0a800}.grade-d{--g:#e8590c}.grade-f{--g:#e03131}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:1.4rem;margin:-1.5rem 0 2rem;position:relative}
.card h2{font-size:1.25rem;margin-bottom:.9rem}.card .bar{margin-bottom:1rem}
.pills{list-style:none;margin:0 0 1.25rem;padding:0;display:flex;flex-wrap:wrap;gap:.5rem}
.pill{background:var(--sev-bg);color:var(--sev);border-radius:999px;padding:.15rem .9rem;font-weight:600;font-size:.92rem}
.meta{display:grid;grid-template-columns:8rem 1fr;gap:.35rem 1rem;margin:0 0 1rem;font-size:.92rem}
.meta dt{color:var(--muted)}.meta dd{margin:0;overflow-wrap:anywhere}
.downloads{display:flex;flex-wrap:wrap;gap:.5rem 1rem;align-items:center;font-size:.95rem}.downloads span{color:var(--muted)}
.group{margin-bottom:2rem}.group h2{font-size:1.35rem;margin-bottom:.75rem}
.finding{background:var(--surface);border:1px solid var(--line);border-left:6px solid var(--sev);border-radius:8px;margin-bottom:.6rem}
.finding summary{display:flex;align-items:baseline;gap:.75rem;padding:.8rem 1rem;cursor:pointer;list-style:none}
.finding summary::-webkit-details-marker{display:none}
.finding summary::after{content:"+";margin-left:auto;color:var(--muted);font-weight:700}
.finding[open] summary::after{content:"\2212"}
.badge{flex:none;min-width:4.4rem;text-align:center;background:var(--sev-bg);color:var(--sev);border-radius:4px;padding:0 .5rem;font-size:.85rem;font-weight:700}
.title{font-weight:600;overflow-wrap:anywhere}
.detail{padding:0 1rem 1rem}.detail p:last-child{margin-bottom:0}
.evidence{margin:0 0 1rem;padding:.6rem .8rem;background:#f1f4f7;border-radius:4px;font:.85rem var(--mono);white-space:pre-wrap;overflow-wrap:anywhere}
.notice{border-top:1px solid var(--line);padding:1rem 0 3rem;color:var(--muted);font-size:.92rem}

@media(max-width:44rem){.detect-grid,.steps{grid-template-columns:1fr}.meta{grid-template-columns:1fr;gap:.1rem}.meta dd{margin-bottom:.6rem}.headline{flex-direction:column;align-items:flex-start}}
@media print{.hero{background:#fff;color:#000}.back,.downloads,.scan-form{display:none}.finding,.card{break-inside:avoid}}
"""

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Web Application Security Assessment Tool</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <header class="hero"><div class="wrap">
    <div class="bar bar-hero" aria-hidden="true"><span class="seg sev-high"></span><span class="seg sev-high"></span><span class="seg sev-medium"></span><span class="seg sev-medium"></span><span class="seg sev-medium"></span><span class="seg sev-low"></span><span class="seg sev-low"></span><span class="seg sev-low"></span><span class="seg sev-info"></span><span class="seg sev-pass"></span><span class="seg sev-pass"></span><span class="seg sev-pass"></span></div>
    <h1>Find the security gaps in your website</h1>
    <p class="lede">Enter an address and get a graded report on HTTPS, security headers, cookies and login forms, with a fix for every problem found. Nothing is attacked or changed.</p>
    {{ error }}
    <form class="scan-form" method="post" action="/scan">
      <label for="url">Website address</label>
      <div class="row">
        <input id="url" name="url" type="text" inputmode="url" autocomplete="off" placeholder="https://example.com" value="{{ url_value }}" required autofocus>
        <button type="submit">Run check</button>
      </div>
      <label class="consent"><input type="checkbox" name="consent" value="yes" required><span>I own this website or have written permission to test it.</span></label>
    </form>
  </div></header>

  <main>
    <section class="section"><div class="wrap">
      <h2>What it detects</h2>
      <p>Each problem is rated High, Medium or Low, so you know what to fix first.</p>
      <div class="detect-grid">
        <article class="dcard cat-https"><h3>HTTPS and encryption</h3><p>Is traffic to your site protected?</p><ul>
          <li><span class="chip sev-high">High</span>Site served over plain HTTP</li>
          <li><span class="chip sev-high">High</span>Invalid or expired certificate</li>
          <li><span class="chip sev-medium">Medium</span>Outdated TLS version</li>
          <li><span class="chip sev-medium">Medium</span>Mixed content: HTTP files on an HTTPS page</li>
          <li><span class="chip sev-low">Low</span>Certificate close to expiring</li></ul></article>
        <article class="dcard cat-headers"><h3>Security headers</h3><p>Browser protections your server should switch on.</p><ul>
          <li><span class="chip sev-medium">Medium</span>No Content-Security-Policy (script injection)</li>
          <li><span class="chip sev-medium">Medium</span>No X-Frame-Options (clickjacking)</li>
          <li><span class="chip sev-medium">Medium</span>No Strict-Transport-Security</li>
          <li><span class="chip sev-low">Low</span>Missing Referrer-Policy, Permissions-Policy, nosniff</li>
          <li><span class="chip sev-low">Low</span>Server and X-Powered-By reveal versions</li></ul></article>
        <article class="dcard cat-cookies"><h3>Cookies</h3><p>Can session cookies be stolen or misused?</p><ul>
          <li><span class="chip sev-medium">Medium</span>Session cookie without Secure</li>
          <li><span class="chip sev-medium">Medium</span>Session cookie without HttpOnly</li>
          <li><span class="chip sev-medium">Medium</span>SameSite=None without Secure</li>
          <li><span class="chip sev-low">Low</span>Cookie without SameSite</li></ul></article>
        <article class="dcard cat-forms"><h3>HTML forms</h3><p>Are logins and forms handled safely?</p><ul>
          <li><span class="chip sev-high">High</span>Password sent over insecure HTTP</li>
          <li><span class="chip sev-high">High</span>Password sent using GET</li>
          <li><span class="chip sev-low">Low</span>POST form without a CSRF token</li>
          <li><span class="chip sev-low">Low</span>Form submits to another domain</li>
          <li><span class="chip sev-info">Info</span>Login forms found for manual review</li></ul></article>
      </div>
    </div></section>

    <section class="section"><div class="wrap">
      <h2>How it works</h2>
      <ol class="steps">
        <li><b>Enter an address</b><span>Confirm you have permission to test it.</span></li>
        <li><b>The page is loaded once</b><span>Like a browser would, with no attack traffic.</span></li>
        <li><b>Read your report</b><span>Grade, findings, fixes, and downloads in HTML, text or JSON.</span></li>
      </ol>
    </div></section>

    <div class="wrap"><section class="limits">
      <h2>What it does not do</h2>
      <p>It is not a full penetration test. It does not exploit anything, sign in, test for SQL injection or XSS, or crawl other pages. Every finding needs manual verification.</p>
    </section></div>
  </main>
</body>
</html>
"""

RESULTS_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security results for {{ target }}</title>
  {{ head_style }}
</head>
<body>
  <header class="hero hero-result"><div class="wrap">
    <p class="back">{{ nav }}</p>
    <div class="headline">
      <div>
        <p class="kicker">Security results for</p>
        <h1>{{ target }}</h1>
        <p class="sub">Scanned {{ scanned_at }} in {{ duration }} seconds. HTTP status {{ status }}.</p>
      </div>
      <div class="score grade-{{ grade_class }}">
        <span class="grade" aria-label="Grade {{ grade }}">{{ grade }}</span>
        <span class="points">{{ score }} out of 100</span>
      </div>
    </div>
  </div></header>

  <main class="wrap">
    <section class="card">
      <h2>Findings at a glance</h2>
      {{ bar }}
      {{ counts }}
      <dl class="meta">
        <dt>Final address</dt><dd>{{ final_url }}</dd>
        <dt>Redirects</dt><dd>{{ chain }}</dd>
        <dt>Page title</dt><dd>{{ page_title }}</dd>
      </dl>
      {{ actions }}
    </section>

    {{ findings }}

    <footer class="notice">
      <p>These results come from passive checks and are indicators, not proof. Verify each one manually before acting on it. Test only websites you own or have written permission to test.</p>
    </footer>
  </main>
</body>
</html>
"""

TEMPLATES = {"index.html": INDEX_HTML, "results.html": RESULTS_HTML}

# ==========================================================================
# PART 2: SECURITY SCANNER
# ==========================================================================

import http.client
import ipaddress
import re
import socket
import ssl
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

USER_AGENT = "WebSecAssess/1.0 (passive security check; educational use)"
TIMEOUT = 10
MAX_BODY = 1_000_000
MAX_REDIRECTS = 5
REDIRECT_CODES = (301, 302, 303, 307, 308)

SEVERITY_ORDER = ["High", "Medium", "Low", "Info", "Pass"]
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITY_ORDER)}
WEIGHTS = {"High": 15, "Medium": 7, "Low": 3, "Info": 0, "Pass": 0}

TOKEN_RE = re.compile(r"csrf|xsrf|token|nonce|authenticity", re.I)
SENSITIVE_COOKIE_RE = re.compile(r"sess|sid|auth|token|jwt|login|account", re.I)


class ScanError(Exception):
    """Raised for problems the user can understand and fix (bad URL, no connection)."""


@dataclass
class Finding:
    category: str
    title: str
    severity: str
    description: str
    recommendation: str = ""
    evidence: str = ""


@dataclass
class FetchResult:
    start_url: str
    final_url: str
    status: int
    headers: dict
    set_cookies: list
    body: str
    chain: list
    tls_error: str = ""


# --------------------------------------------------------------------------
# URL handling and safety
# --------------------------------------------------------------------------

def normalize_url(raw):
    """Turn user input into a clean http(s) URL or raise ScanError."""
    raw = (raw or "").strip()
    if not raw:
        raise ScanError("Enter a website address.")
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise ScanError("Only http:// and https:// addresses are supported.")
    if not parts.hostname:
        raise ScanError("That address has no host name.")
    if parts.username or parts.password:
        raise ScanError("Remove the user name and password from the address.")
    try:
        parts.port  # raises ValueError for an invalid port
    except ValueError:
        raise ScanError("The port number in the address is not valid.")
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def guard_target(url, allow_private):
    """Resolve the host and refuse internal addresses unless allowed.

    This stops the tool being used to probe a private network. Note: it is a
    best-effort check, DNS answers can change between this check and the request.
    """
    host = urlsplit(url).hostname
    if not host:
        raise ScanError("That address has no host name.")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ScanError("Could not find '%s'. Check the spelling and your connection." % host)
    if allow_private:
        return
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global:
            raise ScanError(
                "'%s' points to a private or local address. "
                "Start the server with --allow-private to test your own local sites." % host
            )


# --------------------------------------------------------------------------
# Fetching
# --------------------------------------------------------------------------

def _request(url, verify):
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    if parts.scheme == "https":
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(parts.hostname, parts.port, timeout=TIMEOUT, context=ctx)
    else:
        conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=TIMEOUT)
    try:
        conn.request("GET", path, headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
            "Accept-Encoding": "identity",
            "Connection": "close",
        })
        resp = conn.getresponse()
        raw = resp.read(MAX_BODY)
        charset = resp.headers.get_content_charset() or "utf-8"
        try:
            body = raw.decode(charset, "replace")
        except LookupError:
            body = raw.decode("utf-8", "replace")
        return resp.status, resp.getheaders(), body
    finally:
        conn.close()


def fetch(start_url, allow_private=False):
    """GET the page, following redirects by hand so the redirect chain is visible."""
    url = start_url
    chain = []
    status, headers, body, tls_error = 0, [], "", ""
    for hop in range(MAX_REDIRECTS + 1):
        guard_target(url, allow_private)
        tls_error = ""
        try:
            try:
                status, headers, body = _request(url, True)
            except ssl.SSLCertVerificationError as exc:
                # Remember the problem, then retry without verification so the
                # headers and cookies can still be analysed.
                tls_error = getattr(exc, "verify_message", "") or str(exc)
                status, headers, body = _request(url, False)
        except (OSError, http.client.HTTPException, ValueError) as exc:
            raise ScanError("Could not connect to %s: %s" % (urlsplit(url).netloc, exc))
        chain.append({"url": url, "status": status})
        location = next((v for k, v in headers if k.lower() == "location"), None)
        if status in REDIRECT_CODES and location and hop < MAX_REDIRECTS:
            nxt = urljoin(url, location)
            if urlsplit(nxt).scheme not in ("http", "https"):
                break
            url = nxt
            continue
        break

    hdrs, cookies = {}, []
    for key, value in headers:
        lk = key.lower()
        if lk == "set-cookie":
            cookies.append(value)
        elif lk in hdrs:
            hdrs[lk] += ", " + value
        else:
            hdrs[lk] = value
    return FetchResult(start_url, url, status, hdrs, cookies, body, chain, tls_error)


def get_tls_info(host, port=443):
    """Return TLS version and certificate days-left, or None if it cannot be read."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version()
        not_after = ssl.cert_time_to_seconds(cert["notAfter"])
        return {"version": version, "days_left": int((not_after - time.time()) // 86400)}
    except (OSError, ssl.SSLError, KeyError, ValueError):
        return None


# --------------------------------------------------------------------------
# HTML parsing (forms and resources)
# --------------------------------------------------------------------------

class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.resources = []
        self.title = ""
        self.loose_password = 0
        self._form = None
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "form":
            self._form = {
                "action": a.get("action", ""),
                "method": a.get("method", "get").lower(),
                "inputs": [],
                "has_password": False,
                "has_token": False,
            }
            self.forms.append(self._form)
        elif tag == "input":
            itype = a.get("type", "text").lower()
            name = a.get("name", "")
            if self._form is not None:
                self._form["inputs"].append({"type": itype, "name": name})
                if itype == "password":
                    self._form["has_password"] = True
                if itype == "hidden" and TOKEN_RE.search(name):
                    self._form["has_token"] = True
            elif itype == "password":
                self.loose_password += 1
        elif tag == "title":
            self._in_title = True

        if tag in ("script", "img", "iframe", "source", "audio", "video", "embed") and a.get("src"):
            self.resources.append((tag, a["src"]))
        elif tag == "link" and a.get("href") and "stylesheet" in a.get("rel", "").lower():
            self.resources.append((tag, a["href"]))

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title and len(self.title) < 200:
            self.title += data


def parse_set_cookie(raw):
    parts = [p.strip() for p in raw.split(";")]
    name, _, _value = parts[0].partition("=")
    attrs = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        if key:
            attrs[key.strip().lower()] = value.strip()
    return {"name": name.strip(), "attrs": attrs}


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------

def check_https(start_url, fetched, tls_info, parser):
    cat = "HTTPS"
    out = []
    start_scheme = urlsplit(start_url).scheme
    final = urlsplit(fetched.final_url)

    if final.scheme != "https":
        out.append(Finding(
            cat, "Site is served over plain HTTP", "High",
            "Traffic between visitors and the site is not encrypted, so passwords, "
            "cookies and page content can be read or changed on the network.",
            "Install a TLS certificate (free ones are available from Let's Encrypt), "
            "serve the site over HTTPS and redirect all HTTP requests to it.",
            "Final address: " + fetched.final_url))
        return out

    if start_scheme == "http":
        out.append(Finding(
            cat, "HTTP redirects to HTTPS", "Pass",
            "Visitors who type an http:// address are sent to the secure version.",
            evidence="Redirect chain: " + " -> ".join(
                "%s (%s)" % (c["url"], c["status"]) for c in fetched.chain)))
    else:
        out.append(Finding(cat, "HTTPS is in use", "Pass",
                           "The page was loaded over an encrypted connection."))

    if fetched.tls_error:
        out.append(Finding(
            cat, "Certificate could not be verified", "High",
            "Browsers will warn visitors, and the connection can be intercepted "
            "without detection.",
            "Install a certificate from a trusted authority that matches the domain "
            "name and includes the full certificate chain.",
            fetched.tls_error))

    if tls_info:
        version = tls_info["version"] or "unknown"
        if version in ("SSLv3", "TLSv1", "TLSv1.1"):
            out.append(Finding(
                cat, "Outdated TLS version in use", "Medium",
                "Old TLS versions have known weaknesses.",
                "Disable TLS 1.0 and 1.1 and allow only TLS 1.2 and 1.3.",
                "Negotiated: " + version))
        else:
            out.append(Finding(cat, "Modern TLS version (%s)" % version, "Pass",
                               "The connection negotiated a current TLS version."))
        days = tls_info["days_left"]
        if days < 0:
            out.append(Finding(cat, "Certificate has expired", "High",
                               "Browsers will block or warn about this site.",
                               "Renew the certificate now and automate renewal."))
        elif days < 15:
            out.append(Finding(cat, "Certificate expires in %d days" % days, "Medium",
                               "The certificate is close to expiring.",
                               "Renew it soon and automate renewal."))
        elif days < 30:
            out.append(Finding(cat, "Certificate expires in %d days" % days, "Low",
                               "The certificate will need renewing within the month.",
                               "Check that automatic renewal is working."))
        else:
            out.append(Finding(cat, "Certificate valid for %d more days" % days, "Pass",
                               "The certificate is current."))

    mixed = [u for _tag, u in parser.resources if u.lower().startswith("http://")]
    if mixed:
        out.append(Finding(
            cat, "Mixed content on HTTPS page", "Medium",
            "The secure page loads resources over plain HTTP. Attackers can alter "
            "those resources and browsers may block them.",
            "Load every script, style, image and frame over https://.",
            "\n".join(mixed[:5]) + ("\n..." if len(mixed) > 5 else "")))
    return out


HEADER_RULES = [
    ("Strict-Transport-Security", "Medium",
     "Tells browsers to use HTTPS only, which blocks downgrade and cookie-hijacking attacks.",
     "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on every HTTPS response."),
    ("Content-Security-Policy", "Medium",
     "Limits where scripts and other content can load from, which reduces the damage of cross-site scripting.",
     "Define a Content-Security-Policy that restricts script, style and frame sources. "
     "Start with Content-Security-Policy-Report-Only to avoid breaking the site."),
    ("X-Frame-Options", "Medium",
     "Stops other sites from embedding this page in a frame (clickjacking).",
     "Send 'X-Frame-Options: DENY' or 'SAMEORIGIN', or use the CSP frame-ancestors directive."),
    ("X-Content-Type-Options", "Low",
     "Stops browsers from guessing content types, which can turn uploaded files into scripts.",
     "Send 'X-Content-Type-Options: nosniff'."),
    ("Referrer-Policy", "Low",
     "Controls how much of the page address is shared with other sites.",
     "Send 'Referrer-Policy: strict-origin-when-cross-origin' or stricter."),
    ("Permissions-Policy", "Low",
     "Restricts browser features such as camera, microphone and location.",
     "Send a Permissions-Policy header that turns off features the site does not use."),
]


def check_headers(fetched):
    cat = "Security headers"
    out = []
    h = fetched.headers
    is_https = urlsplit(fetched.final_url).scheme == "https"
    csp = h.get("content-security-policy", "")

    for name, severity, why, fix in HEADER_RULES:
        key = name.lower()
        present = key in h
        if key == "strict-transport-security" and not is_https:
            continue  # only meaningful over HTTPS
        if key == "x-frame-options" and not present and "frame-ancestors" in csp.lower():
            out.append(Finding(cat, "Framing is controlled by CSP frame-ancestors", "Pass",
                               "The Content-Security-Policy header covers clickjacking protection.",
                               evidence="Content-Security-Policy: " + csp[:200]))
            continue
        if not present:
            out.append(Finding(cat, "Missing " + name, severity, why, fix))
            continue
        value = h[key]
        if key == "x-content-type-options" and value.strip().lower() != "nosniff":
            out.append(Finding(cat, "X-Content-Type-Options has an unexpected value", "Low",
                               why, fix, "Value: " + value))
        elif key == "strict-transport-security":
            match = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
            if not match or int(match.group(1)) < 15552000:
                out.append(Finding(cat, "Strict-Transport-Security max-age is short", "Low",
                                   "A short lifetime leaves visitors unprotected between visits.",
                                   "Use a max-age of at least 15552000 seconds (180 days); 31536000 is common.",
                                   "Value: " + value))
            else:
                out.append(Finding(cat, "Strict-Transport-Security is set", "Pass", why,
                                   evidence="Value: " + value))
        else:
            out.append(Finding(cat, name + " is set", "Pass", why,
                               evidence="Value: " + value[:200]))

    if "unsafe-inline" in csp.lower() or "unsafe-eval" in csp.lower():
        out.append(Finding(
            cat, "Content-Security-Policy allows unsafe sources", "Low",
            "'unsafe-inline' or 'unsafe-eval' weakens the protection CSP gives against "
            "cross-site scripting. (Heuristic: check which directive contains it.)",
            "Move inline scripts to files, use nonces or hashes, and remove 'unsafe-*' keywords.",
            "Content-Security-Policy: " + csp[:200]))

    server = h.get("server", "")
    if re.search(r"\d", server):
        out.append(Finding(cat, "Server header reveals version", "Low",
                           "Exact software versions help attackers look up known flaws.",
                           "Configure the web server to hide its version number.",
                           "Server: " + server))
    if "x-powered-by" in h:
        out.append(Finding(cat, "X-Powered-By header reveals technology", "Low",
                           "This header tells attackers which framework the site runs on.",
                           "Remove the X-Powered-By header.",
                           "X-Powered-By: " + h["x-powered-by"]))
    if h.get("access-control-allow-origin", "").strip() == "*":
        out.append(Finding(cat, "CORS allows any origin", "Info",
                           "Any website can read this response from a visitor's browser. "
                           "That is fine for public data and risky for private data.",
                           "Confirm this is intended, otherwise list specific trusted origins.",
                           "Access-Control-Allow-Origin: *"))
    return out


def check_cookies(set_cookies, is_https):
    cat = "Cookies"
    if not set_cookies:
        return [Finding(cat, "No cookies set by this page", "Info",
                        "The page did not send any cookies. Cookies set after login or by "
                        "other pages are not covered by this check.")]
    out = []
    for raw in set_cookies:
        parsed = parse_set_cookie(raw)
        name = parsed["name"] or "(unnamed)"
        attrs = parsed["attrs"]
        sensitive = bool(SENSITIVE_COOKIE_RE.search(name))
        base = "Medium" if sensitive else "Low"
        missing, severity = [], "Pass"

        def bump(level):
            nonlocal severity
            if SEVERITY_RANK[level] < SEVERITY_RANK[severity]:
                severity = level

        if is_https and "secure" not in attrs:
            missing.append("Secure")
            bump(base)
        if "httponly" not in attrs:
            missing.append("HttpOnly")
            bump(base)
        if "samesite" not in attrs:
            missing.append("SameSite")
            bump("Low")
        if attrs.get("samesite", "").lower() == "none" and "secure" not in attrs:
            if "Secure" not in missing:
                missing.append("Secure")
            bump("Medium")

        # Hide the cookie value so reports never contain a live session token.
        shown = "; ".join(["%s=[hidden]" % name] + [p.strip() for p in raw.split(";")[1:]])
        if missing:
            out.append(Finding(
                cat, "Cookie '%s' is missing %s" % (name, ", ".join(missing)), severity,
                "Secure keeps the cookie off plain HTTP, HttpOnly hides it from JavaScript "
                "(limiting theft through XSS) and SameSite limits cross-site requests (CSRF)."
                + (" The name suggests a session or login cookie." if sensitive else ""),
                "Add the missing attributes, e.g. 'Set-Cookie: %s=...; Secure; HttpOnly; SameSite=Lax'." % name,
                "Set-Cookie: " + shown))
        else:
            out.append(Finding(cat, "Cookie '%s' has the recommended attributes" % name, "Pass",
                               "Secure, HttpOnly and SameSite are all set correctly.",
                               evidence="Set-Cookie: " + shown))
    return out


def check_forms(fetched, parser):
    cat = "Forms"
    out = []
    page_url = fetched.final_url
    page_host = urlsplit(page_url).hostname

    if parser.loose_password:
        out.append(Finding(cat, "Password field found outside a form", "Info",
                           "The page has a password input that is not inside a <form>, "
                           "so it is probably handled by JavaScript.",
                           "Verify manually that the credentials are sent over HTTPS."))
    if not parser.forms:
        if not parser.loose_password:
            out.append(Finding(cat, "No HTML forms found", "Info",
                               "The page has no forms. Other pages on the site may."))
        return out

    for n, form in enumerate(parser.forms, start=1):
        action = urljoin(page_url, form["action"]) if form["action"] else page_url
        action_parts = urlsplit(action)
        label = "Form %d" % n
        detail = "method=%s, action=%s" % (form["method"].upper(), action)

        if form["has_password"]:
            out.append(Finding(cat, "%s: password field found" % label, "Info",
                               "This looks like a login or sign-up form. Review it manually.",
                               evidence=detail))
            if action_parts.scheme != "https":
                out.append(Finding(
                    cat, "%s: password sent over insecure HTTP" % label, "High",
                    "The password is submitted without encryption and can be read on the network.",
                    "Serve the page and the form action over HTTPS only.", detail))
            if form["method"] != "post":
                out.append(Finding(
                    cat, "%s: password sent using GET" % label, "High",
                    "GET puts form values in the address, where they end up in browser history "
                    "and server logs.",
                    "Use method=\"post\" for any form with a password.", detail))

        if form["method"] == "post" and not form["has_token"]:
            out.append(Finding(
                cat, "%s: no anti-CSRF token detected" % label, "Low",
                "A POST form without a hidden token field may be open to cross-site request "
                "forgery. (Heuristic: the site may protect itself in other ways.)",
                "Add a per-session CSRF token to state-changing forms and verify it on the server.",
                detail))

        if action_parts.hostname and action_parts.hostname != page_host:
            out.append(Finding(
                cat, "%s: submits to another domain" % label, "Low",
                "Data from this form is sent to a different site than the one being viewed.",
                "Confirm the destination is trusted and expected.", detail))
    return out


# --------------------------------------------------------------------------
# Scoring and orchestration
# --------------------------------------------------------------------------

def grade_for(score):
    for limit, grade in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
        if score >= limit:
            return grade
    return "F"


def summarize(findings):
    counts = {name: 0 for name in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] += 1
    score = max(0, 100 - sum(WEIGHTS[f["severity"]] for f in findings))
    return counts, score, grade_for(score)


def run_scan(raw_url, allow_private=False):
    """Run every check and return a plain dict that is easy to store and render."""
    started = time.time()
    target = normalize_url(raw_url)
    fetched = fetch(target, allow_private)
    final = urlsplit(fetched.final_url)
    is_https = final.scheme == "https"

    tls_info = None
    if is_https and not fetched.tls_error:
        tls_info = get_tls_info(final.hostname, final.port or 443)

    parser = PageParser()
    ctype = fetched.headers.get("content-type", "").lower()
    if "html" in ctype or not ctype:
        try:
            parser.feed(fetched.body)
            parser.close()
        except Exception:  # malformed HTML must never stop the scan
            pass

    found = []
    found += check_https(target, fetched, tls_info, parser)
    found += check_headers(fetched)
    found += check_cookies(fetched.set_cookies, is_https)
    found += check_forms(fetched, parser)
    findings = [asdict(f) for f in found]
    counts, score, grade = summarize(findings)

    return {
        "target": target,
        "final_url": fetched.final_url,
        "status": fetched.status,
        "page_title": parser.title.strip(),
        "redirect_chain": fetched.chain,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "duration": round(time.time() - started, 2),
        "findings": findings,
        "counts": counts,
        "score": score,
        "grade": grade,
    }


# ==========================================================================
# PART 3: DASHBOARD AND REPORTS
# ==========================================================================

import json
import re
from html import escape
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"

SECTIONS = ["HTTPS", "Security headers", "Cookies", "Forms"]
ID_RE = re.compile(r"^[0-9a-f]{32}$")


def esc(value):
    return escape(str(value), quote=True)


def render(template_name, **values):
    """Fill {{ name }} placeholders. Callers pass already-escaped HTML."""
    text = TEMPLATES[template_name]
    return re.sub(r"\{\{\s*(\w+)\s*\}\}", lambda m: str(values.get(m.group(1), "")), text)


# --------------------------------------------------------------------------
# HTML fragments
# --------------------------------------------------------------------------

def severity_bar_html(findings):
    ordered = sorted(findings, key=lambda f: SEVERITY_ORDER.index(f["severity"]))
    segs = "".join(
        '<span class="seg sev-%s" title="%s"></span>'
        % (f["severity"].lower(), esc("%s: %s" % (f["severity"], f["title"])))
        for f in ordered
    )
    return '<div class="bar" role="img" aria-label="One block per finding, coloured by severity">%s</div>' % segs


def counts_html(counts):
    items = "".join(
        '<li class="pill sev-%s"><b>%d</b> %s</li>' % (name.lower(), counts[name], name)
        for name in SEVERITY_ORDER
    )
    return '<ul class="pills">%s</ul>' % items


def findings_html(findings):
    blocks = []
    for cat in SECTIONS:
        items = [f for f in findings if f["category"] == cat]
        if not items:
            continue
        items.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))
        parts = ['<section class="group"><h2>%s</h2>' % esc(cat)]
        for f in items:
            sev = f["severity"]
            open_attr = " open" if sev in ("High", "Medium") else ""
            body = "<p>%s</p>" % esc(f["description"])
            if f["evidence"]:
                body += '<pre class="evidence">%s</pre>' % esc(f["evidence"])
            if f["recommendation"]:
                body += '<p class="fix"><strong>Recommended fix.</strong> %s</p>' % esc(f["recommendation"])
            parts.append(
                '<details class="finding sev-%s"%s><summary>'
                '<span class="badge">%s</span><span class="title">%s</span></summary>'
                '<div class="detail">%s</div></details>'
                % (sev.lower(), open_attr, esc(sev), esc(f["title"]), body)
            )
        parts.append("</section>")
        blocks.append("".join(parts))
    return "".join(blocks)


# --------------------------------------------------------------------------
# Pages and reports
# --------------------------------------------------------------------------

def build_results_page(result, scan_id=None, standalone=False):
    if standalone:
        css = STYLE_CSS
        head_style = "<style>%s</style>" % css
        nav, actions = "", ""
    else:
        head_style = '<link rel="stylesheet" href="/static/style.css">'
        nav = '<a href="/">Check another site</a>'
        actions = (
            '<nav class="downloads" aria-label="Download report">'
            '<span>Download report:</span>'
            '<a href="/download/%(i)s.html">HTML</a>'
            '<a href="/download/%(i)s.txt">Text</a>'
            '<a href="/download/%(i)s.json">JSON</a></nav>' % {"i": scan_id}
        ) if scan_id else ""

    chain = " then ".join("%s (%s)" % (c["url"], c["status"]) for c in result["redirect_chain"])
    return render(
        "results.html",
        head_style=head_style,
        nav=nav,
        actions=actions,
        target=esc(result["target"]),
        final_url=esc(result["final_url"]),
        chain=esc(chain),
        status=esc(result["status"]),
        scanned_at=esc(result["scanned_at"]),
        duration=esc(result["duration"]),
        page_title=esc(result["page_title"] or "(no title)"),
        score=esc(result["score"]),
        grade=esc(result["grade"]),
        grade_class=esc(result["grade"].lower()),
        bar=severity_bar_html(result["findings"]),
        counts=counts_html(result["counts"]),
        findings=findings_html(result["findings"]),
    )


def build_text_report(result):
    line = "=" * 70
    out = [
        line,
        "WEB SECURITY ASSESSMENT REPORT",
        line,
        "Target        : " + result["target"],
        "Final address : " + result["final_url"],
        "HTTP status   : %s" % result["status"],
        "Scanned       : " + result["scanned_at"],
        "Score / grade : %s / 100  (%s)" % (result["score"], result["grade"]),
        "Findings      : " + ", ".join("%s %d" % (k, result["counts"][k]) for k in SEVERITY_ORDER),
        "",
    ]
    for cat in SECTIONS:
        items = [f for f in result["findings"] if f["category"] == cat]
        if not items:
            continue
        items.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))
        out += ["-" * 70, cat.upper(), "-" * 70]
        for f in items:
            out.append("[%s] %s" % (f["severity"].upper(), f["title"]))
            out.append("  What: " + f["description"])
            if f["evidence"]:
                out.append("  Evidence: " + f["evidence"].replace("\n", "\n            "))
            if f["recommendation"]:
                out.append("  Fix: " + f["recommendation"])
            out.append("")
    out += [
        line,
        "Findings are indicators from passive checks and need manual verification.",
        "Test only websites you own or have written permission to test.",
        line,
    ]
    return "\n".join(out)


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------

def save_report(scan_id, result):
    REPORT_DIR.mkdir(exist_ok=True)
    (REPORT_DIR / (scan_id + ".json")).write_text(json.dumps(result, indent=2), encoding="utf-8")
    (REPORT_DIR / (scan_id + ".txt")).write_text(build_text_report(result), encoding="utf-8")
    (REPORT_DIR / (scan_id + ".html")).write_text(
        build_results_page(result, standalone=True), encoding="utf-8")


def load_result(scan_id):
    if not ID_RE.match(scan_id):
        return None
    path = REPORT_DIR / (scan_id + ".json")
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


# ==========================================================================
# PART 4: WEB SERVER
# ==========================================================================

import argparse
import re
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

DOWNLOAD_TYPES = {
    "html": "text/html; charset=utf-8",
    "txt": "text/plain; charset=utf-8",
    "json": "application/json; charset=utf-8",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "WebSecAssess/1.0"
    allow_private = False

    # -- helpers ----------------------------------------------------------
    def _send(self, status, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _index(self, error="", url_value="", status=200):
        error_html = '<p class="error" role="alert">%s</p>' % esc(error) if error else ""
        page = render("index.html", error=error_html, url_value=esc(url_value))
        self._send(status, page)

    def _not_found(self):
        self._send(404, "<!DOCTYPE html><title>Not found</title><p>Page not found. <a href=\"/\">Back to start</a></p>")

    # -- routes -----------------------------------------------------------
    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            return self._index()
        if path == "/static/style.css":
            css = STYLE_CSS.encode("utf-8")
            return self._send(200, css, "text/css; charset=utf-8")

        match = re.fullmatch(r"/results/([0-9a-f]{32})", path)
        if match:
            result = load_result(match.group(1))
            if result is None:
                return self._not_found()
            return self._send(200, build_results_page(result, scan_id=match.group(1)))

        match = re.fullmatch(r"/download/([0-9a-f]{32})\.(html|txt|json)", path)
        if match:
            scan_id, ext = match.groups()
            file = REPORT_DIR / ("%s.%s" % (scan_id, ext))
            if not file.is_file():
                return self._not_found()
            return self._send(200, file.read_bytes(), DOWNLOAD_TYPES[ext], {
                "Content-Disposition": 'attachment; filename="security-report-%s.%s"' % (scan_id[:8], ext)})
        self._not_found()

    do_HEAD = do_GET

    def do_POST(self):
        if urlsplit(self.path).path != "/scan":
            return self._not_found()
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 4096:
            return self._index("The request was empty or too large.", status=400)

        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        url = form.get("url", [""])[0].strip()
        if form.get("consent", [""])[0] != "yes":
            return self._index("Confirm that you own the site or have permission to test it.", url, 400)

        try:
            result = run_scan(url, allow_private=self.allow_private)
        except ScanError as exc:
            return self._index(str(exc), url, 400)
        except Exception as exc:  # never show a stack trace to the browser
            self.log_error("scan failed: %r", exc)
            return self._index("The check failed unexpectedly. Try again or use a different address.", url, 500)

        scan_id = uuid.uuid4().hex
        save_report(scan_id, result)
        self._send(303, "", extra={"Location": "/results/" + scan_id})


def make_server(host="127.0.0.1", port=8000):
    return ThreadingHTTPServer((host, port), Handler)


def main():
    parser = argparse.ArgumentParser(description="Passive web security assessment tool")
    parser.add_argument("--host", default="127.0.0.1", help="address to listen on (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="port to listen on (default 8000)")
    parser.add_argument("--allow-private", action="store_true",
                        help="allow scanning localhost and private network addresses")
    parser.add_argument("--no-browser", action="store_true", help="do not open the browser automatically")
    args = parser.parse_args()

    Handler.allow_private = args.allow_private
    server = None
    for port in range(args.port, args.port + 10):  # use the next port if one is busy
        try:
            server = make_server(args.host, port)
            break
        except OSError:
            continue
    if server is None:
        print("Could not find a free port. Close other programs or use --port.")
        return
    url = "http://%s:%d" % (args.host, server.server_address[1])
    print("Web Application Security Assessment Tool")
    print("Running at %s  (press Ctrl+C to stop)" % url)
    print("Test only websites you own or have written permission to test.")
    if not args.no_browser:
        threading.Timer(1.0, webbrowser.open, [url]).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
