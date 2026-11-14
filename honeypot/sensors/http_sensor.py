"""Low-interaction HTTP sensor with bait pages.

Requests are parsed by hand (not http.server) so malformed and hostile requests are still
recorded instead of being rejected before logging. One request per connection. Header and body
sizes are capped. The response is chosen from static templates by path; nothing in the request
is executed, included or fetched. Exploit classification happens at the collector so rule updates
apply to old data too.
"""

from __future__ import annotations

import base64
import socket
import time
import uuid
from urllib.parse import parse_qs, urlsplit

from .base import Sensor

MAX_HEADER_BYTES = 16 * 1024
MAX_BODY_READ = 64 * 1024
MAX_BODY_STORED = 8 * 1024
SERVER = "Apache/2.4.41 (Ubuntu)"

USER_FIELDS = ("log", "user", "username", "login", "pma_username", "email", "usr", "name", "admin_name")
PASS_FIELDS = ("pwd", "pass", "password", "pma_password", "passwd", "psw", "admin_pwd")

LOGIN_FORM = """<!DOCTYPE html><html><head><title>{title}</title></head><body style="font-family:sans-serif">
<h2>{title}</h2><form method="post" action="{action}">
<label>Username <input name="{ufield}"></label><br><label>Password <input type="password" name="{pfield}"></label><br>
<button type="submit">Log in</button></form>{error}</body></html>"""

# Honeytokens: fake secrets that look worth stealing. The AWS pair is the public example from
# AWS documentation, so it can never be a live credential.
FAKE_ENV = """APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:Q2hhbmdlTWVQbGVhc2VUaGlzSXNOb3RBUmVhbEtleQ==
APP_DEBUG=false
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_DATABASE=shop_prod
DB_USERNAME=shop
DB_PASSWORD=Sh0p!2024prod
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
MAIL_HOST=smtp.mailgun.org
"""
FAKE_GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
[remote "origin"]
\turl = git@git.internal.example:web/shop.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
\tremote = origin
\tmerge = refs/heads/master
"""
NOT_FOUND = ("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head><title>404 Not Found</title></head><body>"
             "<h1>Not Found</h1><p>The requested URL was not found on this server.</p><hr>"
             "<address>Apache/2.4.41 (Ubuntu) Server at localhost Port 80</address></body></html>")
INDEX = ("<!DOCTYPE html><html><head><title>Apache2 Ubuntu Default Page: It works</title></head><body>"
         "<h1>It works!</h1><p>This is the default welcome page used to test the correct operation of the Apache2 server.</p>"
         "</body></html>")


def parse_request(raw_head: bytes) -> tuple[str, str, str, dict]:
    lines = raw_head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    method = parts[0][:16] if parts else ""
    path = parts[1] if len(parts) > 1 else ""
    version = parts[2] if len(parts) > 2 else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line and len(headers) < 64:
            k, v = line.split(":", 1)
            k = k.strip()[:128]
            headers[k] = (headers[k] + ", " if k in headers else "") + v.strip()[:2048]
    return method, path[:4096], version[:16], headers


def extract_credentials(path: str, headers: dict, body: str) -> tuple[str | None, str | None, str]:
    """Pull credentials from Basic auth or login form fields."""
    auth = next((v for k, v in headers.items() if k.lower() == "authorization"), "")
    if auth.lower().startswith("basic "):
        try:
            user, _, pw = base64.b64decode(auth[6:].strip()).decode("utf-8", "replace").partition(":")
            return user, pw, "basic"
        except ValueError:
            pass
    fields = parse_qs(body or "", keep_blank_values=True)
    fields.update(parse_qs(urlsplit(path).query, keep_blank_values=True))
    lower = {k.lower(): v[0] for k, v in fields.items() if v}
    user = next((lower[f] for f in USER_FIELDS if f in lower), None)
    pw = next((lower[f] for f in PASS_FIELDS if f in lower), None)
    if user is not None or pw is not None:
        return user, pw, "form"
    return None, None, ""


def choose_response(method: str, path: str, had_creds: bool) -> tuple[int, str, str]:
    """(status, content_type, body) for a request path. Static bait only."""
    p = urlsplit(path).path.lower()
    err = "<p style='color:red'>Invalid username or password.</p>" if had_creds else ""
    if p.endswith("/.env"):
        return 200, "text/plain", FAKE_ENV
    if p.endswith("/.git/config"):
        return 200, "text/plain", FAKE_GIT_CONFIG
    if "wp-login.php" in p or p.startswith("/wp-admin"):
        return 200, "text/html", LOGIN_FORM.format(title="Log In &lsaquo; Shop &mdash; WordPress", action="/wp-login.php",
                                                   ufield="log", pfield="pwd", error=err)
    if "phpmyadmin" in p or p.startswith(("/pma", "/myadmin")):
        return 200, "text/html", LOGIN_FORM.format(title="phpMyAdmin", action="/phpmyadmin/index.php",
                                                   ufield="pma_username", pfield="pma_password", error=err)
    if p.startswith(("/admin", "/login", "/cgi-bin/luci", "/boaform", "/hnap1", "/userrpm", "/webfig", "/manager/html")):
        return 200, "text/html", LOGIN_FORM.format(title="Wireless Router Management", action="/login.cgi",
                                                   ufield="username", pfield="password", error=err)
    if p.startswith("/cgi-bin/") or p in ("/shell", "/gponform/diag_form", "/ctrlt/deviceupgrade_1"):
        return 200, "text/html", "<html><body>OK</body></html>"
    if p.endswith(("server-status", "phpinfo.php", "info.php")):
        return 403, "text/html", "<html><body><h1>Forbidden</h1></body></html>"
    if p in ("/", "/index.html", "/index.php"):
        return 200, "text/html", INDEX
    if p == "/robots.txt":
        return 200, "text/plain", "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n"
    return 404, "text/html", NOT_FOUND


class HTTPSensor(Sensor):
    name = "http"

    def __init__(self, cfg, shipper, port=None):
        super().__init__(cfg, shipper, port if port is not None else cfg.http_port)

    def _read_head(self, sock: socket.socket) -> tuple[bytes, bytes]:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > MAX_HEADER_BYTES:
                break
        head, _, rest = data.partition(b"\r\n\r\n")
        return head[:MAX_HEADER_BYTES], rest

    def handle(self, sock: socket.socket, src_ip: str, src_port: int) -> None:
        sock.settimeout(10)
        session_id = uuid.uuid4().hex[:16]
        head, body = self._read_head(sock)
        if not head:
            self.emit("connect", src_ip, src_port, session_id, data={"note": "no request sent"})
            return
        method, path, version, headers = parse_request(head)
        length = next((v for k, v in headers.items() if k.lower() == "content-length"), "0")
        want = min(int(length) if length.isdigit() else 0, MAX_BODY_READ)
        try:
            while len(body) < want:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                body += chunk
        except (socket.timeout, TimeoutError):
            pass
        body_text = body[:MAX_BODY_STORED].decode("utf-8", "replace")
        user, pw, cred_kind = extract_credentials(path, headers, body_text)
        self.emit("http_request", src_ip, src_port, session_id, method=method, path=path,
                  data={"version": version, "headers": headers, "body": body_text, "body_len": len(body)})
        if cred_kind:
            self.emit("auth", src_ip, src_port, session_id, username=user, password=pw,
                      auth_method=f"http-{cred_kind}", success=False, data={"path": path[:512]})
        status, ctype, content = choose_response(method, path, bool(cred_kind))
        payload = content.encode()
        reason = {200: "OK", 403: "Forbidden", 404: "Not Found"}[status]
        resp = (f"HTTP/1.1 {status} {reason}\r\nDate: {time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())}\r\n"
                f"Server: {SERVER}\r\nContent-Type: {ctype}; charset=UTF-8\r\nContent-Length: {len(payload)}\r\n"
                f"Connection: close\r\n\r\n").encode()
        sock.sendall(resp + (b"" if method == "HEAD" else payload))
