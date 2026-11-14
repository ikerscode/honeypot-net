"""Signature-based classification of HTTP requests seen by the HTTP sensor.

Each rule is a regex matched against the URL-decoded request (request line, headers, body).
Rules carry a category, a severity and, where a public CVE exists for the exploited flaw, its
CVE id. The rules describe what an attacker is *trying*; the sensor never runs any of it.

Scanner identification uses the User-Agent (and a couple of header quirks) to tell known
internet-wide research scanners and common tools apart from unidentified traffic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote_plus

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    category: str
    severity: str
    pattern: re.Pattern
    cve: tuple[str, ...] = ()


def R(rule_id, name, category, severity, pattern, *cves):
    return Rule(rule_id, name, category, severity, re.compile(pattern, re.I | re.S), tuple(cves))


# Order matters only for readability; every matching rule is reported.
RULES: list[Rule] = [
    # ---- CVE-specific web application exploits ----
    R("log4shell", "Log4Shell JNDI lookup", "log4shell", "critical",
      r"\$\{jndi:(?:ldaps?|rmi|dns|iiop|corba|nds|http)", "CVE-2021-44228"),
    R("shellshock", "Shellshock bash function definition", "shellshock", "critical", r"\(\)\s*\{\s*:?\s*;?\s*\}\s*;", "CVE-2014-6271"),
    R("struts-ognl", "Apache Struts2 OGNL in Content-Type", "ognl_injection", "critical",
      r"content-type:[^\n]*(?:%\{|\$\{)[^\n]*(?:#_memberAccess|ognl|@java\.lang)", "CVE-2017-5638"),
    R("confluence-ognl", "Confluence OGNL injection in URI", "ognl_injection", "critical",
      r"^\S+ /[^ \n]*\$\{[^ \n]*(?:@java\.lang\.Runtime|getRuntime|ognl|#a=)", "CVE-2022-26134"),
    R("spring4shell", "Spring4Shell classLoader binding", "spring4shell", "critical",
      r"class\.module\.classLoader", "CVE-2022-22965"),
    R("spring-cloud-function", "Spring Cloud Function routing expression", "spring4shell", "critical",
      r"spring\.cloud\.function\.routing-expression", "CVE-2022-22963"),
    R("spring-gateway", "Spring Cloud Gateway actuator route injection", "spring4shell", "high",
      r"/actuator/gateway/routes", "CVE-2022-22947"),
    R("thinkphp-rce", "ThinkPHP 5.x invokefunction RCE", "php_rce", "critical",
      r"(?:invokefunction|think\\+app|\\think\\|s=/index/\\think)", "CVE-2018-20062", "CVE-2019-9082"),
    R("phpunit-eval", "PHPUnit eval-stdin.php RCE", "php_rce", "critical", r"eval-stdin\.php", "CVE-2017-9841"),
    R("php-cgi-arg", "PHP-CGI argument injection", "php_rce", "critical",
      r"\?(?:-|%ad|\xad)d[+ ]*(?:allow_url_include|auto_prepend_file)", "CVE-2012-1823", "CVE-2024-4577"),
    R("laravel-ignition", "Laravel Ignition execute-solution", "php_rce", "critical", r"/_ignition/execute-solution", "CVE-2021-3129"),
    R("vbulletin-widget", "vBulletin widgetConfig RCE", "php_rce", "critical", r"widgetConfig\[code\]", "CVE-2019-16759"),
    R("drupalgeddon2", "Drupalgeddon2 form API RCE", "php_rce", "critical", r"element_parents=account/mail/#value", "CVE-2018-7600"),
    R("apache-traversal", "Apache 2.4.49/50 path traversal", "path_traversal", "critical",
      r"/(?:cgi-bin|icons)/(?:\.%2e|%2e\.|\.\.?%%32%65|%%32%65)", "CVE-2021-41773", "CVE-2021-42013"),
    R("citrix-traversal", "Citrix ADC /vpns/ traversal", "path_traversal", "critical", r"/vpn/\.\./vpns/", "CVE-2019-19781"),
    R("fortinet-traversal", "FortiOS SSL-VPN fgt_lang traversal", "path_traversal", "critical",
      r"/remote/fgt_lang\?lang=/\.\.", "CVE-2018-13379"),
    R("pulse-traversal", "Pulse Secure arbitrary file read", "path_traversal", "critical",
      r"/dana-na/\.\./dana/html5acc", "CVE-2019-11510"),
    R("ivanti-cs", "Ivanti Connect Secure auth bypass", "path_traversal", "critical",
      r"/api/v1/(?:totp/user-backup-code|cav/client)/\.\./", "CVE-2023-46805", "CVE-2024-21887"),
    R("f5-bigip", "F5 BIG-IP iControl REST bash", "command_injection", "critical", r"/mgmt/tm/util/bash", "CVE-2022-1388"),
    R("proxyshell", "Exchange ProxyShell autodiscover", "path_traversal", "critical", r"/autodiscover/autodiscover\.json\?@", "CVE-2021-34473"),
    # ---- IoT / router exploits used by Mirai-family botnets ----
    R("gpon", "GPON router auth bypass + diag injection", "iot_router_exploit", "critical",
      r"/GponForm/diag_Form", "CVE-2018-10561", "CVE-2018-10562"),
    R("huawei-hg532", "Huawei HG532 DeviceUpgrade injection", "iot_router_exploit", "critical",
      r"/ctrlt/DeviceUpgrade_1", "CVE-2017-17215"),
    R("realtek-sdk", "Realtek SDK miniigd UPnP injection", "iot_router_exploit", "critical",
      r"(?:/picsdesc\.xml|NewInternalClient[^<]*[`$;])", "CVE-2014-8361"),
    R("dlink-hnap", "D-Link HNAP SOAPAction injection", "iot_router_exploit", "critical",
      r"/HNAP1/?[^\n]*\n(?:.*\n)*?soapaction:[^\n]*(?:`|\$\(|;)", "CVE-2015-2051"),
    R("dlink-login-cli", "D-Link DSL login.cgi cli injection", "iot_router_exploit", "critical",
      r"/login\.cgi\?cli=", "CVE-2016-20017"),
    R("tplink-ax21", "TP-Link Archer AX21 locale injection", "iot_router_exploit", "critical",
      r"/cgi-bin/luci/;stok=/locale", "CVE-2023-1389"),
    R("hikvision", "Hikvision webLanguage command injection", "iot_router_exploit", "critical",
      r"/SDK/webLanguage", "CVE-2021-36260"),
    R("zyxel-viewlog", "Zyxel ViewLog.asp remote_host injection", "iot_router_exploit", "critical",
      r"/cgi-bin/ViewLog\.asp", "CVE-2017-18368"),
    R("netgear-setup", "Netgear DGN setup.cgi syscmd", "iot_router_exploit", "critical", r"setup\.cgi\?next_file=netgear\.cfg&todo=syscmd"),
    R("jaws-dvr", "MVPower/JAWS DVR /shell command", "iot_router_exploit", "critical", r"^\S+ /shell\?"),
    R("linksys-moon", "Linksys tmUnblock.cgi (TheMoon)", "iot_router_exploit", "high", r"/tmUnblock\.cgi"),
    # ---- Generic attack classes ----
    R("traversal-generic", "Directory traversal", "path_traversal", "high",
      r"(?:\.\./|\.\.\\|%2e%2e[/%]|\.\.%2f)[^\n]*(?:etc/passwd|win\.ini|boot\.ini|proc/self)|/etc/passwd"),
    R("sqli-union", "SQL injection (UNION/boolean)", "sqli", "high",
      r"(?:union\s+(?:all\s+)?select|'\s*or\s*'?\d+'?\s*=\s*'?\d|\bor\s+1\s*=\s*1\b|information_schema|"
      r"\bsleep\s*\(\s*\d+\s*\)|benchmark\s*\(|extractvalue\s*\(|waitfor\s+delay)"),
    R("cmd-injection", "OS command injection", "command_injection", "high",
      r"(?:[;|&`]\s*|\$\()\s*(?:wget|curl|tftp|ftpget|busybox|chmod|sh\b|bash\b|cd\s+/tmp|nc\s|rm\s+-rf|id\b|uname|cat\s+/etc)"),
    R("php-code", "PHP code / wrapper injection", "php_rce", "high",
      r"(?:<\?php|php://input|php://filter|allow_url_include|base64_decode\s*\(|\bsystem\s*\(|\beval\s*\(|"
      r"call_user_func_array|shell_exec\s*\(|passthru\s*\()"),
    R("xss", "Cross-site scripting probe", "xss", "medium", r"(?:<script|onerror\s*=|javascript:alert)"),
    R("webshell", "Known webshell path", "webshell_probe", "high",
      r"^\S+ /[^ ]*(?:shell|cmd|wso|alfa|c99|r57|up|bypass|xleet)[0-9]*\.php\b"),
    R("info-env", "Secrets file probe (.env, .git, cloud creds)", "info_disclosure", "medium",
      r"^\S+ /[^ ]*(?:\.env\b|\.git/(?:config|HEAD)|\.aws/credentials|\.ssh/id_rsa|wp-config\.php\.(?:bak|old|save)|"
      r"\.DS_Store|config\.json|\.svn/entries|backup\.(?:sql|zip|tar\.gz))"),
    R("info-server", "Server info / debug endpoint probe", "info_disclosure", "low",
      r"^\S+ /[^ ]*(?:server-status|phpinfo\.php|info\.php|actuator/(?:env|health|heapdump)|/debug/|\.well-known/security\.txt)"),
    R("docker-api", "Docker Engine API probe", "info_disclosure", "high", r"^\S+ /(?:v1\.\d+/)?containers/json"),
    R("admin-wordpress", "WordPress login / xmlrpc probe", "admin_panel_probe", "low", r"^\S+ /[^ ]*(?:wp-login\.php|xmlrpc\.php|wp-admin)"),
    R("admin-pma", "phpMyAdmin probe", "admin_panel_probe", "low", r"^\S+ /[^ ]*(?:phpmyadmin|pma|myadmin)\b"),
    R("admin-generic", "Admin / router login page probe", "admin_panel_probe", "low",
      r"^\S+ /(?:admin|login|manager/html|boaform/admin/formLogin|cgi-bin/login|HNAP1|webfig|userRpm|login\.htm)"),
]

SCANNERS = [
    # (name, kind, regex on User-Agent)
    ("Censys", "research", r"censys"),
    ("Shodan", "research", r"shodan"),
    ("Palo Alto Expanse", "research", r"expanse"),
    ("InternetMeasurement", "research", r"internetmeasurement|internet-measurement"),
    ("LeakIX", "research", r"l9explore|l9tcpid|leakix"),
    ("Onyphe", "research", r"onyphe"),
    ("masscan", "scanner", r"masscan"),
    ("zgrab", "scanner", r"zgrab"),
    ("Nuclei", "scanner", r"nuclei|projectdiscovery"),
    ("Nmap NSE", "scanner", r"nmap scripting engine|\bnmap\b"),
    ("sqlmap", "scanner", r"sqlmap"),
    ("Nikto", "scanner", r"nikto"),
    ("WPScan", "scanner", r"wpscan"),
    ("gobuster/ffuf", "scanner", r"gobuster|fuzz faster u fool|dirbuster"),
    ("Mirai-variant", "bot", r"^hello,? ?world|^mozi\.[am]\b"),
    ("Go net/http", "library", r"go-http-client"),
    ("python-requests", "library", r"python-requests|python-urllib|aiohttp"),
    ("curl", "library", r"^curl/"),
    ("wget", "library", r"^wget/"),
    ("libwww-perl", "library", r"libwww-perl"),
]
_SCANNER_RE = [(n, k, re.compile(p, re.I)) for n, k, p in SCANNERS]
URL_IN_PAYLOAD = re.compile(r"((?:https?|ftp|tftp)://[^\s'\"<>;|&`)]+)", re.I)


def decode(text: str) -> str:
    """URL-decode twice, so single and double encoded payloads both match the rules."""
    once = unquote_plus(text)
    return unquote_plus(once) if "%" in once else once


def identify_scanner(user_agent: str | None) -> tuple[str | None, str | None]:
    ua = (user_agent or "").strip()
    if not ua:
        return None, None
    for name, kind, rx in _SCANNER_RE:
        if rx.search(ua):
            return name, kind
    return None, None


LOG4J_NESTED = re.compile(r"\$\{(?:lower:|upper:|::-|[a-z]*:[^:${}]*:-)([^${}]*)\}", re.I)


def unwrap_log4j(text: str) -> str:
    """Collapse Log4j lookup obfuscation, e.g. ${${lower:j}${::-n}di:...} -> ${jndi:...}."""
    for _ in range(5):
        new = LOG4J_NESTED.sub(r"\1", text)
        if new == text:
            break
        text = new
    return text


def build_haystack(method: str, path: str, headers: dict, body: str) -> str:
    """Request as text: raw form plus decoded and de-obfuscated forms when they differ."""
    head = "\n".join(f"{k.lower()}: {v}" for k, v in (headers or {}).items())
    raw = f"{method} {path} HTTP/1.1\n{head}\n\n{body or ''}"
    variants = [raw]
    for v in (decode(raw), unwrap_log4j(decode(raw))):
        if v not in variants:
            variants.append(v)
    return "\n".join(variants)


def payload_urls(method, path, headers, body, include_ua: bool) -> list[str]:
    """URLs an attacker wants a victim to fetch (droppers, callbacks). Recorded, never fetched.
    The User-Agent and Referer are skipped for plain requests because scanners put their own
    info page there."""
    skip = set() if include_ua else {"user-agent", "referer"}
    kept = {k: v for k, v in (headers or {}).items() if k.lower() not in skip}
    return sorted(set(URL_IN_PAYLOAD.findall(build_haystack(method or "GET", path or "/", kept, body or ""))))[:10]


def classify_request(method: str, path: str, headers: dict | None, body: str | None) -> dict:
    """Return categories, CVEs, matched rules, severity, scanner identity and payload URLs."""
    headers = headers or {}
    hay = build_haystack(method or "GET", path or "/", headers, body or "")
    matches = [r for r in RULES if r.pattern.search(hay)]
    ua = next((v for k, v in headers.items() if k.lower() == "user-agent"), "")
    scanner, scanner_kind = identify_scanner(ua)
    # Primary category: the most severe match; CVE-specific rules win ties.
    matches.sort(key=lambda r: (SEVERITY_ORDER[r.severity], bool(r.cve)), reverse=True)
    cves = sorted({c for r in matches for c in r.cve})
    return {
        "category": matches[0].category if matches else ("scan" if scanner else "benign_or_unknown"),
        "categories": sorted({r.category for r in matches}),
        "rules": [r.rule_id for r in matches],
        "rule_names": [r.name for r in matches],
        "cves": cves,
        "severity": matches[0].severity if matches else "info",
        "scanner": scanner,
        "scanner_kind": scanner_kind,
        "urls": payload_urls(method, path, headers, body, include_ua=bool(matches)),
    }
