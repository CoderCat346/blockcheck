#!/usr/bin/env python3
"""Offline tests for blockcheck's classification logic.

Two mock resolvers run on loopback: a "filtering" one that sinks, NXDOMAINs,
drops and rewrites names, and a clean "truth" one. Nothing leaves the machine.

    python3 tests/test_classification.py
"""

import argparse
import os
import sys
from importlib.machinery import SourceFileLoader

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from mock_dns import MockDNS  # noqa: E402

bc = SourceFileLoader(
    "blockcheck", os.path.join(HERE, os.pardir, "blockcheck")).load_module()

TRUTH = {
    "example.com": ("A", "93.184.216.34"),
    "nx.test": ("A", "1.2.3.4"),
    "drop.test": ("A", "1.2.3.4"),
    "nodata.test": ("A", "1.2.3.4"),
    "private.test": ("A", "1.2.3.4"),
    "bp.test": ("A", "1.2.3.4"),
    "servfail.test": ("A", "1.2.3.4"),
    "refused.test": ("A", "1.2.3.4"),
    "ghost.test": ("NX", None),
    "track.site.test": ("CNAME", "site.test.sc.omtrdc.net"),
    "site.test.sc.omtrdc.net": ("A", "1.2.3.4"),
    "cdn.site.test": ("CNAME", "site.test.cdn.cloudflare.net"),
    "site.test.cdn.cloudflare.net": ("A", "1.2.3.4"),
}

LOCAL = {
    "example.com": ("A", "0.0.0.0"),
    "nx.test": ("NX", None),
    "drop.test": ("DROP", None),
    "nodata.test": ("NODATA", None),
    "private.test": ("A", "10.1.2.3"),
    "bp.test": ("A", "146.112.61.106"),
    "servfail.test": ("SERVFAIL", None),
    "refused.test": ("REFUSED", None),
    "ghost.test": ("NX", None),
    "track.site.test": ("CNAME", "site.test.sc.omtrdc.net"),
    "site.test.sc.omtrdc.net": ("A", "1.2.3.4"),
    "cdn.site.test": ("CNAME", "site.test.cdn.cloudflare.net"),
    "site.test.cdn.cloudflare.net": ("A", "1.2.3.4"),
}

failures = []
passes = 0


def check(cond, label, detail=""):
    global passes
    if cond:
        passes += 1
    else:
        failures.append(f"{label}{(': ' + detail) if detail else ''}")


def make_opts(local, truth, timeout=0.6):
    return argparse.Namespace(
        timeout=timeout, retries=1, dnssec=False, doh=False, doh_provider=None,
        local_resolvers=[local], control_resolvers=[truth],
        tls=False, http=False, auth=False, asn=False, port=443, http_port=80,
        max_ips=2, verbose=False, json=False, brief=False, quiet=True,
        check_chain_targets=True, no_color=True)


def main():
    local = MockDNS(LOCAL).start()
    truth = MockDNS(TRUTH).start()
    truth_addr = ("127.0.0.1", truth.port)
    opts = make_opts(local.address, truth_addr)

    cases = [
        ("example.com", "sinkhole", "BLOCKED"),
        ("nx.test", "nxdomain", "BLOCKED"),
        ("drop.test", "dropped", "BLOCKED"),
        ("nodata.test", "nodata", "BLOCKED"),
        ("private.test", "private", "BLOCKED"),
        ("bp.test", "blockpage", "BLOCKED"),
        ("servfail.test", "servfail", "BLOCKED"),
        ("refused.test", "refused", "BLOCKED"),
        ("ok.test", "ok", "ALLOWED"),
        ("ghost.test", "nonexistent", "UNKNOWN"),
    ]

    for name, want_class, want_verdict in cases:
        rep = bc.check_name(name, opts)
        got_class = rep["local"][0]["class"]
        check(got_class == want_class, f"{name}: class",
              f"want {want_class}, got {got_class}")
        check(rep["verdict"] == want_verdict, f"{name}: verdict",
              f"want {want_verdict}, got {rep['verdict']}")
        check(bool(rep["reasons"]) or want_verdict == "ALLOWED",
              f"{name}: has a reason")

    # a filtered name must still be probed against its real addresses
    rep = bc.check_name("example.com", opts)
    check(rep["truth"]["ips"] == ["93.184.216.34"], "truth survives the sinkhole",
          str(rep["truth"]["ips"]))
    check("93.184.216.34" not in [i for m in rep["local"] for i in bc.ips_of(m)],
          "local answer is not mistaken for the truth")

    # CNAME cloaking vs a legitimate CDN edge
    rep = bc.check_name("track.site.test", opts)
    ck = rep["cloaking"]
    check(ck["vendor"] == "Adobe Analytics", "cloaking: vendor", str(ck["vendor"]))
    check(ck["first_party"] is True, "cloaking: first-party disguise")
    check(len(ck["cross_domain"]) == 1, "cloaking: cross-domain hop")

    rep = bc.check_name("cdn.site.test", opts)
    ck = rep["cloaking"]
    check(ck["vendor"] is None, "cdn: no vendor")
    check(ck["cdn"] == "site.test.cdn.cloudflare.net", "cdn: recognised",
          str(ck["cdn"]))

    # --- pure functions --------------------------------------------------- #
    norm = bc.normalize
    check(norm("https://Example.COM/path?q=1")["base"] == "example.com", "normalize url")
    check(norm("*.Example.com.")["kind"] == "wildcard", "normalize wildcard")
    check(norm("example.com:8443")["base"] == "example.com", "normalize port")
    check(norm("not a domain!!")["error"], "normalize rejects junk")
    check(norm("example.*")["error"], "normalize rejects suffix wildcard")

    check(bc.registrable("a.b.example.co.uk") == "example.co.uk", "registrable psl")
    check(bc.registrable("x.example.com") == "example.com", "registrable simple")

    check(bc.ip_kind("0.0.0.0") == "sinkhole", "ip_kind sinkhole")
    check(bc.ip_kind("::") == "sinkhole", "ip_kind sinkhole v6")
    check(bc.ip_kind("10.1.2.3") == "private", "ip_kind private")
    check(bc.ip_kind("146.112.61.106") == "blockpage", "ip_kind blockpage")
    check(bc.ip_kind("93.184.216.34") == "public", "ip_kind public")
    check(bc.is_nat64("64:ff9b::1.2.3.4"), "ip_kind nat64")

    check(bc.cert_matches("example.com", {"san": ["example.com"]}) is True,
          "cert exact")
    check(bc.cert_matches("a.example.com", {"san": ["*.example.com"]}) is True,
          "cert wildcard")
    check(bc.cert_matches("a.b.example.com", {"san": ["*.example.com"]}) is False,
          "cert wildcard is one label")
    check(bc.cert_matches("example.com", {"subject": "CN=portal.local"}) is False,
          "cert mismatch")
    check(bc.cert_matches("x.test", {}) is None, "cert unknown")

    local.stop()
    truth.stop()

    print(f"{passes} passed, {len(failures)} failed")
    for f in failures:
        print(f"  FAIL {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
