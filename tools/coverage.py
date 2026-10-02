#!/usr/bin/env python3
"""Build an ATT&CK coverage report from Sigma rule tags and, optionally,
from the '## ATT&CK' line of hunting-query markdown files.

Usage:
  python tools/coverage.py                        # Sigma rules only
  python tools/coverage.py --hunting ../soc-hunting-queries
Outputs:
  coverage/COVERAGE.md            readable table grouped by tactic
  coverage/navigator-layer.json   import at https://mitre-attack.github.io/attack-navigator/
"""
import argparse, glob, json, os, re, sys
from collections import defaultdict
import yaml

TACTICS = ["initial-access","execution","persistence","privilege-escalation","defense-evasion",
           "credential-access","discovery","lateral-movement","collection","command-and-control",
           "exfiltration","impact"]
# base technique -> tactics it belongs to (primary ATT&CK mapping)
BASE = {
 "T1003":["credential-access"],"T1016":["discovery"],"T1018":["discovery"],"T1082":["discovery"],"T1087":["discovery"],"T1021":["lateral-movement"],"T1027":["defense-evasion"],
 "T1036":["defense-evasion"],"T1041":["exfiltration"],"T1046":["discovery"],"T1047":["execution"],
 "T1048":["exfiltration"],"T1053":["execution","persistence","privilege-escalation"],"T1059":["execution"],
 "T1069":["discovery"],"T1070":["defense-evasion"],"T1071":["command-and-control"],
 "T1078":["initial-access","persistence","privilege-escalation","defense-evasion"],
 "T1095":["command-and-control"],"T1098":["persistence","privilege-escalation"],"T1105":["command-and-control"],
 "T1110":["credential-access"],"T1114":["collection"],"T1133":["initial-access","persistence"],
 "T1136":["persistence"],"T1137":["persistence"],"T1140":["defense-evasion"],"T1189":["initial-access"],
 "T1190":["initial-access"],"T1204":["execution"],"T1218":["defense-evasion"],"T1482":["discovery"],
 "T1484":["defense-evasion","privilege-escalation"],"T1485":["impact"],"T1486":["impact"],"T1489":["impact"],
 "T1490":["impact"],"T1496":["impact"],"T1528":["credential-access"],"T1530":["collection"],
 "T1543":["persistence","privilege-escalation"],"T1546":["persistence","privilege-escalation"],
 "T1547":["persistence","privilege-escalation"],"T1550":["defense-evasion","lateral-movement"],
 "T1552":["credential-access"],"T1556":["credential-access","defense-evasion","persistence"],
 "T1558":["credential-access"],"T1562":["defense-evasion"],"T1566":["initial-access"],
 "T1567":["exfiltration"],"T1568":["command-and-control"],"T1569":["execution"],"T1570":["lateral-movement"],
 "T1572":["command-and-control"],"T1573":["command-and-control"],"T1578":["defense-evasion"],
 "T1621":["credential-access"],
}
NAMES = {
 "T1003":"OS Credential Dumping","T1003.001":"LSASS Memory","T1003.002":"Security Account Manager",
 "T1003.003":"NTDS","T1003.006":"DCSync","T1016":"System Network Configuration Discovery","T1018":"Remote System Discovery","T1082":"System Information Discovery","T1087":"Account Discovery",
 "T1021":"Remote Services","T1021.001":"Remote Desktop Protocol","T1021.002":"SMB/Windows Admin Shares",
 "T1021.006":"Windows Remote Management","T1027":"Obfuscated Files or Information",
 "T1036.003":"Rename Legitimate Utilities","T1041":"Exfiltration Over C2 Channel",
 "T1046":"Network Service Discovery","T1047":"Windows Management Instrumentation",
 "T1048":"Exfiltration Over Alternative Protocol","T1053.005":"Scheduled Task","T1059.001":"PowerShell",
 "T1069.002":"Domain Groups","T1070.001":"Clear Windows Event Logs","T1071":"Application Layer Protocol",
 "T1071.001":"Web Protocols","T1071.004":"DNS","T1078":"Valid Accounts","T1078.004":"Cloud Accounts",
 "T1095":"Non-Application Layer Protocol","T1098":"Account Manipulation",
 "T1098.001":"Additional Cloud Credentials","T1098.003":"Additional Cloud Roles",
 "T1105":"Ingress Tool Transfer","T1110":"Brute Force","T1110.003":"Password Spraying",
 "T1114.003":"Email Forwarding Rule","T1133":"External Remote Services","T1136":"Create Account",
 "T1137":"Office Application Startup","T1140":"Deobfuscate/Decode Files or Information",
 "T1189":"Drive-by Compromise","T1190":"Exploit Public-Facing Application","T1204.002":"Malicious File",
 "T1204.004":"Malicious Copy and Paste","T1218":"System Binary Proxy Execution","T1218.005":"Mshta",
 "T1482":"Domain Trust Discovery","T1484":"Domain or Tenant Policy Modification","T1485":"Data Destruction",
 "T1486":"Data Encrypted for Impact","T1489":"Service Stop","T1490":"Inhibit System Recovery",
 "T1496":"Resource Hijacking","T1528":"Steal Application Access Token","T1530":"Data from Cloud Storage Object",
 "T1543.003":"Windows Service","T1546.003":"WMI Event Subscription","T1547":"Boot or Logon Autostart Execution",
 "T1547.001":"Registry Run Keys / Startup Folder","T1550.001":"Application Access Token",
 "T1552":"Unsecured Credentials","T1552.001":"Credentials In Files","T1556":"Modify Authentication Process",
 "T1558.003":"Kerberoasting","T1562":"Impair Defenses","T1562.001":"Disable or Modify Tools",
 "T1566":"Phishing","T1566.001":"Spearphishing Attachment","T1567":"Exfiltration Over Web Service",
 "T1567.002":"Exfiltration to Cloud Storage","T1568":"Dynamic Resolution","T1568.002":"Domain Generation Algorithms",
 "T1569.002":"Service Execution","T1570":"Lateral Tool Transfer","T1572":"Protocol Tunneling",
 "T1573":"Encrypted Channel","T1578":"Modify Cloud Compute Infrastructure","T1621":"Multi-Factor Authentication Request Generation",
}
TID = re.compile(r"^T\d{4}(?:\.\d{3})?$")

def sigma_techniques(root):
    out = defaultdict(list)
    for f in sorted(glob.glob(os.path.join(root, "rules", "**", "*.yml"), recursive=True)):
        r = yaml.safe_load(open(f))
        for t in r.get("tags", []):
            m = re.match(r"attack\.(t\d{4}(?:\.\d{3})?)$", t)
            if m:
                out[m.group(1).upper()].append(("rule", r["title"]))
    return out

def hunting_techniques(root):
    out = defaultdict(list)
    for f in sorted(glob.glob(os.path.join(root, "*", "*.md"))):
        lines = open(f, encoding="utf-8").read().split("\n")
        for i, l in enumerate(lines):
            if l.strip() == "## ATT&CK":
                j = i + 1
                while j < len(lines) and not lines[j].strip():
                    j += 1
                for m in re.finditer(r"(T\d{4}(?:\.\d{3})?)", lines[j] if j < len(lines) else ""):
                    out[m.group(1)].append(("query", os.path.relpath(f, root)))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hunting", help="path to the hunting-queries repo")
    ap.add_argument("--out", default="coverage")
    a = ap.parse_args()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cov = defaultdict(list)
    for k, v in sigma_techniques(root).items(): cov[k] += v
    if a.hunting:
        for k, v in hunting_techniques(a.hunting).items(): cov[k] += v
    unknown = [t for t in cov if t.split(".")[0] not in BASE]
    for t in unknown: print("warning: no tactic mapping for", t, file=sys.stderr)
    os.makedirs(os.path.join(root, a.out), exist_ok=True)

    by_tactic = defaultdict(list)
    for t in sorted(cov):
        for tac in BASE.get(t.split(".")[0], ["unmapped"]):
            by_tactic[tac].append(t)

    md = ["# ATT&CK coverage", "",
          "Generated by `tools/coverage.py` from Sigma rule tags" + (" and hunting-query ATT&CK lines" if a.hunting else "") + ".",
          "Coverage here means *a rule or query exists*, not that it is tuned or deployed in any environment.", "",
          f"**{len(cov)} techniques and sub-techniques** across {len([t for t in by_tactic if by_tactic[t]])} tactics.", ""]
    for tac in TACTICS + ["unmapped"]:
        items = by_tactic.get(tac)
        if not items: continue
        md += [f"## {tac.replace('-', ' ').title()}", "", "| Technique | Name | Rules | Queries |", "|---|---|---|---|"]
        for t in items:
            rules = sum(1 for k, _ in cov[t] if k == "rule")
            qs = sum(1 for k, _ in cov[t] if k == "query")
            md.append(f"| {t} | {NAMES.get(t, '')} | {rules} | {qs} |")
        md.append("")
    open(os.path.join(root, a.out, "COVERAGE.md"), "w").write("\n".join(md))

    layer = {"name": "Hashem detection coverage", "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
             "domain": "enterprise-attack",
             "description": "Techniques with at least one Sigma rule or hunting query.",
             "gradient": {"colors": ["#cfe8ff", "#1f6feb"], "minValue": 1, "maxValue": max([len(v) for v in cov.values()] + [1])},
             "techniques": [{"techniqueID": t, "score": len(v), "enabled": True,
                             "comment": "; ".join(sorted({n for _, n in v}))[:900]} for t, v in sorted(cov.items())]}
    json.dump(layer, open(os.path.join(root, a.out, "navigator-layer.json"), "w"), indent=2)
    print(f"{len(cov)} techniques written to {a.out}/")

if __name__ == "__main__":
    main()
