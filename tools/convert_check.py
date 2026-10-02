#!/usr/bin/env python3
"""Convert every rule to Splunk and KQL with pySigma to prove the rules compile.
pip install pysigma pysigma-backend-splunk pysigma-backend-kusto"""
import glob, sys
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.backends.kusto import KustoBackend

bad = 0
for f in sorted(glob.glob("rules/**/*.yml", recursive=True)):
    try:
        c = SigmaCollection.from_yaml(open(f).read())
        SplunkBackend().convert(c); KustoBackend().convert(c)
    except Exception as e:
        bad += 1; print("FAIL", f, type(e).__name__, str(e)[:200])
print("conversion check:", "FAILED" if bad else "all rules convert to Splunk and KQL")
sys.exit(1 if bad else 0)
