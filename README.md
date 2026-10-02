# sigma-rules

Detection rules in [Sigma](https://github.com/SigmaHQ/sigma) format for Windows endpoint and identity telemetry, written for threat hunting and SOC triage. Each rule has an ATT&CK mapping, a stated false-positive list and a severity.

> **Read this first.** These are starting points, not production detections. Test each rule on historical data, tune it against your normal activity and review false positives before alerting. Rules use the standard Sigma Windows field names (`Image`, `CommandLine`, `ParentImage`, and so on). Nothing here comes from any employer, and all examples are generic.

## Why Sigma
One rule converts to many platforms. Every rule in this repo is checked in CI by converting it to **Splunk** and **Microsoft KQL** with [pySigma](https://github.com/SigmaHQ/pySigma).

## Rules (20)

| Rule | Log source | ATT&CK | Level |
|---|---|---|---|
| [ClickFix Pattern: Explorer Spawns Scripting Host With Remote Content](rules/windows/process_creation/clickfix_explorer_spawns_scripting_host.yml) | process_creation | T1204.004, T1059.001, T1218.005 | high |
| [Microsoft Defender Tampering Commands](rules/windows/process_creation/defender_tampering_commands.yml) | process_creation | T1562.001 | high |
| [Privileged Group Discovery via Net or Nltest](rules/windows/process_creation/domain_admins_discovery.yml) | process_creation | T1069.002, T1482 | low |
| [Windows Event Log Cleared via Command Line](rules/windows/process_creation/event_log_clearing.yml) | process_creation | T1070.001 | high |
| [Signed Binary Proxy Execution With Remote Content](rules/windows/process_creation/lolbin_remote_content.yml) | process_creation | T1218 | medium |
| [LSASS Memory Dump via Comsvcs or ProcDump](rules/windows/process_creation/lsass_dump_comsvcs.yml) | process_creation | T1003.001 | high |
| [NTDS.dit Extraction via Ntdsutil or Shadow Copy](rules/windows/process_creation/ntdsutil_ifm_extraction.yml) | process_creation | T1003.003 | high |
| [Office Application Spawns Scripting Host or Shell](rules/windows/process_creation/office_spawns_script_host.yml) | process_creation | T1566.001, T1204.002 | high |
| [PowerShell Download Cradle](rules/windows/process_creation/powershell_download_cradle.yml) | process_creation | T1059.001, T1105 | medium |
| [PowerShell Encoded or Hidden Command](rules/windows/process_creation/powershell_encoded_hidden.yml) | process_creation | T1059.001, T1027 | medium |
| [PsExec Service Execution](rules/windows/process_creation/psexec_service_execution.yml) | process_creation | T1021.002, T1569.002 | medium |
| [Rclone or Cloud Sync Tool Used for Bulk Transfer](rules/windows/process_creation/rclone_data_exfiltration.yml) | process_creation | T1567.002 | high |
| [Registry Hive Save of SAM, SYSTEM or SECURITY](rules/windows/process_creation/reg_save_credential_hives.yml) | process_creation | T1003.002 | high |
| [Scheduled Task Created With Suspicious Command or Path](rules/windows/process_creation/schtasks_create_suspicious_command.yml) | process_creation | T1053.005 | medium |
| [Shadow Copy and Recovery Deletion](rules/windows/process_creation/shadow_copy_and_recovery_deletion.yml) | process_creation | T1490 | high |
| [Shell Spawned by WMI Provider Host](rules/windows/process_creation/wmi_remote_process_creation.yml) | process_creation | T1047 | medium |
| [ClickFix Pattern: RunMRU Entry With Scripting Host or URL](rules/windows/registry/clickfix_runmru_script_host.yml) | registry_set | T1204.004 | high |
| [DCSync Replication Rights Used by a Non-Computer Account](rules/windows/security/dcsync_replication_by_user.yml) | security | T1003.006 | high |
| [Kerberos Service Ticket Requested With RC4 Encryption](rules/windows/security/kerberoasting_rc4_service_ticket.yml) | security | T1558.003 | medium |
| [New Service Installed With Suspicious Image Path](rules/windows/system/new_service_suspicious_image_path.yml) | system | T1543.003, T1569.002 | high |

## ATT&CK coverage
See [`coverage/COVERAGE.md`](coverage/COVERAGE.md) for a table by tactic, and load [`coverage/navigator-layer.json`](coverage/navigator-layer.json) into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) (Open Existing Layer → Upload from local) for a heat map. The report combines these rules with the query sets in [soc-hunting-queries](https://github.com/HaHashem/soc-hunting-queries). Coverage means a rule or query exists, not that it is tuned or deployed.

Rebuild it after changing rules:
```
python tools/coverage.py --hunting ../soc-hunting-queries
```

## Convert a rule
```
pip install sigma-cli pysigma-backend-splunk pysigma-backend-kusto
sigma convert -t splunk rules/windows/process_creation/powershell_download_cradle.yml
sigma convert -t kusto  rules/windows/process_creation/powershell_download_cradle.yml
```
For Sysmon, Microsoft Defender or other schemas, add the matching pipeline with `-p`. Field names depend on the pipeline you choose, so check the output before use.

## Checks
```
pip install -r requirements.txt
python tools/validate_rules.py     # required fields, unique ids, tags, levels
python tools/convert_check.py      # every rule compiles to Splunk and KQL
```

## Related
- [soc-hunting-queries](https://github.com/HaHashem/soc-hunting-queries): platform-native hunting queries
- [Articles and write-ups](https://hahashem.github.io/articles.html)

## License
[MIT](LICENSE)
