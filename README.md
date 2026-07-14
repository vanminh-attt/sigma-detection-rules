# Sigma Detection Rules 🕵️

Hand-written [Sigma](https://sigmahq.io) detection rules from my purple-team lab — mapped to [MITRE ATT&CK](https://attack.mitre.org/), tested against real Windows event logs, and converted to Splunk queries with `sigma-cli`.

> 🧪 **Lab setup:** Windows VM (Sysmon + PowerShell Script Block Logging) → Splunk. Rule descriptions are written in Vietnamese — the detection logic is universal 😄

## 📋 Rule index

| Rule | MITRE ATT&CK | Log source | Severity |
|---|---|---|---|
| [PowerShell Encoded Command](rules/windows/encoded_powershell.yml) | [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1027](https://attack.mitre.org/techniques/T1027/) | process_creation | 🔴 High |
| [Failed Logon → Brute Force](rules/windows/failed_logon.yml) *(correlation rule)* | [T1110](https://attack.mitre.org/techniques/T1110/) | Security EventID 4625 | 🔴 High |
| [Suspicious LSASS Process Access](rules/windows/lsass_access.yml) | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Sysmon EventID 10 (process_access) | 🔴 High |
| [PowerShell Download Cradle](rules/windows/ps_download.yml) | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Script Block Logging (4104) | 🔴 High |
| [User Added to Local Administrators](rules/windows/user_add_admin.yml) | [T1098](https://attack.mitre.org/techniques/T1098/) | Security EventID 4732 | 🔴 High |
| [Whoami Execution](rules/windows/whoami.yml) | [T1033](https://attack.mitre.org/techniques/T1033/) | process_creation | 🟡 Medium |

## 🚀 Convert to Splunk

```bash
pip install sigma-cli
sigma plugin install splunk

# Convert every rule using the custom lab pipeline
sigma convert -t splunk -p pipelines/splunk_pipeline.yml rules/windows/
```

The [custom pipeline](pipelines/splunk_pipeline.yml) wraps each query with `index=*` so it works out of the box in a lab; in production you would scope it to your Windows indexes.

Example — `encoded_powershell.yml` becomes:

```
index=* (Image="*\\powershell.exe" OR Image="*\\pwsh.exe") (CommandLine="* -enc *" OR CommandLine="* -encodedcommand *" OR CommandLine="* -ec *")
```

## 🧠 Detection engineering notes

- **Every rule documents its false positives** — a detection without an FP strategy is just an alert generator.
- **Noise-tiering:** `whoami.exe` alone is Medium (post-exploitation discovery signal), while LSASS access with read rights is High — severity follows attacker cost, not event rarity.
- **Correlation over single events:** [failed_logon.yml](rules/windows/failed_logon.yml) ships a low-severity base rule (4625) plus a Sigma **correlation rule** — ≥10 failures from the same `IpAddress` + `TargetUserName` within 5 minutes ⇒ brute force.
- **Benign-path filtering:** the LSASS rule excludes `C:\Windows\System32\` and `C:\Program Files\` source images to cut AV/EDR noise before it hits the SOC queue.

## 🗺️ ATT&CK coverage

`Execution` · `Defense Evasion` · `Credential Access` · `Persistence` · `Discovery`

## 🛣️ Roadmap

- [ ] Scheduled task persistence (T1053.005) & registry run keys (T1547.001)
- [ ] GitHub Actions CI: `sigma check` validation on every push
- [ ] Second backend: Elastic / Wazuh conversion
- [ ] Atomic Red Team test mapping per rule

## 📄 License

[MIT](LICENSE) — use, adapt, and hunt freely.
