# detection-rules-ci

![CI](https://github.com/JoseArgento/detection-rules-ci/actions/workflows/validate.yaml/badge.svg)

Detection as code: Sigma rules kept in Git, tested with pytest against real
log lines, compiled to LogQL in CI, and deployed to a Grafana/Loki SIEM as
generated provisioning files with stable IDs.

I treat detection rules the same way I treat test code: every push is linted
and validated, every rule is checked against known attacks and against a
corpus of normal traffic, and nobody edits the generated output by hand.

The rules protect a live target: a WoW Classic (VMaNGOS) server running on my
own hardware. The full lab is in
[`wow-classic-secure-lab`](https://github.com/JoseArgento/wow-classic-secure-lab).

---

## Rules

| Rule | Source | Technique | Level | Threshold and why |
|---|---|---|---|---|
| SSH Brute Force | `sshd` (journal) | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Medium | Fires on the 4th attempt, **before** fail2ban bans at 5 |
| SSH Preauth Disconnect | `sshd` (journal) | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Low | Scanners that connect but never get to authenticate |
| SSH Penalty Caused Crash | `sshd` (journal) | [T1190](https://attack.mitre.org/techniques/T1190/) | High | One line is enough: a client made an `sshd` process crash. Also submitted to SigmaHQ (PR #6127) |
| Linux Security Service Stopped | systemd (journal) | [T1685](https://attack.mitre.org/techniques/T1685/) | Medium | fail2ban, ssh or ufw stopped. Complements the dead man's switch, which covers the log agent |
| Linux Local Account Created | `useradd` (journal) | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Medium | Any new local account on the server is unexpected |
| VMaNGOS Wrong Password | `Realmd.log` | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Medium | Fires on the 5th attempt, **before** the server locks the IP at 10 |
| VMaNGOS IP Lockout | `Realmd.log` | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | High | A single lockout line means the server already confirmed an attack, so `> 0` and no wait |
| VMaNGOS Protocol Scan | `Realmd.log` | [T1046](https://attack.mitre.org/techniques/T1046/) | Low | A burst of unknown packet commands means something other than a game client |

Most thresholds are set so that **detection fires before the response layer
acts**. That way the SOC sees the attack while it is happening, not only after
something already blocked it.

### Where each alert goes

- **Rules with an IP** (SSH and VMaNGOS) go to the n8n SOAR, which looks the IP
  up, asks an LLM for a verdict and can propose a ban. Each IP gets its own
  notification (`group_by` on `ip`), because the SOAR evaluates one alert per
  webhook.
- **Host rules** (service stopped, account created) have no IP to look up or
  ban, so they go straight to Telegram for a person to check.

This is configured per rule in `deploy/rules-config.yaml` (`ip: false`,
`receiver`).

---

## ATT&CK coverage

Measured with [`attack-mapper`](https://pypi.org/project/attack-mapper/)
against Enterprise ATT&CK v19 (April 2026):

| | Before (5 rules) | After (8 rules) |
|---|---|---|
| Techniques | 3 | 7 |
| Tactics | 2 | 5 |
| Coverage | 0.4 % | 1.0 % |

The reports (HTML, JSON, SVG and text) and the comparison script are in
[`docs/coverage/`](docs/coverage/). The low percentage is expected: this is a
single game server, not an enterprise. The point is to measure, not to chase
the number.

ATT&CK v19 split Defense Evasion and moved `T1562.001` to `T1685` (Defense
Impairment). attack-mapper flagged the old ID as unknown instead of counting
it, which is how the remap was caught.

---

## Pipeline

### On every push (GitHub Actions)

1. `sigma check rules/`: syntax, required fields, ATT&CK tags
2. `sigma convert -t loki rules/`: every merged rule must be deployable
3. `pytest tests/ -v`: true positive and false positive regression suite

### Deploy (`deploy/deploy.sh`, from my PC)

```
tests -> generate_alerts.py -> copy to the lab repo -> scp to the SIEM VM -> restart Grafana
```

`generate_alerts.py` compiles the Sigma rules to LogQL and writes a complete
Grafana alerting provisioning file. The alert UIDs come from the Sigma rule
IDs, so a redeploy updates the existing rules instead of creating duplicates,
and the file can be rebuilt from source at any time. The generated file is not
committed here; the deployed copy is versioned in the lab repo.

### Separation of concerns

- **`rules/`** (Sigma) says *what to detect*. Portable and independent of the
  backend.
- **`deploy/rules-config.yaml`** says *how it runs in this environment*:
  datasource, receivers, thresholds per rule, Loki streams. None of that leaks
  into the detection logic.

---

## Testing approach

`tests/test_detections.py` is parametrized: adding a rule means one
`pytest.param` and one log file. The two checks are asymmetric on purpose:

- **Detection: `>= 1` match.** Flexible, so a rule being tuned doesn't break
  the build over exact counts.
- **False positives: `== 0`.** Strict. Every rule must stay silent on a shared
  benign corpus (`normal_activity.log`) that keeps growing with legitimate
  traffic, so each new rule is tested against everything known to be normal.

The log files for the newer rules are real lines taken from the lab server,
not written by hand. Tests compile the rule with the same pySigma Loki
backend used for deployment, so what gets tested is what gets shipped.

---

## Known gaps

- **VMaNGOS doesn't log login attempts against accounts that don't exist**,
  even at `LogLevel 3`, so username enumeration with invalid accounts is
  invisible to the `Realmd.log` rules. The protocol scan and preauth rules
  partly cover the probing around it.
- **`sudo-rs` doesn't log denied commands** the way classic `sudo` does, so a
  privilege escalation attempt that gets rejected leaves no trace for a rule
  to match. Found by generating the real event; `auditd` is on the backlog.
- Network level detection (scans, known bad IPs) is handled by Suricata in
  the lab, not by these log rules.

---

## Downstream

Alerts are triaged by an n8n SOAR pipeline (LLM analyst, IP lookups, verdict
cache), and bans only happen after a person approves them on Telegram. Full
write-up:
[`soar-pipeline.md`](https://github.com/JoseArgento/wow-classic-secure-lab/blob/main/docs/soar-pipeline.md).

---

## Roadmap

- [x] Automated tests against sample logs (TP/FP regression)
- [x] Alert generation and deployment to Grafana (stable provisioning)
- [x] Game protocol detections (VMaNGOS family)
- [x] Host integrity rules (security services, new accounts) routed straight to a human
- [x] ATT&CK coverage measured with attack-mapper
- [ ] `auditd` rules to cover the `sudo-rs` gap
- [ ] Web attack detections (path traversal, SQLi)
- [ ] Attack chain simulation as an end to end pipeline test
