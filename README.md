# detection-rules-ci

![CI](https://github.com/JoseArgento/detection-rules-ci/actions/workflows/validate.yaml/badge.svg)

**Detection-as-Code**: Sigma rules versioned in Git, regression-tested with
pytest, compiled to LogQL in CI, and deployed to a Grafana/Loki SIEM as
generated provisioning — with deterministic identity end to end.

Detection rules are treated exactly like software, because they are: linted
and validated on every push, tested against known-attack and known-benign
log corpus, and never edited by hand downstream. The approach applies QA
automation discipline (regression suites, CI gates, single source of truth)
to detection engineering.

These rules monitor a live target: a hardened WoW Classic (VMaNGOS) server on
AWS EC2 — full lab: [`wow-classic-secure-lab`](https://github.com/JoseArgento/wow-classic-secure-lab).

---

## Rules

| Rule | Source | Technique | Level | Threshold rationale |
|---|---|---|---|---|
| SSH Brute Force | `sshd` journald | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Medium | Fires on the 4th attempt — **before** fail2ban bans at 5 |
| SSH Preauth Disconnect | `sshd` journald | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Low | Catches scanner probing that never reaches auth |
| VMaNGOS Wrong Password | `Realmd.log` | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Medium | Fires on the 5th attempt — **before** the server's lockout at 10 |
| VMaNGOS IP Lockout | `Realmd.log` | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | High | `> 0`: a single lockout line encodes a confirmed sustained attack; `for: 0s` — notify immediately |
| VMaNGOS Protocol Scan | `Realmd.log` | [T1046](https://attack.mitre.org/techniques/T1046/) | Low | Burst of unknown packet commands = non-game-client probing |

The pattern across thresholds is deliberate: **detection fires before the
response layer acts**, so the SOC pipeline sees the attack developing, not
just its aftermath.

---

## Pipeline

### On every push (GitHub Actions)

1. `sigma check rules/` — syntax, required fields, ATT&CK tags
2. `sigma convert -t loki rules/` — guarantees every merged rule is deployable
3. `pytest tests/ -v` — true-positive / false-positive regression suite

### On deploy (`deploy/deploy.sh`, run on the SIEM host)

```
git pull → generate_alerts.py → cp to Grafana provisioning → docker restart grafana
```

`generate_alerts.py` compiles the Sigma sources to LogQL and emits a complete
Grafana alerting provisioning file, with **UIDs derived deterministically from
the Sigma rule IDs** — redeploys update rules in place instead of duplicating
them, and the generated file is reproducible from source at any time.

### Separation of concerns

- **`rules/`** (Sigma) answers *what to detect* — portable, backend-agnostic.
- **`deploy/rules-config.yaml`** answers *in this environment* — datasource,
  receiver, per-rule thresholds and Loki source streams. Environment identity
  never leaks into the detection logic.

---

## Testing philosophy

The suite (`tests/test_detections.py`) is parametrized: adding a rule means
adding one `pytest.param` and two log fixtures. Two asymmetric assertions, by
design:

- **Positive detection: `>= 1`** — flexible; rules under active tuning
  shouldn't break the build over match counts.
- **False positives: `== 0`** — strict, non-negotiable. Every rule must pass
  clean against a **shared benign corpus** (`normal_activity.log`) that
  accumulates legitimate traffic — so each new rule is automatically tested
  against everything ever known to be normal.

Tests compile the rule through the same pySigma Loki backend used for
deployment and assert against the compiled artifact — **what's tested is
what ships**, not a hand-written approximation of it.

---

## Known detection gaps (documented, not hidden)

- **VMaNGOS does not log authentication attempts against non-existent
  accounts**, even at `LogLevel 3`. Username-enumeration attempts using
  invalid accounts are invisible to the `Realmd.log` rules. Documented as an
  accepted gap: partially compensated by the protocol-scan and preauth rules,
  which catch the surrounding probing behavior.

---

## Downstream

Firing alerts are triaged by an n8n SOAR pipeline (LLM analyst, IOC
enrichment, verdict cache) with human-in-the-loop banning via a hardened SSH
channel. Full write-up:
[`soar-pipeline.md`](https://github.com/JoseArgento/wow-classic-secure-lab/blob/main/docs/soar-pipeline.md).

---

## Roadmap

- [x] Automated tests against sample logs (TP/FP regression)
- [x] Alert generation & deployment to Grafana (deterministic provisioning)
- [x] Game-protocol detections (VMaNGOS family)
- [ ] Web attack detections (path traversal, SQLi)
- [ ] Attack-chain simulation as an end-to-end pipeline test
