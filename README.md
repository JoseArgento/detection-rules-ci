# detection-rules-ci

![CI](https://github.com/JoseArgento/detection-rules-ci/actions/workflows/validate.yaml/badge.svg)

Detection-as-Code lab: Sigma rules validated and compiled to LogQL through a CI pipeline.

Detection rules are treated like software — versioned in Git, linted and
validated on every push, and automatically converted to LogQL for deployment
on a Grafana/Loki SIEM stack. The approach applies QA automation practices
(regression testing, CI gates) to detection engineering.

## How it works

Every push triggers a GitHub Actions workflow that:
1. Validates all rules with `sigma check` (syntax, required fields, ATT&CK tags)
2. Compiles them to LogQL with the pySigma Loki backend, guaranteeing every
   merged rule is deployable

## Rules

| Rule | Technique | Level |
|------|-----------|-------|
| SSH brute force | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Medium |

## Roadmap

- [ ] Automated tests against sample logs (true positive / false positive regression)
- [ ] Web attack detections (path traversal, SQLi)
- [ ] Alert deployment to Grafana

Part of a broader blue team lab: SIEM stack (Grafana/Loki/Promtail) monitoring
a live game server, with automated IOC triage via n8n.
