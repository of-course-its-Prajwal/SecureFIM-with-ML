# SecureFIM Pro — Unit Tests

Unit tests for the detection logic used in the thesis evaluation.

## Running

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

## Coverage by module

| Test module | Code under test | What it verifies |
|---|---|---|
| `test_sensitivity_classifier.py` | `server.features.classify_sensitivity` | HIGH/MEDIUM/LOW path classification, incl. Nepal government record patterns (nagarikta, lalpurja, malpot, voter ID) |
| `test_ransomware_single_event.py` | `server.ransomware` | Signature checks: suspicious/double extensions, ransom-note filenames, encryption keywords in small text files |
| `test_ransomware_mass_patterns.py` | `server.ransomware` | Volumetric rules: mass rename/delete/create/modify thresholds and sliding-window eviction |
| `test_threat_scoring.py` | `server.features.calculate_threat_score` | Per-signal point contributions, 0–100 cap, severity-level boundaries |
| `test_corroborative_veto.py` | `server.features` | The H2 mechanism: SVM veto of volumetric alerts, unconditional trust of signature alerts, legacy additive mode |
| `test_mitre_and_working_hours.py` | `server.features` | MITRE ATT&CK technique tagging; business-hours/weekend detection incl. Nepali Sunday–Friday week |
| `test_auth_passwords.py` | `server.auth` | Salted PBKDF2-HMAC-SHA256 hashing, salt uniqueness, legacy SHA-256 upgrade path |
| `test_baseline.py` | `server.features` | SHA-256 file hashing and baseline entry creation |

All tests are offline — no OpenSearch, no network, no running server required.
