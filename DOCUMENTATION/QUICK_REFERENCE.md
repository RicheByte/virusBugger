# Quick Reference Card

## Installation

```powershell
pip install pefile yara-python requests
```

## Basic Commands

```powershell
# Simple analysis
python mal.py sample.exe

# With custom YARA
python mal.py sample.exe --yara rules.yar

# With Cuckoo sandbox
python mal.py sample.exe --cuckoo http://127.0.0.1:8090

# JSON output + verbose
python mal.py sample.exe --json output.json --verbose

# No database
python mal.py sample.exe --no-db
```

## Output Files

- **Report**: `reports/report_<md5>_<timestamp>.md`
- **Database**: `malware_analysis.db`
- **JSON** (if --json): Custom path

## Risk Scores

- **0-49**: 🟢 LOW RISK
- **50-74**: 🟡 MEDIUM RISK
- **75-100**: 🔴 HIGH RISK

## Database Queries

```sql
-- High risk samples
SELECT filename, md5, risk_score FROM samples WHERE risk_score >= 75;

-- All IOCs for a sample
SELECT type, value FROM iocs WHERE sample_md5='<hash>';

-- YARA matches
SELECT rule_name, COUNT(*) FROM yara_matches GROUP BY rule_name;
```

## Embedded YARA Rules

1. Suspicious_URL_Strings
2. Suspicious_Registry
3. Packer_Indicators
4. Suspicious_Network
5. Process_Injection
6. Ransomware_Indicators
7. Keylogger_Indicators
8. Credential_Theft
9. Anti_Analysis

## Analysis Steps

1. Hash computation (MD5, SHA1, SHA256)
2. String extraction (streaming)
3. IOC extraction (URLs, IPs, domains, etc.)
4. PE analysis (sections, imports, entropy)
5. YARA scanning
6. Cuckoo sandbox (optional)
7. Risk scoring
8. Report generation

## Safety Checklist

- [ ] Isolated network (air-gapped or host-only)
- [ ] VM snapshot taken
- [ ] No personal data on analysis system
- [ ] Legal authorization obtained
- [ ] Chain of custody documented

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Module not found | `pip install <module>` |
| Cuckoo timeout | Check service, use --verbose |
| Database locked | Reset DB or check WAL mode |
| Out of memory | Reduce max_strings in code |

## Documentation

- `README.md` - Main documentation
- `SETUP_GUIDE.md` - Installation guide
- `WORKFLOW_GUIDE.md` - Analysis workflow
- `IMPROVEMENTS.md` - Technical details
- `EXAMPLES.md` - Usage examples
- `PROJECT_SUMMARY.md` - What was created

## Support

- Check documentation files
- Run with `--verbose` for debug info
- Review error logs

---

**Version**: 2.0 | **Date**: Oct 26, 2025
