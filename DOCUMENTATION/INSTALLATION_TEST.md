# Installation & Test Script

## Quick Test (After Installing Dependencies)

### Step 1: Install Dependencies

```powershell
# Windows PowerShell
pip install pefile yara-python requests
```

### Step 2: Create Test File

```powershell
# Create a harmless test file
echo "This is a test file for malware analysis tool" > test_sample.txt
```

### Step 3: Run Analysis

```powershell
python mal.py test_sample.txt --verbose
```

### Step 4: Verify Output

You should see:

```
======================================================================
MALWARE ANALYSIS TRIAGE TOOL
======================================================================

[INFO] Step 1: Computing hashes and metadata...
    MD5:    <hash>
    SHA256: <hash>
    Type:   Unknown

[INFO] Step 2: Extracting strings (streaming mode)...
    ASCII strings: <count>

[INFO] Step 3: Extracting IOCs from strings...

[INFO] Step 5: Running YARA rules...
    Matches: <count>

[INFO] Step 7: Calculating risk score...
    Risk Score: <score>/100
    Assessment: 🟢 LOW RISK

[INFO] Step 8: Generating report...
    Report saved: reports/report_<md5>_<timestamp>.md

======================================================================
ANALYSIS COMPLETE
======================================================================

[✓] Analysis complete!
[✓] Report: reports/report_<md5>_<timestamp>.md
[✓] Data saved to database: malware_analysis.db
```

### Step 5: Check Generated Files

```powershell
# List report files
dir reports\

# Check database
sqlite3 malware_analysis.db "SELECT filename, md5, risk_score FROM samples;"
```

## Expected Files After First Run

```
mal/
├── mal.py
├── requirements.txt
├── README.md
├── SETUP_GUIDE.md
├── WORKFLOW_GUIDE.md
├── IMPROVEMENTS.md
├── EXAMPLES.md
├── PROJECT_SUMMARY.md
├── QUICK_REFERENCE.md
├── malware_analysis.db          ← Created on first run
└── reports/                      ← Created on first run
    └── report_*.md
```

## Installation Verification

### Check Python Version

```powershell
python --version
# Should be 3.8 or higher
```

### Check Dependencies

```powershell
python -c "import pefile; print('pefile:', pefile.__version__)"
python -c "import yara; print('yara:', yara.__version__)"
python -c "import requests; print('requests:', requests.__version__)"
```

Expected output:
```
pefile: 2023.2.7
yara: 4.3.1
requests: 2.31.0
```

### Run Help

```powershell
python mal.py --help
```

Should display full usage information.

## Troubleshooting Installation

### Issue: "No module named 'pefile'"

```powershell
pip install pefile
```

### Issue: "No module named 'yara'"

```powershell
pip install yara-python
```

If still fails, try:
```powershell
pip install yara-python-devel
```

### Issue: "No module named 'requests'"

```powershell
pip install requests
```

### Issue: Python not found

```powershell
# Check if Python is in PATH
where python

# If not found, add to PATH or use full path
C:\Python310\python.exe mal.py test_sample.txt
```

### Issue: pip not found

```powershell
python -m pip install --upgrade pip
```

## Testing All Features

### Test 1: Basic Analysis (No Dependencies)

```powershell
# Even without pefile/yara, basic analysis works
python mal.py test_sample.txt --no-db
```

### Test 2: With YARA Rules

```powershell
# Create simple YARA rule
@"
rule Test_Rule {
    strings:
        `$test = "test" nocase
    condition:
        `$test
}
"@ | Out-File -Encoding ASCII test.yar

# Run with custom rule
python mal.py test_sample.txt --yara test.yar
```

### Test 3: JSON Output

```powershell
python mal.py test_sample.txt --json test_output.json
type test_output.json | ConvertFrom-Json | ConvertTo-Json
```

### Test 4: Database Query

```powershell
# Install SQLite if not already
# Download from https://sqlite.org/download.html

sqlite3 malware_analysis.db "SELECT * FROM samples;"
```

## Success Indicators

✅ No import errors  
✅ Report file created in `reports/`  
✅ Database file created (`malware_analysis.db`)  
✅ JSON output created (if using `--json`)  
✅ Risk score calculated  
✅ No crashes or exceptions  

## Next Steps After Successful Test

1. Read `SETUP_GUIDE.md` for VM setup
2. Review `WORKFLOW_GUIDE.md` for analysis procedures
3. Study `EXAMPLES.md` for real-world scenarios
4. **Set up isolated analysis environment before analyzing real malware!**

---

**⚠️ WARNING: Never analyze real malware on your primary workstation!**

---

**Last Updated**: October 26, 2025
