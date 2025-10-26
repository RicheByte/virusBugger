# Usage Examples

## Quick Start Examples

### Basic Analysis

```bash
# Analyze a single executable
python mal.py sample.exe

# Output:
# ======================================================================
# MALWARE ANALYSIS TRIAGE TOOL
# ======================================================================
# 
# [INFO] Step 1: Computing hashes and metadata...
#     MD5:    5d41402abc4b2a76b9719d911017c592
#     SHA256: 2c26b46b68ffc68ff99b453c1d3041...
#     Type:   PE/DOS Executable
# 
# [INFO] Step 2: Extracting strings (streaming mode)...
#     ASCII strings: 847
#     Unicode strings: 132
# ...
# [INFO] Step 8: Generating report...
#     Report saved: reports/report_5d41402abc4b2a76b9719d911017c592_20251026_143022.md
```

### Verbose Mode for Debugging

```bash
python mal.py suspicious.dll --verbose

# Shows debug output:
# [DEBUG] Cuckoo task 42 status: pending
# [DEBUG] Cuckoo task 42 status: running
# [DEBUG] String extraction buffer size: 131072 bytes
```

### Custom YARA Rules

```bash
# Download community rules first
git clone https://github.com/Yara-Rules/rules.git yara-rules

# Use specific ruleset
python mal.py malware.exe --yara yara-rules/malware/MALW_Ransomware.yar

# Or combine multiple rule files
cat yara-rules/malware/*.yar > combined.yar
python mal.py sample.exe --yara combined.yar
```

### No Database Mode (Quick Triage)

```bash
# Don't save to database - just generate report
python mal.py quick_check.exe --no-db

# Useful for:
# - Quick one-off analysis
# - When database is corrupted
# - Privacy/retention requirements
```

### JSON Output for Automation

```bash
# Save as JSON for SIEM ingestion
python mal.py sample.exe --json results.json

# Batch processing
for file in samples/*.exe; do
    hash=$(md5sum "$file" | cut -d' ' -f1)
    python mal.py "$file" --json "results/${hash}.json" --no-db
done

# Parse with jq
cat results/*.json | jq '.analysis.risk_score' | sort -n
```

### Cuckoo Sandbox Integration

```bash
# Submit to local Cuckoo instance
python mal.py malware.exe --cuckoo http://127.0.0.1:8090

# With custom output
python mal.py malware.exe \
    --cuckoo http://192.168.56.10:8090 \
    --output /mnt/analysis/reports/ \
    --json /mnt/analysis/json/result.json
```

---

## Real-World Scenarios

### Scenario 1: Suspected Phishing Attachment

```bash
# Email attachment forwarded by user
# File: "Invoice_2025.exe" (suspicious .exe with document icon)

# Step 1: Initial triage
python mal.py Invoice_2025.exe --verbose

# Expected findings:
# - YARA hits: Suspicious_URL_Strings, Anti_Analysis
# - IOCs: Malicious download URL found in strings
# - PE Analysis: High entropy section (.rsrc: 7.89) - packed
# - Risk Score: 85/100 (HIGH RISK)

# Step 2: Check report
cat reports/report_<md5>_*.md

# Step 3: Extract IOCs for blocking
sqlite3 malware_analysis.db "
  SELECT type, value FROM iocs 
  WHERE sample_md5='<md5>' 
  AND type IN ('urls', 'ips', 'domains');
" | tee iocs_to_block.txt

# Step 4: Block IOCs in firewall/proxy
# (Tool-specific commands)
```

### Scenario 2: Suspected Ransomware

```bash
# File found in quarantine by AV
# File: "encrypted_files.dll"

# Step 1: Safe analysis (no-db to avoid contaminating main DB)
python mal.py encrypted_files.dll --no-db --json ransomware_analysis.json

# Expected findings:
# - YARA hits: Ransomware_Indicators, Process_Injection, Credential_Theft
# - IOCs: Bitcoin addresses, .onion domains
# - PE Imports: CryptEncrypt, CryptAcquireContext (crypto APIs)
# - Risk Score: 95/100 (CRITICAL)

# Step 2: Dynamic analysis (if isolated Cuckoo available)
python mal.py encrypted_files.dll \
    --cuckoo http://10.0.0.5:8090 \
    --no-db \
    --json ransomware_dynamic.json

# Step 3: Check for known ransomware family
grep -i "ransom\|wannacry\|lockbit\|ryuk" reports/report_*.md

# Step 4: Incident response
# - Isolate affected systems
# - Check for backups
# - Search for decryption tools
# - Report to authorities if applicable
```

### Scenario 3: APT Investigation

```bash
# Suspected advanced persistent threat (APT) implant
# File: "svchost.exe" (masquerading as Windows service)

# Step 1: Full analysis with custom APT YARA rules
python mal.py svchost.exe \
    --yara yara-rules/malware/APT_*.yar \
    --verbose \
    --json apt_analysis.json

# Expected findings:
# - YARA hits: APT28_Dropper, Anti_Analysis, Keylogger_Indicators
# - IOCs: C2 domains (compromised legitimate sites)
# - PE Timestamp: 2015-01-01 (timestomping - suspicious)
# - PE Imports: Keylogging APIs, network APIs
# - Risk Score: 92/100 (CRITICAL)

# Step 2: Extract C2 infrastructure
sqlite3 malware_analysis.db "
  SELECT DISTINCT value FROM iocs 
  WHERE sample_md5='<md5>' 
  AND type IN ('domains', 'ips')
  ORDER BY value;
"

# Step 3: Threat hunting
# Search other systems for same IOCs
for host in $(cat host_list.txt); do
    ssh $host "grep -r '<c2_domain>' /var/log/ /etc/hosts"
done

# Step 4: Timeline analysis
sqlite3 malware_analysis.db "
  SELECT filename, first_seen, risk_score 
  FROM samples 
  ORDER BY first_seen DESC 
  LIMIT 10;
"
```

### Scenario 4: Batch Analysis of Malware Collection

```bash
#!/bin/bash
# analyze_batch.sh - Process malware collection

SAMPLE_DIR="malware_samples"
OUTPUT_DIR="batch_results"
mkdir -p "$OUTPUT_DIR"

echo "Starting batch analysis of $SAMPLE_DIR"

for sample in "$SAMPLE_DIR"/*; do
    filename=$(basename "$sample")
    md5=$(md5sum "$sample" | cut -d' ' -f1)
    
    echo "[*] Analyzing: $filename ($md5)"
    
    # Run analysis
    python mal.py "$sample" \
        --json "$OUTPUT_DIR/${md5}.json" \
        --output "$OUTPUT_DIR/reports/" \
        2>&1 | tee "$OUTPUT_DIR/${md5}.log"
    
    # Extract risk score
    score=$(jq -r '.analysis.risk_score // 0' "$OUTPUT_DIR/${md5}.json")
    
    echo "$filename,$md5,$score" >> "$OUTPUT_DIR/summary.csv"
done

# Generate summary report
echo "Analysis complete. Summary:"
cat "$OUTPUT_DIR/summary.csv" | column -t -s','
echo ""
echo "High-risk samples (score >= 75):"
awk -F',' '$3 >= 75 {print $1, $2, $3}' "$OUTPUT_DIR/summary.csv"
```

### Scenario 5: Investigating Unknown File Type

```bash
# Unknown binary file found in network traffic capture
# File: "data.bin"

# Step 1: Check what it might be
python mal.py data.bin --verbose

# If not PE, you'll get limited analysis but still useful:
# [INFO] Type: Unknown
# [INFO] Step 2: Extracting strings...
#     ASCII strings: 234
# [INFO] Step 3: Extracting IOCs...
#     urls: 3
#     domains: 5

# Step 2: Manual investigation
strings -a data.bin | less
hexdump -C data.bin | head -n 50

# Step 3: Check for embedded files
binwalk data.bin

# Step 4: If embedded files found, extract and analyze
binwalk -e data.bin
for extracted in _data.bin.extracted/*; do
    python mal.py "$extracted"
done
```

---

## Advanced Usage

### Custom Risk Thresholds

```python
# Edit mal.py to customize risk scoring
def calculate_risk_score(analysis_results):
    score = 0
    
    # Custom weights for your environment
    if 'yara' in analysis_results:
        for match in analysis_results['yara']:
            severity = match.get('meta', {}).get('severity', 'medium')
            if severity == 'critical':
                score += 30  # Increased from 20
            # ... etc
    
    # Custom logic
    if analysis_results.get('cuckoo_iocs'):
        network_iocs = analysis_results['cuckoo_iocs'].get('ips', [])
        if len(network_iocs) > 5:
            score += 20  # Heavy network activity
    
    return min(score, 100)
```

### Database Queries

```sql
-- Find all samples with high risk scores
SELECT filename, md5, risk_score, first_seen 
FROM samples 
WHERE risk_score >= 75 
ORDER BY risk_score DESC;

-- Find samples sharing IOCs
SELECT s1.filename, s2.filename, i.value, i.type
FROM samples s1
JOIN iocs i ON s1.md5 = i.sample_md5
JOIN iocs i2 ON i.value = i2.value AND i.type = i2.type
JOIN samples s2 ON i2.sample_md5 = s2.md5
WHERE s1.md5 < s2.md5  -- Avoid duplicates
ORDER BY i.value;

-- Timeline of malware samples
SELECT date(first_seen) as day, COUNT(*) as count, AVG(risk_score) as avg_risk
FROM samples
GROUP BY day
ORDER BY day DESC;

-- Most common IOC domains
SELECT value, COUNT(DISTINCT sample_md5) as sample_count
FROM iocs
WHERE type = 'domains'
GROUP BY value
ORDER BY sample_count DESC
LIMIT 20;

-- YARA rule effectiveness
SELECT rule_name, COUNT(*) as match_count
FROM yara_matches
GROUP BY rule_name
ORDER BY match_count DESC;
```

### Scripting Integration

```python
#!/usr/bin/env python3
# custom_pipeline.py - Custom analysis pipeline

import subprocess
import json
import sys

def analyze_sample(file_path):
    """Run mal.py and return parsed results"""
    result = subprocess.run(
        ['python', 'mal.py', file_path, '--json', '/tmp/result.json', '--no-db'],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"Analysis failed: {result.stderr}", file=sys.stderr)
        return None
    
    with open('/tmp/result.json') as f:
        return json.load(f)

def main():
    sample = sys.argv[1]
    data = analyze_sample(sample)
    
    if data:
        risk = data['analysis']['risk_score']
        
        # Custom logic
        if risk >= 75:
            # Auto-quarantine
            subprocess.run(['mv', sample, '/quarantine/'])
            
            # Alert SIEM
            alert = {
                'severity': 'critical',
                'sample_md5': data['sample']['md5'],
                'risk_score': risk,
                'iocs': data['analysis']['iocs']
            }
            # Send to SIEM (pseudo-code)
            # send_to_siem(alert)
            
            print(f"[ALERT] High-risk sample quarantined: {sample}")
        else:
            print(f"[INFO] Sample appears benign (risk: {risk}/100)")

if __name__ == '__main__':
    main()
```

---

## Troubleshooting Examples

### Issue: Cuckoo Connection Timeout

```bash
# Test Cuckoo connectivity
curl http://127.0.0.1:8090/cuckoo/status

# If timeout, check Cuckoo service
systemctl status cuckoo

# If Cuckoo is running, check firewall
sudo iptables -L -n | grep 8090

# Run analysis with verbose logging
python mal.py sample.exe --cuckoo http://127.0.0.1:8090 --verbose
```

### Issue: Out of Memory

```bash
# Check file size first
ls -lh large_sample.bin

# If > 1GB, process may take time but should work
# Monitor memory usage in another terminal
watch -n 1 'ps aux | grep python | grep mal.py'

# If still OOM, reduce max_strings
# Edit mal.py line ~320:
# def extract_strings(file_path, min_length=4, max_strings=500):  # Reduced from 1000
```

### Issue: YARA Rules Not Loading

```bash
# Check rule syntax
yara -C custom_rules.yar

# If errors, fix them, then:
python mal.py sample.exe --yara custom_rules.yar --verbose

# Check the verbose output for detailed YARA errors
```

---

## Production Deployment Example

```bash
#!/bin/bash
# deploy_mal_tool.sh - Production deployment

set -euo pipefail

# Configuration
INSTALL_DIR="/opt/malware_analysis"
VENV="$INSTALL_DIR/venv"
DB_PATH="/var/lib/malware_analysis/samples.db"

# Create directories
sudo mkdir -p "$INSTALL_DIR"
sudo mkdir -p "/var/lib/malware_analysis"
sudo mkdir -p "/var/log/malware_analysis"

# Copy tool
sudo cp mal.py "$INSTALL_DIR/"
sudo cp requirements.txt "$INSTALL_DIR/"

# Create virtual environment
cd "$INSTALL_DIR"
sudo python3 -m venv "$VENV"
sudo "$VENV/bin/pip" install -r requirements.txt

# Create systemd service (for automated processing)
sudo tee /etc/systemd/system/malware-watcher.service > /dev/null <<EOF
[Unit]
Description=Malware Analysis Watcher
After=network.target

[Service]
Type=simple
ExecStart=$VENV/bin/python $INSTALL_DIR/mal.py
Restart=always
User=malware-analyst
Group=malware-analyst

[Install]
WantedBy=multi-user.target
EOF

# Set permissions
sudo chown -R malware-analyst:malware-analyst "$INSTALL_DIR"
sudo chmod 700 "$INSTALL_DIR"

# Start service
sudo systemctl daemon-reload
sudo systemctl enable malware-watcher
sudo systemctl start malware-watcher

echo "Deployment complete!"
```

---

**Last Updated**: October 26, 2025
