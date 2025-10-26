# Malware Analysis Workflow Guide

## Analysis Workflow Overview

This document describes the complete triage workflow implemented by the tool, from sample intake to final report generation.

## Complete Analysis Pipeline

```
Sample Intake
    ↓
Hash Computation & Metadata
    ↓
String Extraction (Streaming)
    ↓
IOC Pattern Matching
    ↓
File Type Specific Analysis (PE, ELF, etc.)
    ↓
YARA Rule Scanning
    ↓
Dynamic Analysis (Optional: Cuckoo)
    ↓
Risk Score Calculation
    ↓
Report Generation & Storage
```

## Step-by-Step Workflow

### Step 1: Sample Intake & Metadata Collection

**What happens:**
- File is loaded and basic metadata extracted
- Multiple hash algorithms computed (MD5, SHA1, SHA256)
- File size and type detection
- Sample record created in database

**Why it matters:**
- Hashes are used for deduplication and correlation
- Metadata helps with timeline analysis
- File type determines which analysis modules run

**Command:**
```bash
python mal.py sample.exe
```

**Output:**
```
[INFO] Step 1: Computing hashes and metadata...
    MD5:    5d41402abc4b2a76b9719d911017c592
    SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706...
    Type:   PE/DOS Executable
```

### Step 2: String Extraction (Memory-Efficient Streaming)

**What happens:**
- File is processed in chunks (default: 64 KB) to avoid memory exhaustion
- ASCII strings extracted (printable characters, configurable minimum length)
- UTF-16 LE Unicode strings extracted
- Overlap buffer maintained to catch strings spanning chunk boundaries

**Why it matters:**
- Strings often reveal:
  - URLs, domains, IP addresses (C2 infrastructure)
  - File paths (persistence locations)
  - Registry keys (persistence mechanisms)
  - Error messages (functionality clues)
  - Embedded credentials
  - Debug strings (development artifacts)

**Technical improvement over naive approach:**
- **Old approach**: Load entire file into memory → OOM on large files
- **New approach**: Stream processing with overlap → handles multi-GB files safely

**Command:**
```bash
python mal.py sample.exe --verbose
```

**Output:**
```
[INFO] Step 2: Extracting strings (streaming mode)...
    ASCII strings: 847
    Unicode strings: 132
```

### Step 3: IOC Extraction & Pattern Matching

**What happens:**
- Regex patterns applied to extracted strings
- Multiple IOC types identified:
  - **URLs**: HTTP/HTTPS endpoints (download sites, C2 servers)
  - **IP Addresses**: Network destinations (validated, private IPs filtered)
  - **Domains**: DNS names (normalized: lowercase, port removed)
  - **Email Addresses**: Contact info or C2 channels
  - **Registry Keys**: Persistence mechanisms
  - **File Paths**: Dropped files, target directories
  - **Base64 Strings**: Encoded payloads or configuration

**Normalization applied:**
- Domains: lowercase, trailing dots removed, ports stripped
- IPs: Private/loopback/multicast/reserved filtered out
- URLs: Trailing punctuation removed
- Deduplication: Sets converted to sorted lists

**Why it matters:**
- IOCs are **actionable intelligence** for defenders
- Can be added to firewalls, IDS/IPS, SIEM systems
- Enable threat hunting and correlation across incidents

**Database storage:**
- Each IOC stored with type, value, source (static/cuckoo), timestamp
- Linked to sample via MD5 hash

**Output:**
```
[INFO] Step 3: Extracting IOCs from strings...
    urls: 5
    ips: 3
    domains: 7
    registry_keys: 12
    file_paths: 8
```

### Step 4: File Format Specific Analysis

#### 4a. PE (Windows Executable) Analysis

**What happens:**
- PE header parsed (machine type, timestamp, characteristics)
- Sections analyzed (name, size, virtual address, **entropy**)
- Import table extracted (DLLs and functions)
- Export table extracted (if DLL)
- Resources enumerated
- Suspicious patterns flagged:
  - High entropy sections (> 7.0) → packing/encryption
  - Suspicious API imports (VirtualAlloc, WriteProcessMemory, etc.)
  - Invalid/zero timestamps → timestomping

**Timestamp handling (improved):**
- Validates timestamp is in reasonable range
- Catches overflow/underflow errors
- Flags invalid timestamps as suspicious

**Why it matters:**
- **Imports reveal functionality**:
  - `VirtualAlloc` + `VirtualProtect` → code injection
  - `InternetOpen` + `InternetReadFile` → network downloader
  - `CreateRemoteThread` → process injection
  - `RegSetValue` → persistence via registry

- **High entropy sections**:
  - Entropy > 7.0 typically indicates compression or encryption
  - Packed malware hides true functionality
  - Requires unpacking for deeper analysis

- **Compile timestamp**:
  - Can correlate campaigns by build date
  - Timestomping (zeros or future dates) is suspicious

**Output:**
```
[INFO] Step 4: Analyzing PE structure...
    Sections: 5
    Imports: 3
    Suspicious flags: 2
      - High entropy in section .rsrc: 7.92
      - Suspicious import: KERNEL32.dll!VirtualAllocEx
```

#### 4b. Future: ELF, Mach-O, PDF, Office Docs

Currently focused on PE, but architecture supports:
- ELF analysis (Linux binaries)
- Mach-O analysis (macOS binaries)
- PDF parsing (embedded JavaScript, exploits)
- Office document macros (VBA analysis)

### Step 5: YARA Rule Scanning

**What happens:**
- YARA rules compiled (either custom or embedded defaults)
- Rules matched against sample
- Matches include:
  - Rule name
  - Severity (from metadata)
  - Description
  - Matched strings and their offsets

**Embedded YARA Rules:**
1. **Suspicious_URL_Strings**: HTTP/HTTPS + download/exe patterns
2. **Suspicious_Registry**: Registry manipulation APIs
3. **Packer_Indicators**: UPX, ASPack, PECompact signatures
4. **Suspicious_Network**: Internet APIs (URLDownloadToFile, etc.)
5. **Process_Injection**: Code injection techniques
6. **Ransomware_Indicators**: Encryption, bitcoin, ransom keywords
7. **Keylogger_Indicators**: GetAsyncKeyState, SetWindowsHookEx
8. **Credential_Theft**: Password, SAM, mimikatz references
9. **Anti_Analysis**: VM detection, debugger checks

**Match sanitization (new):**
- Matched strings truncated to 200 chars to prevent DB bloat
- Binary data decoded safely with error handling
- Metadata validated as serializable (str/int/float/bool only)

**Why it matters:**
- YARA is **industry standard** for malware classification
- Rules encode expert knowledge about malware families
- Can detect specific APT campaigns, ransomware variants, etc.

**Output:**
```
[INFO] Step 5: Running YARA rules...
    Matches: 3
      - Process_Injection (severity: critical)
      - Suspicious_Network (severity: high)
      - Anti_Analysis (severity: high)
```

### Step 6: Dynamic Analysis (Optional - Cuckoo Sandbox)

**What happens:**
- Sample submitted to local Cuckoo sandbox via REST API
- Task ID returned
- Polling with **exponential backoff** (improved):
  - Initial interval: 5 seconds
  - Backoff on errors: 5s → 10s → 20s → 30s (max)
  - Timeout: 300 seconds (5 minutes) default
- Report fetched when status == "reported"
- IOCs extracted from report:
  - Network connections (TCP/UDP/HTTP/DNS)
  - Mutexes created
  - Files dropped
  - Registry modifications
  - Processes spawned

**Improvements over original:**
- HTTP errors handled gracefully (timeouts, connection errors)
- JSON parsing errors caught (non-JSON responses)
- Exponential backoff reduces server load during long analyses
- Detailed logging of task status

**Why it matters:**
- Static analysis can be evaded (packing, obfuscation)
- Dynamic analysis observes **actual behavior** in controlled VM
- Reveals:
  - True network destinations (even if encrypted/encoded in binary)
  - Persistence mechanisms activated at runtime
  - Lateral movement attempts
  - Data exfiltration

**Safety reminder:**
- Cuckoo VMs must be **isolated** (no internet access or use honeypot network)
- Use disposable VMs with snapshots
- Never run Cuckoo on systems with access to production networks

**Output:**
```
[INFO] Step 6: Submitting to Cuckoo sandbox...
    This may take several minutes...
[INFO] Cuckoo task submitted: 42
[DEBUG] Cuckoo task 42 status: pending
[DEBUG] Cuckoo task 42 status: running
[DEBUG] Cuckoo task 42 status: reported
[INFO] Analysis complete (Task ID: 42)
```

### Step 7: Risk Score Calculation

**What happens:**
- Weighted scoring algorithm applied:
  - **YARA matches**: Critical +20, High +15, Medium +10, Low +5
  - **PE suspicious flags**: +5 each (max +20)
  - **IOC count**: URLs +3 each (max +15), IPs +3 each (max +15), Registry keys +2 each (max +10)
  - **High entropy sections**: +5 each (max +15)
- Score capped at 100

**Risk levels:**
- **0-49**: 🟢 LOW RISK - Likely benign or low-threat
- **50-74**: 🟡 MEDIUM RISK - Suspicious, requires investigation
- **75-100**: 🔴 HIGH RISK - Likely malicious, immediate action required

**Why it matters:**
- Provides quick triage decision for analysts
- Prioritizes high-risk samples for manual analysis
- Can automate initial response (e.g., quarantine if score > 75)

**Output:**
```
[INFO] Step 7: Calculating risk score...
    Risk Score: 65/100
    Assessment: 🟡 MEDIUM RISK
```

### Step 8: Report Generation & Storage

**What happens:**
- Markdown report generated with:
  - Sample metadata (hashes, size, type, risk score)
  - YARA detections with severity
  - IOCs organized by type (URLs, IPs, domains, etc.)
  - PE analysis details (sections, entropy, imports)
  - Recommended actions based on risk level
- Report saved to `reports/report_<md5>_<timestamp>.md`
- Full analysis JSON stored in SQLite database
- JSON output option (`--json`) for automation/SIEM integration

**Database schema:**
- **samples**: Metadata, hashes, risk score
- **iocs**: Type-value pairs linked to samples
- **yara_matches**: Rule matches with metadata
- **reports**: Full analysis JSON for historical queries

**Why it matters:**
- **Markdown reports**: Human-readable for analysts
- **JSON storage**: Machine-readable for automation, correlation, SIEM
- **Database**: Historical analysis, trend detection, IOC correlation

**Output:**
```
[INFO] Step 8: Generating report...
    Report saved: reports/report_5d41402abc4b2a76b9719d911017c592_20251026_143022.md
```

## Workflow Variations

### Quick Triage (No DB, No Cuckoo)
```bash
python mal.py sample.exe --no-db
```
- Fastest option
- Report generated, no persistence
- Use for one-off analysis

### Full Analysis with Custom YARA
```bash
python mal.py sample.exe --yara custom_rules.yar --verbose
```
- Uses your ruleset
- Verbose logging for debugging
- Database storage enabled

### Automated Batch Processing
```bash
#!/bin/bash
for file in samples/*.exe; do
    python mal.py "$file" --json "results/$(basename $file).json"
done
```
- Process multiple samples
- JSON output for aggregation
- Scriptable workflow

### Deep Analysis with Cuckoo
```bash
python mal.py sample.exe --cuckoo http://127.0.0.1:8090 --verbose
```
- Full static + dynamic analysis
- Extended timeout for complex samples
- Maximum intelligence gathering

## Best Practices

### 1. Sample Handling
- **Quarantine**: Store samples in password-protected archives (`.zip` with password)
- **Naming**: Use hash as filename (`5d41402abc4b2a76b9719d911017c592.bin`)
- **Metadata**: Document source, date collected, incident ID

### 2. Analysis Environment
- **Snapshots**: Revert VM after each analysis
- **Network**: Host-only or controlled honeypot network
- **Monitoring**: Log all VM activity (process, network, file)

### 3. IOC Management
- **Validation**: Verify IOCs before blocking (avoid false positives)
- **Context**: Always include sample hash with IOC reports
- **Timeliness**: Act on high-risk IOCs within 1 hour

### 4. Reporting
- **Chain of Custody**: Document who analyzed, when, why
- **Peer Review**: Have critical findings reviewed by second analyst
- **Retention**: Keep reports for compliance (typically 7 years)

## Troubleshooting Common Issues

### Sample Won't Analyze
- Check file exists and is readable
- Verify file type supported
- Try `--verbose` for detailed errors

### Cuckoo Times Out
- Increase timeout: Edit `cuckoo_submit_and_wait()` timeout parameter
- Check Cuckoo VM is running
- Verify network connectivity to Cuckoo API

### Database Locked
- Close other processes accessing DB
- WAL mode should handle concurrency
- As last resort: delete DB and re-run

### High Memory Usage
- Streaming strings should prevent this
- Check sample size (multi-GB files need more RAM)
- Reduce `max_strings` parameter in `extract_strings()`

## Next Steps

- Review `SAFETY_PROCEDURES.md` for safe handling guidelines
- See `FEATURES.md` for detailed feature documentation
- Check `EXAMPLES.md` for real-world usage scenarios
- Read `IMPROVEMENTS.md` for recent code improvements

---

**Last Updated**: October 26, 2025
