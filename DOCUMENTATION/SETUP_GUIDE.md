# Malware Analysis Tool - Setup Guide

## Overview

This is a comprehensive, self-contained malware analysis triage tool that performs static and dynamic analysis **without relying on external APIs**. All analysis is done locally.

## ⚠️ CRITICAL SAFETY WARNINGS

**DO NOT use this tool on your primary workstation!**

### Required Safety Measures:

1. **Isolated Network Environment**
   - Use air-gapped systems or host-only VM networks
   - Block all outbound internet access by default
   - Never analyze malware on systems connected to production networks

2. **Use Disposable Virtual Machines**
   - VMware Workstation/Player, VirtualBox, or QEMU
   - Take snapshots before each analysis
   - Revert to clean snapshot after each run
   - Use unique MAC addresses per analysis session

3. **Dedicated Analysis Systems**
   - Windows 7/10/11 or Linux VMs specifically for malware analysis
   - No personal data or credentials on analysis VMs
   - Separate physical hardware if possible

4. **Legal Compliance**
   - Only analyze samples you legally own or have permission to analyze
   - Maintain chain-of-custody documentation
   - Follow your organization's incident response procedures

## Installation

### Prerequisites

**Python 3.8 or higher required**

### Core Dependencies

```bash
# Install via pip
pip install pefile yara-python requests

# Or use requirements.txt (create this file)
pip install -r requirements.txt
```

### Optional but Recommended Tools

#### For Windows Analysis:
- **FLARE VM** - Complete Windows malware analysis environment
- **Sysinternals Suite** - Process monitoring and analysis tools
- **Wireshark** - Network traffic capture and analysis

#### For Linux Analysis:
- **REMnux** - Linux malware analysis toolkit
- **Volatility3** - Memory forensics
- **binwalk** - Firmware and binary analysis

#### For Dynamic Analysis:
- **Cuckoo Sandbox** - Automated malware analysis system (self-hosted)
  ```bash
  # Installation varies - see: https://cuckoo.sh/docs/
  # Requires separate VM setup
  ```

## Configuration

### 1. Basic Configuration

The tool works out of the box with minimal configuration:

```bash
# Run with default settings
python mal.py sample.exe
```

### 2. Database Setup

By default, creates `malware_analysis.db` in the current directory:

```bash
# Use custom database location
python mal.py sample.exe --db-path /path/to/custom.db
```

### 3. YARA Rules

The tool includes embedded YARA rules, but you can provide custom rules:

```bash
# Download community rules
git clone https://github.com/Yara-Rules/rules.git yara-rules

# Use custom rules
python mal.py sample.exe --yara yara-rules/malware/APT_*.yar
```

### 4. Cuckoo Sandbox Integration (Optional)

If you have a local Cuckoo instance:

```bash
# Submit to Cuckoo for dynamic analysis
python mal.py sample.exe --cuckoo http://127.0.0.1:8090
```

**Important**: Ensure Cuckoo is properly isolated and configured!

## Directory Structure

```
mal/
├── mal.py                      # Main analysis tool
├── malware_analysis.db         # SQLite database (auto-created)
├── reports/                    # Analysis reports (auto-created)
│   ├── report_<md5>_<timestamp>.md
│   └── ...
├── yara-rules/                 # Optional: Custom YARA rules
└── samples/                    # Optional: Quarantine directory
```

## Testing the Installation

### 1. Create a Test File

```bash
# Create a harmless test file (Windows)
echo "This is a test file" > test.txt

# Run analysis
python mal.py test.txt --verbose
```

### 2. Expected Output

You should see:

- ✓ Hash computation (MD5, SHA1, SHA256)
- ✓ File type detection
- ✓ String extraction
- ✓ IOC extraction
- ✓ YARA scanning
- ✓ Report generation
- ✓ Database storage

### 3. Verify Database

```bash
# Check database was created
sqlite3 malware_analysis.db "SELECT filename, md5, file_type FROM samples;"
```

## Next Steps

1. Read `WORKFLOW_GUIDE.md` for analysis workflow
2. Review `FEATURES.md` for detailed feature documentation
3. Check `SAFETY_PROCEDURES.md` for handling procedures
4. See `EXAMPLES.md` for usage examples

## Troubleshooting

### "pefile not installed"
```bash
pip install pefile
```

### "yara-python not installed"
```bash
pip install yara-python

# On some systems:
pip install yara-python-devel
```

### "requests not installed"
```bash
pip install requests
```

### Permission Errors
```bash
# Run with appropriate permissions
# On Linux/Mac:
chmod +x mal.py
python3 mal.py sample.exe

# On Windows: Run PowerShell as Administrator if needed
```

### Database Locked Errors
```bash
# The tool uses WAL mode for concurrent access
# If you see locks, check for other processes accessing the DB

# Reset database
rm malware_analysis.db
python mal.py sample.exe  # Will recreate DB
```

## System Requirements

### Minimum:
- Python 3.8+
- 2 GB RAM
- 1 GB free disk space

### Recommended:
- Python 3.10+
- 8 GB RAM (for large samples and Cuckoo)
- 20 GB free disk space
- SSD for database performance

## Security Hardening

1. **File Permissions**: Restrict access to the database and reports
   ```bash
   chmod 600 malware_analysis.db
   chmod 700 reports/
   ```

2. **Network Isolation**: Use VM host-only networks
   ```bash
   # VMware: Configure host-only adapter
   # VirtualBox: Use "Host-only Adapter" in network settings
   ```

3. **Process Isolation**: Run in containers if possible
   ```bash
   # Example using Docker (advanced)
   docker run --rm -it --network none -v $(pwd):/work python:3.10 \
       bash -c "cd /work && pip install -r requirements.txt && python mal.py sample.exe"
   ```

## License & Disclaimer

**FOR EDUCATIONAL AND DEFENSIVE SECURITY PURPOSES ONLY**

This tool is provided as-is with no warranty. The author is not responsible for any misuse or damage caused by this tool. Always follow applicable laws and obtain proper authorization before analyzing any files.

---

**Last Updated**: October 26, 2025
