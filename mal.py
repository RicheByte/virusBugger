#!/usr/bin/env python3
"""
Malware Analysis Triage Tool (MAL)
==================================
A comprehensive, self-contained malware analysis tool for static and dynamic analysis.
NO external APIs required - all analysis is done locally.

WARNING: Only analyze malware in isolated, controlled environments!
"""

import os
import sys
import hashlib
import sqlite3
import json
import argparse
import subprocess
import re
import struct
import time
import logging
from datetime import datetime
from pathlib import Path
from collections import defaultdict
import ipaddress

# Optional imports with graceful fallback
try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging(verbose=False):
    """Configure logging"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='[%(levelname)s] %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

logger = logging.getLogger(__name__)


# ============================================================================
# DATABASE SETUP
# ============================================================================

class AnalysisDB:
    """SQLite database for storing samples and IOCs"""
    
    def __init__(self, db_path="malware_analysis.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database schema with WAL mode for concurrent access"""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # Samples table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT,
                filepath TEXT,
                md5 TEXT UNIQUE,
                sha1 TEXT,
                sha256 TEXT,
                size INTEGER,
                file_type TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                source TEXT,
                risk_score INTEGER DEFAULT 0,
                tags TEXT,
                notes TEXT
            )
        """)
        
        # IOCs table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_md5 TEXT,
                type TEXT,
                value TEXT,
                source TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                tags TEXT,
                FOREIGN KEY (sample_md5) REFERENCES samples(md5)
            )
        """)
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_ioc_type_value ON iocs(type, value)")
        
        # YARA matches table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS yara_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_md5 TEXT,
                rule_name TEXT,
                namespace TEXT,
                tags TEXT,
                meta TEXT,
                matched_strings TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sample_md5) REFERENCES samples(md5)
            )
        """)
        
        # Analysis reports table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_md5 TEXT,
                report_type TEXT,
                report_data TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sample_md5) REFERENCES samples(md5)
            )
        """)
        
        conn.commit()
        conn.close()
    
    def insert_sample(self, sample_data):
        """Insert or update sample record using proper UPSERT"""
        with sqlite3.connect(self.db_path, timeout=30) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            try:
                cur.execute("""
                    INSERT INTO samples (filename, filepath, md5, sha1, sha256, size, file_type, source, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(md5) DO UPDATE SET
                      filename=excluded.filename,
                      filepath=excluded.filepath,
                      sha1=excluded.sha1,
                      sha256=excluded.sha256,
                      size=excluded.size,
                      file_type=excluded.file_type,
                      source=excluded.source,
                      tags=excluded.tags
                """, (
                    sample_data['filename'],
                    sample_data['filepath'],
                    sample_data['md5'],
                    sample_data['sha1'],
                    sample_data['sha256'],
                    sample_data['size'],
                    sample_data.get('file_type', 'unknown'),
                    sample_data.get('source', 'manual'),
                    sample_data.get('tags', '')
                ))
                conn.commit()
                return cur.lastrowid
            except Exception as e:
                logger.error(f"Failed to insert sample: {e}")
                raise
    
    def insert_ioc(self, sample_md5, ioc_type, value, source="static", tag=None):
        """Insert IOC record with proper error handling"""
        with sqlite3.connect(self.db_path, timeout=30) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            try:
                cur.execute("""
                    INSERT OR IGNORE INTO iocs (sample_md5, type, value, source, tags)
                    VALUES (?, ?, ?, ?, ?)
                """, (sample_md5, ioc_type, value, source, tag or ''))
                conn.commit()
            except Exception as e:
                logger.error(f"Failed to insert IOC: {e}")
    
    def insert_yara_match(self, sample_md5, match_data):
        """Insert YARA match record with sanitized data"""
        with sqlite3.connect(self.db_path, timeout=30) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            try:
                cur.execute("""
                    INSERT INTO yara_matches 
                    (sample_md5, rule_name, namespace, tags, meta, matched_strings)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    sample_md5,
                    match_data['rule'],
                    match_data.get('namespace', ''),
                    json.dumps(match_data.get('tags', [])),
                    json.dumps(match_data.get('meta', {})),
                    json.dumps(match_data.get('strings', []))
                ))
                conn.commit()
            except Exception as e:
                logger.error(f"Failed to insert YARA match: {e}")
    
    def save_report(self, sample_md5, report_type, report_data):
        """Save analysis report"""
        with sqlite3.connect(self.db_path, timeout=30) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            try:
                cur.execute("""
                    INSERT INTO reports (sample_md5, report_type, report_data)
                    VALUES (?, ?, ?)
                """, (sample_md5, report_type, json.dumps(report_data, indent=2)))
                conn.commit()
            except Exception as e:
                logger.error(f"Failed to save report: {e}")
    
    def get_sample_by_hash(self, hash_value):
        """Get sample by any hash"""
        with sqlite3.connect(self.db_path, timeout=30) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            try:
                cur.execute("""
                    SELECT * FROM samples 
                    WHERE md5=? OR sha1=? OR sha256=?
                """, (hash_value, hash_value, hash_value))
                row = cur.fetchone()
                if row:
                    return dict(row)
                return None
            except Exception as e:
                logger.error(f"Failed to get sample: {e}")
                return None
    
    def get_iocs_for_sample(self, sample_md5):
        """Get all IOCs for a sample"""
        with sqlite3.connect(self.db_path, timeout=30) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            try:
                cur.execute("SELECT * FROM iocs WHERE sample_md5=?", (sample_md5,))
                rows = cur.fetchall()
                return [dict(row) for row in rows]
            except Exception as e:
                logger.error(f"Failed to get IOCs: {e}")
                return []


# ============================================================================
# HASH COMPUTATION
# ============================================================================

def compute_hashes(file_path):
    """Compute MD5, SHA1, SHA256 hashes of file"""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
    except Exception as e:
        return {"error": str(e)}
    
    return {
        'md5': md5.hexdigest(),
        'sha1': sha1.hexdigest(),
        'sha256': sha256.hexdigest()
    }


# ============================================================================
# STATIC ANALYSIS - FILE TYPE DETECTION
# ============================================================================

def detect_file_type(file_path):
    """Detect file type using magic bytes"""
    signatures = {
        b'MZ': 'PE/DOS Executable',
        b'\x7fELF': 'ELF Executable',
        b'\xca\xfe\xba\xbe': 'Mach-O Binary',
        b'PK\x03\x04': 'ZIP Archive',
        b'Rar!\x1a\x07': 'RAR Archive',
        b'\x1f\x8b': 'GZIP Archive',
        b'%PDF': 'PDF Document',
        b'\xd0\xcf\x11\xe0': 'Microsoft Office Document',
        b'PK\x03\x04\x14\x00\x06\x00': 'Office Open XML',
    }
    
    try:
        with open(file_path, 'rb') as f:
            header = f.read(8)
            for sig, ftype in signatures.items():
                if header.startswith(sig):
                    return ftype
    except Exception as e:
        return f"Error: {e}"
    
    return "Unknown"


# ============================================================================
# STATIC ANALYSIS - STRINGS EXTRACTION (MEMORY-EFFICIENT STREAMING)
# ============================================================================

def extract_strings(file_path, min_length=4, max_strings=1000, chunk_size=65536):
    """Extract ASCII and Unicode strings from file using streaming to avoid memory issues"""
    ascii_strings = []
    unicode_strings = []
    buf = b""
    
    ascii_re = re.compile(rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}')
    uni_re = re.compile(rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}')
    
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                buf += chunk
                # Keep overlap to catch strings split across chunks
                scan_buf = buf if len(buf) <= chunk_size * 2 else buf[-chunk_size*2:]
                
                # ASCII strings
                for m in ascii_re.finditer(scan_buf):
                    try:
                        s = m.group().decode('ascii', errors='ignore')
                        if s not in ascii_strings:  # Avoid duplicates
                            ascii_strings.append(s)
                        if len(ascii_strings) >= max_strings:
                            return {
                                'ascii': ascii_strings,
                                'unicode': unicode_strings,
                                'total_ascii': len(ascii_strings),
                                'total_unicode': len(unicode_strings)
                            }
                    except Exception:
                        continue
                
                # Unicode strings (UTF-16 LE)
                for m in uni_re.finditer(scan_buf):
                    try:
                        s = m.group().decode('utf-16-le', errors='ignore')
                        if s not in unicode_strings:  # Avoid duplicates
                            unicode_strings.append(s)
                        if len(unicode_strings) >= max_strings // 2:
                            return {
                                'ascii': ascii_strings,
                                'unicode': unicode_strings,
                                'total_ascii': len(ascii_strings),
                                'total_unicode': len(unicode_strings)
                            }
                    except Exception:
                        continue
                
                # Drop older bytes but keep overlap for strings that span chunks
                if len(buf) > chunk_size * 3:
                    buf = buf[-chunk_size*2:]
    
    except Exception as e:
        logger.error(f"String extraction error: {e}")
        return {"error": str(e)}
    
    return {
        'ascii': ascii_strings,
        'unicode': unicode_strings,
        'total_ascii': len(ascii_strings),
        'total_unicode': len(unicode_strings)
    }


# ============================================================================
# STATIC ANALYSIS - SUSPICIOUS PATTERNS (WITH NORMALIZATION)
# ============================================================================

def normalize_domain(domain):
    """Normalize domain name"""
    try:
        # Convert to lowercase and strip trailing dots
        domain = domain.lower().rstrip('.')
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        # Basic validation - must have at least one dot and valid characters
        if '.' in domain and re.match(r'^[a-z0-9.-]+$', domain):
            return domain
    except Exception:
        pass
    return None

def normalize_ip(ip_str):
    """Validate and normalize IP address"""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Exclude private, loopback, multicast, reserved
        if not (ip.is_private or ip.is_loopback or ip.is_multicast or 
                ip.is_reserved or ip.is_link_local):
            return str(ip)
    except Exception:
        pass
    return None

def find_suspicious_patterns(strings_data):
    """Find suspicious patterns in strings (URLs, IPs, emails, registry keys) with normalization"""
    patterns = {
        'urls': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
        'ips': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        'emails': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'registry_keys': re.compile(r'HKEY_[A-Z_]+\\[^\s]+', re.IGNORECASE),
        'file_paths': re.compile(r'[A-Za-z]:\\(?:[^\s<>:"|?*]+\\)*[^\s<>:"|?*]+'),
        'domains': re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.IGNORECASE),
        'base64': re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
    }
    
    iocs = defaultdict(set)
    all_strings = strings_data.get('ascii', []) + strings_data.get('unicode', [])
    
    for string in all_strings:
        for pattern_name, pattern in patterns.items():
            matches = pattern.findall(string)
            for match in matches:
                if pattern_name == 'ips':
                    normalized = normalize_ip(match)
                    if normalized:
                        iocs[pattern_name].add(normalized)
                elif pattern_name == 'domains':
                    normalized = normalize_domain(match)
                    if normalized:
                        iocs[pattern_name].add(normalized)
                elif pattern_name == 'urls':
                    # Strip trailing punctuation from URLs
                    url = match.rstrip('.,;:)')
                    iocs[pattern_name].add(url)
                else:
                    iocs[pattern_name].add(match)
    
    # Convert sets to sorted lists
    result = {key: sorted(list(values)) for key, values in iocs.items()}
    return result


# ============================================================================
# STATIC ANALYSIS - PE FILE ANALYSIS
# ============================================================================

def analyze_pe_file(file_path):
    """Analyze PE file structure and extract metadata"""
    if not HAS_PEFILE:
        return {"error": "pefile not installed"}
    
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        return {"error": f"Not a valid PE file: {e}"}
    
    result = {
        'machine': pe.FILE_HEADER.Machine,
        'timestamp': 'Unknown',
        'characteristics': pe.FILE_HEADER.Characteristics,
        'subsystem': pe.OPTIONAL_HEADER.Subsystem,
        'dll_characteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
        'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
        'sections': [],
        'imports': [],
        'exports': [],
        'resources': [],
        'suspicious_flags': []
    }
    
    # Safely parse timestamp
    try:
        timestamp = pe.FILE_HEADER.TimeDateStamp
        if timestamp > 0 and timestamp < 0xFFFFFFFF:
            result['timestamp'] = datetime.fromtimestamp(timestamp).isoformat()
        else:
            result['suspicious_flags'].append(f"Invalid PE timestamp: {timestamp}")
    except Exception as e:
        logger.warning(f"Could not parse PE timestamp: {e}")
        result['timestamp'] = 'Invalid'
    
    # Sections
    for section in pe.sections:
        result['sections'].append({
            'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
            'virtual_address': hex(section.VirtualAddress),
            'virtual_size': section.Misc_VirtualSize,
            'raw_size': section.SizeOfRawData,
            'entropy': section.get_entropy(),
            'characteristics': section.Characteristics
        })
        
        # Check for suspicious entropy (packed/encrypted)
        if section.get_entropy() > 7.0:
            result['suspicious_flags'].append(
                f"High entropy in section {section.Name.decode('utf-8', errors='ignore').strip('\x00')}: "
                f"{section.get_entropy():.2f}"
            )
    
    # Imports
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore')
            imports = []
            for imp in entry.imports:
                if imp.name:
                    imports.append(imp.name.decode('utf-8', errors='ignore'))
            result['imports'].append({
                'dll': dll_name,
                'functions': imports[:50]  # Limit to 50 per DLL
            })
    
    # Exports
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                result['exports'].append({
                    'name': exp.name.decode('utf-8', errors='ignore'),
                    'ordinal': exp.ordinal,
                    'address': hex(exp.address)
                })
    
    # Resources
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            result['resources'].append({
                                'type': resource_type.id,
                                'id': resource_id.id,
                                'lang': resource_lang.id,
                                'size': resource_lang.data.struct.Size
                            })
    
    # Check for suspicious imports
    suspicious_imports = [
        'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory', 'CreateRemoteThread',
        'LoadLibrary', 'GetProcAddress', 'WinExec', 'ShellExecute', 'URLDownloadToFile',
        'InternetOpen', 'InternetReadFile', 'CreateProcess', 'RegSetValue', 'RegCreateKey'
    ]
    
    for imp_dll in result['imports']:
        for func in imp_dll['functions']:
            if any(sus in func for sus in suspicious_imports):
                result['suspicious_flags'].append(f"Suspicious import: {imp_dll['dll']}!{func}")
    
    pe.close()
    return result


# ============================================================================
# YARA SCANNING
# ============================================================================

def sanitize_yara_match_for_db(match_data):
    """Sanitize YARA match data before storing in database"""
    max_str_len = 200
    clean_strings = []
    
    for item in match_data.get('strings', []):
        try:
            if len(item) >= 3:
                identifier, offset, matched_data = item[0], item[1], item[2]
                # Convert bytes to string safely
                if isinstance(matched_data, (bytes, bytearray)):
                    s_clean = matched_data.decode('utf-8', errors='ignore')
                else:
                    s_clean = str(matched_data)
                
                # Truncate long strings
                if len(s_clean) > max_str_len:
                    s_clean = s_clean[:max_str_len] + "...[truncated]"
                
                clean_strings.append((identifier, offset, s_clean))
        except Exception as e:
            logger.warning(f"Failed to sanitize YARA string: {e}")
            clean_strings.append(("<error>", 0, "<unprintable>"))
    
    # Sanitize metadata - ensure serializable types only
    meta = {}
    for k, v in match_data.get('meta', {}).items():
        if isinstance(v, (str, int, float, bool)):
            meta[k] = v
        else:
            meta[k] = str(v)
    
    return {
        'rule': match_data['rule'],
        'namespace': match_data.get('namespace', ''),
        'tags': match_data.get('tags', []),
        'meta': meta,
        'strings': clean_strings
    }

def run_yara_scan(file_path, rules_path=None):
    """Run YARA rules against file"""
    if not HAS_YARA:
        return {"error": "yara-python not installed"}
    
    if not rules_path or not os.path.exists(rules_path):
        # Use embedded default rules
        return run_default_yara_rules(file_path)
    
    try:
        rules = yara.compile(filepath=rules_path)
        matches = rules.match(file_path)
        
        results = []
        for match in matches:
            results.append({
                'rule': match.rule,
                'namespace': match.namespace,
                'tags': match.tags,
                'meta': match.meta,
                'strings': [(s[0], s[1], s[2][:100]) for s in match.strings]  # Limit string length
            })
        
        return results
    except Exception as e:
        logger.error(f"YARA scan error: {e}")
        return {"error": str(e)}


def run_default_yara_rules(file_path):
    """Run embedded YARA rules"""
    if not HAS_YARA:
        return {"error": "yara-python not installed"}
    
    # Embedded YARA rules
    default_rules = """
    rule Suspicious_URL_Strings {
        meta:
            description = "Detects suspicious URL patterns"
            severity = "medium"
        strings:
            $url_http = "http://" nocase
            $url_https = "https://" nocase
            $exe = ".exe" ascii
            $download = "download" nocase
        condition:
            (($url_http or $url_https) and ($exe or $download))
    }
    
    rule Suspicious_Registry {
        meta:
            description = "Detects registry manipulation"
            severity = "high"
        strings:
            $reg1 = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" nocase
            $reg2 = "RegSetValue" nocase
            $reg3 = "RegCreateKey" nocase
        condition:
            any of them
    }
    
    rule Packer_Indicators {
        meta:
            description = "Common packer indicators"
            severity = "medium"
        strings:
            $upx1 = "UPX0" ascii
            $upx2 = "UPX1" ascii
            $aspack = ".aspack" ascii
            $pecompact = "PECompact" ascii
        condition:
            any of them
    }
    
    rule Suspicious_Network {
        meta:
            description = "Network activity indicators"
            severity = "high"
        strings:
            $api1 = "InternetOpen" ascii
            $api2 = "InternetReadFile" ascii
            $api3 = "URLDownloadToFile" ascii
            $api4 = "HttpSendRequest" ascii
        condition:
            2 of them
    }
    
    rule Process_Injection {
        meta:
            description = "Process injection techniques"
            severity = "critical"
        strings:
            $api1 = "VirtualAllocEx" ascii
            $api2 = "WriteProcessMemory" ascii
            $api3 = "CreateRemoteThread" ascii
            $api4 = "NtUnmapViewOfSection" ascii
        condition:
            2 of them
    }
    
    rule Ransomware_Indicators {
        meta:
            description = "Potential ransomware behavior"
            severity = "critical"
        strings:
            $s1 = "encrypt" nocase
            $s2 = "bitcoin" nocase
            $s3 = "decrypt" nocase
            $s4 = ".locked" nocase
            $s5 = "ransom" nocase
            $s6 = "payment" nocase
        condition:
            3 of them
    }
    
    rule Keylogger_Indicators {
        meta:
            description = "Keylogger behavior"
            severity = "high"
        strings:
            $api1 = "GetAsyncKeyState" ascii
            $api2 = "SetWindowsHookEx" ascii
            $api3 = "GetForegroundWindow" ascii
        condition:
            2 of them
    }
    
    rule Credential_Theft {
        meta:
            description = "Credential stealing indicators"
            severity = "critical"
        strings:
            $s1 = "password" nocase
            $s2 = "credential" nocase
            $s3 = "mimikatz" nocase
            $s4 = "SAM" nocase
            $api1 = "LsaEnumerateLogonSessions" ascii
        condition:
            2 of them
    }
    
    rule Anti_Analysis {
        meta:
            description = "Anti-analysis techniques"
            severity = "high"
        strings:
            $vm1 = "VMware" nocase
            $vm2 = "VirtualBox" nocase
            $vm3 = "QEMU" nocase
            $dbg1 = "IsDebuggerPresent" ascii
            $dbg2 = "CheckRemoteDebuggerPresent" ascii
        condition:
            any of them
    }
    """
    
    try:
        rules = yara.compile(source=default_rules)
        matches = rules.match(file_path)
        
        results = []
        for match in matches:
            results.append({
                'rule': match.rule,
                'namespace': match.namespace,
                'tags': match.tags,
                'meta': match.meta,
                'strings': [(s[0], s[1], s[2][:100]) for s in match.strings]
            })
        
        return results
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# CUCKOO SANDBOX INTEGRATION (LOCAL)
# ============================================================================

def cuckoo_submit_and_wait(cuckoo_url, file_path, timeout=300, poll_interval=5):
    """Submit file to local Cuckoo sandbox and wait for results with exponential backoff"""
    if not HAS_REQUESTS:
        return {"error": "requests library not installed"}
    
    submit_url = f"{cuckoo_url}/tasks/create/file"
    
    try:
        with open(file_path, 'rb') as f:
            files = {"file": f}
            r = requests.post(submit_url, files=files, timeout=30)
            r.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"Cuckoo submit failed: {e}")
        return {"error": f"Submit failed: {e}"}
    except Exception as e:
        logger.error(f"Cuckoo submit error: {e}")
        return {"error": f"Submit error: {e}"}
    
    try:
        response_data = r.json()
    except ValueError as e:
        logger.error(f"Cuckoo returned non-JSON response: {r.text[:200]}")
        return {"error": f"Invalid JSON response: {e}"}
    
    task_id = response_data.get("task_id")
    if not task_id:
        return {"error": "No task_id returned"}
    
    logger.info(f"Cuckoo task submitted: {task_id}")
    
    # Poll for completion with exponential backoff
    status_url = f"{cuckoo_url}/tasks/view/{task_id}"
    start = time.time()
    attempt = 0
    
    while time.time() - start < timeout:
        try:
            s = requests.get(status_url, timeout=10)
            s.raise_for_status()
            s_json = s.json()
            status = s_json.get("task", {}).get("status")
            
            logger.debug(f"Cuckoo task {task_id} status: {status}")
            
            if status == "reported":
                # Fetch report
                report_url = f"{cuckoo_url}/tasks/report/{task_id}/json"
                rep = requests.get(report_url, timeout=20)
                rep.raise_for_status()
                return {"task_id": task_id, "report": rep.json()}
            elif status == "failed":
                logger.error(f"Cuckoo task {task_id} failed")
                return {"error": "Cuckoo analysis failed", "task_id": task_id}
        except requests.RequestException as e:
            logger.warning(f"Cuckoo poll request error (attempt {attempt}): {e}")
            attempt += 1
        except ValueError as e:
            logger.warning(f"Cuckoo poll JSON error (attempt {attempt}): {e}")
            attempt += 1
        except Exception as e:
            logger.error(f"Cuckoo poll unexpected error: {e}")
            return {"error": f"Poll error: {e}"}
        
        # Exponential backoff with max 30 seconds
        sleep_time = min(poll_interval * (2 ** min(attempt, 4)), 30)
        time.sleep(sleep_time)
        attempt += 1
    
    logger.warning(f"Cuckoo task {task_id} timeout after {timeout}s")
    return {"error": "Timeout waiting for Cuckoo report", "task_id": task_id}


def extract_iocs_from_cuckoo(report_json):
    """Extract IOCs from Cuckoo JSON report"""
    iocs = {
        "domains": set(),
        "ips": set(),
        "mutexes": set(),
        "files": set(),
        "registry": set(),
        "urls": set(),
        "processes": []
    }
    
    if not report_json or "error" in report_json:
        return iocs
    
    # Network indicators
    network = report_json.get("network", {})
    
    for conn in network.get("tcp", []) + network.get("udp", []):
        if isinstance(conn, dict):
            dst = conn.get("dst")
            if dst:
                try:
                    ipaddress.ip_address(dst)
                    iocs["ips"].add(dst)
                except:
                    pass
    
    for http in network.get("http", []):
        if isinstance(http, dict):
            if http.get("host"):
                iocs["domains"].add(http.get("host"))
            if http.get("url"):
                iocs["urls"].add(http.get("url"))
    
    # DNS requests
    for dns in network.get("dns", []):
        if isinstance(dns, dict) and dns.get("request"):
            iocs["domains"].add(dns.get("request"))
    
    # Behavior indicators
    behavior = report_json.get("behavior", {})
    
    for proc in behavior.get("processes", []):
        if isinstance(proc, dict):
            iocs["processes"].append({
                "name": proc.get("process_name"),
                "pid": proc.get("process_id"),
                "parent_id": proc.get("parent_id")
            })
            
            # Mutexes
            for mutex in proc.get("summary", {}).get("mutexes", []):
                iocs["mutexes"].add(mutex)
            
            # Registry keys
            for reg in proc.get("summary", {}).get("keys", []):
                iocs["registry"].add(reg)
    
    # Dropped files
    for dropped in report_json.get("dropped", []):
        if isinstance(dropped, dict):
            path = dropped.get("path") or dropped.get("name")
            if path:
                iocs["files"].add(path)
    
    # Convert sets to lists
    return {k: list(v) if isinstance(v, set) else v for k, v in iocs.items()}


# ============================================================================
# RISK SCORING
# ============================================================================

def calculate_risk_score(analysis_results):
    """Calculate risk score based on analysis results"""
    score = 0
    max_score = 100
    
    # YARA matches
    if 'yara' in analysis_results and isinstance(analysis_results['yara'], list):
        for match in analysis_results['yara']:
            severity = match.get('meta', {}).get('severity', 'medium')
            if severity == 'critical':
                score += 20
            elif severity == 'high':
                score += 15
            elif severity == 'medium':
                score += 10
            else:
                score += 5
    
    # PE suspicious flags
    if 'pe_analysis' in analysis_results:
        pe = analysis_results['pe_analysis']
        if isinstance(pe, dict) and 'suspicious_flags' in pe:
            score += min(len(pe['suspicious_flags']) * 5, 20)
    
    # IOCs count
    if 'iocs' in analysis_results:
        iocs = analysis_results['iocs']
        score += min(len(iocs.get('urls', [])) * 3, 15)
        score += min(len(iocs.get('ips', [])) * 3, 15)
        score += min(len(iocs.get('registry_keys', [])) * 2, 10)
    
    # High entropy sections
    if 'pe_analysis' in analysis_results and isinstance(analysis_results['pe_analysis'], dict):
        sections = analysis_results['pe_analysis'].get('sections', [])
        high_entropy_count = sum(1 for s in sections if s.get('entropy', 0) > 7.0)
        score += min(high_entropy_count * 5, 15)
    
    return min(score, max_score)


# ============================================================================
# REPORT GENERATION
# ============================================================================

def generate_report(sample_data, analysis_results, output_dir="reports"):
    """Generate comprehensive analysis report"""
    os.makedirs(output_dir, exist_ok=True)
    
    md5 = sample_data['md5']
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(output_dir, f"report_{md5}_{timestamp}.md")
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(f"# Malware Analysis Report\n\n")
        f.write(f"**Generated:** {datetime.now().isoformat()}\n\n")
        f.write(f"---\n\n")
        
        # Sample metadata
        f.write(f"## Sample Metadata\n\n")
        f.write(f"| Field | Value |\n")
        f.write(f"|-------|-------|\n")
        f.write(f"| Filename | `{sample_data['filename']}` |\n")
        f.write(f"| File Size | {sample_data['size']} bytes |\n")
        f.write(f"| MD5 | `{sample_data['md5']}` |\n")
        f.write(f"| SHA1 | `{sample_data['sha1']}` |\n")
        f.write(f"| SHA256 | `{sample_data['sha256']}` |\n")
        f.write(f"| File Type | {sample_data.get('file_type', 'unknown')} |\n")
        f.write(f"| Risk Score | **{analysis_results.get('risk_score', 0)}/100** |\n\n")
        
        # YARA matches
        if 'yara' in analysis_results and isinstance(analysis_results['yara'], list) and analysis_results['yara']:
            f.write(f"## YARA Detections\n\n")
            for match in analysis_results['yara']:
                severity = match.get('meta', {}).get('severity', 'unknown')
                f.write(f"### 🔴 {match['rule']} (Severity: {severity})\n\n")
                if 'meta' in match and match['meta']:
                    f.write(f"**Description:** {match['meta'].get('description', 'N/A')}\n\n")
                if match.get('strings'):
                    f.write(f"**Matched Strings:** {len(match['strings'])}\n\n")
        
        # IOCs
        if 'iocs' in analysis_results:
            iocs = analysis_results['iocs']
            f.write(f"## Indicators of Compromise (IOCs)\n\n")
            
            if iocs.get('urls'):
                f.write(f"### URLs ({len(iocs['urls'])})\n\n")
                for url in iocs['urls'][:20]:
                    f.write(f"- `{url}`\n")
                if len(iocs['urls']) > 20:
                    f.write(f"\n*...and {len(iocs['urls']) - 20} more*\n")
                f.write(f"\n")
            
            if iocs.get('ips'):
                f.write(f"### IP Addresses ({len(iocs['ips'])})\n\n")
                for ip in iocs['ips'][:20]:
                    f.write(f"- `{ip}`\n")
                if len(iocs['ips']) > 20:
                    f.write(f"\n*...and {len(iocs['ips']) - 20} more*\n")
                f.write(f"\n")
            
            if iocs.get('domains'):
                f.write(f"### Domains ({len(iocs['domains'])})\n\n")
                for domain in iocs['domains'][:20]:
                    f.write(f"- `{domain}`\n")
                if len(iocs['domains']) > 20:
                    f.write(f"\n*...and {len(iocs['domains']) - 20} more*\n")
                f.write(f"\n")
            
            if iocs.get('registry_keys'):
                f.write(f"### Registry Keys ({len(iocs['registry_keys'])})\n\n")
                for key in iocs['registry_keys'][:15]:
                    f.write(f"- `{key}`\n")
                if len(iocs['registry_keys']) > 15:
                    f.write(f"\n*...and {len(iocs['registry_keys']) - 15} more*\n")
                f.write(f"\n")
        
        # PE Analysis
        if 'pe_analysis' in analysis_results and isinstance(analysis_results['pe_analysis'], dict):
            pe = analysis_results['pe_analysis']
            f.write(f"## PE File Analysis\n\n")
            
            if 'timestamp' in pe:
                f.write(f"**Compile Time:** {pe['timestamp']}\n\n")
            
            if pe.get('suspicious_flags'):
                f.write(f"### ⚠️ Suspicious Flags\n\n")
                for flag in pe['suspicious_flags']:
                    f.write(f"- {flag}\n")
                f.write(f"\n")
            
            if pe.get('sections'):
                f.write(f"### Sections\n\n")
                f.write(f"| Name | Virtual Size | Raw Size | Entropy |\n")
                f.write(f"|------|-------------|----------|----------|\n")
                for sec in pe['sections']:
                    entropy = sec.get('entropy', 0)
                    entropy_str = f"**{entropy:.2f}**" if entropy > 7.0 else f"{entropy:.2f}"
                    f.write(f"| {sec['name']} | {sec['virtual_size']} | {sec['raw_size']} | {entropy_str} |\n")
                f.write(f"\n")
            
            if pe.get('imports'):
                f.write(f"### Imported DLLs ({len(pe['imports'])})\n\n")
                for imp in pe['imports'][:10]:
                    f.write(f"- **{imp['dll']}** ({len(imp['functions'])} functions)\n")
                if len(pe['imports']) > 10:
                    f.write(f"\n*...and {len(pe['imports']) - 10} more DLLs*\n")
                f.write(f"\n")
        
        # Recommendations
        f.write(f"## Recommended Actions\n\n")
        risk_score = analysis_results.get('risk_score', 0)
        
        if risk_score >= 75:
            f.write(f"### 🔴 HIGH RISK - IMMEDIATE ACTION REQUIRED\n\n")
            f.write(f"1. **Quarantine immediately** - Isolate affected systems\n")
            f.write(f"2. **Block all IOCs** - Add to firewall/IDS/IPS rules\n")
            f.write(f"3. **Hunt for additional infections** - Check for lateral movement\n")
            f.write(f"4. **Preserve evidence** - Create forensic images\n")
            f.write(f"5. **Incident response** - Escalate to security team\n\n")
        elif risk_score >= 50:
            f.write(f"### 🟡 MEDIUM RISK - INVESTIGATION REQUIRED\n\n")
            f.write(f"1. **Contain** - Limit network access for affected systems\n")
            f.write(f"2. **Monitor** - Watch for suspicious activity\n")
            f.write(f"3. **Investigate** - Perform deeper analysis\n")
            f.write(f"4. **Block IOCs** - Add to monitoring systems\n\n")
        else:
            f.write(f"### 🟢 LOW RISK - MONITORING RECOMMENDED\n\n")
            f.write(f"1. **Log** - Keep records of the sample\n")
            f.write(f"2. **Monitor** - Watch for related activity\n")
            f.write(f"3. **Update signatures** - Add to detection systems\n\n")
        
        f.write(f"---\n\n")
        f.write(f"*Report generated by Malware Analysis Triage Tool*\n")
    
    return report_file


# ============================================================================
# MAIN ANALYSIS WORKFLOW
# ============================================================================

def analyze_sample(file_path, cuckoo_url=None, yara_rules=None, save_to_db=True, output_dir="reports"):
    """Main analysis workflow - orchestrates all analysis steps"""
    
    logger.info(f"\n{'='*70}")
    logger.info(f"MALWARE ANALYSIS TRIAGE TOOL")
    logger.info(f"{'='*70}\n")
    
    # Check dependencies
    if not HAS_PEFILE:
        logger.warning("pefile not installed - PE analysis will be limited")
    if not HAS_YARA:
        logger.warning("yara-python not installed - YARA scanning disabled")
    if not HAS_REQUESTS and cuckoo_url:
        logger.warning("requests not installed - Cuckoo integration disabled")
    
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        return None
    
    # Initialize database
    db = AnalysisDB() if save_to_db else None
    
    # Step 1: Basic metadata
    logger.info(f"[*] Step 1: Computing hashes and metadata...")
    sample_data = {
        'filename': os.path.basename(file_path),
        'filepath': os.path.abspath(file_path),
        'size': os.path.getsize(file_path)
    }
    
    hashes = compute_hashes(file_path)
    if 'error' in hashes:
        logger.error(f"Failed to compute hashes: {hashes['error']}")
        return None
    
    sample_data.update(hashes)
    sample_data['file_type'] = detect_file_type(file_path)
    
    logger.info(f"    MD5:    {sample_data['md5']}")
    logger.info(f"    SHA256: {sample_data['sha256']}")
    logger.info(f"    Type:   {sample_data['file_type']}")
    
    if save_to_db and db:
        db.insert_sample(sample_data)
    
    analysis_results = {}
    
    # Step 2: String extraction
    logger.info(f"\n[*] Step 2: Extracting strings (streaming mode)...")
    strings_data = extract_strings(file_path)
    if 'error' not in strings_data:
        logger.info(f"    ASCII strings: {strings_data['total_ascii']}")
        logger.info(f"    Unicode strings: {strings_data['total_unicode']}")
        analysis_results['strings'] = strings_data
    else:
        logger.error(f"    String extraction failed: {strings_data['error']}")
    
    # Step 3: IOC extraction from strings
    logger.info(f"\n[*] Step 3: Extracting IOCs from strings...")
    iocs = find_suspicious_patterns(strings_data)
    analysis_results['iocs'] = iocs
    
    for ioc_type, values in iocs.items():
        if values:
            logger.info(f"    {ioc_type}: {len(values)}")
            if save_to_db and db:
                for value in values:
                    db.insert_ioc(sample_data['md5'], ioc_type, value, source="static")
    
    # Step 4: PE analysis
    if 'PE' in sample_data['file_type'] or 'DOS' in sample_data['file_type']:
        logger.info(f"\n[*] Step 4: Analyzing PE structure...")
        pe_analysis = analyze_pe_file(file_path)
        if 'error' not in pe_analysis:
            analysis_results['pe_analysis'] = pe_analysis
            logger.info(f"    Sections: {len(pe_analysis.get('sections', []))}")
            logger.info(f"    Imports: {len(pe_analysis.get('imports', []))}")
            logger.info(f"    Suspicious flags: {len(pe_analysis.get('suspicious_flags', []))}")
            
            for flag in pe_analysis.get('suspicious_flags', [])[:5]:
                logger.info(f"      - {flag}")
        else:
            logger.warning(f"    PE analysis failed: {pe_analysis['error']}")
    
    # Step 5: YARA scanning
    logger.info(f"\n[*] Step 5: Running YARA rules...")
    yara_results = run_yara_scan(file_path, yara_rules)
    if isinstance(yara_results, list):
        analysis_results['yara'] = yara_results
        logger.info(f"    Matches: {len(yara_results)}")
        for match in yara_results:
            severity = match.get('meta', {}).get('severity', 'unknown')
            logger.info(f"      - {match['rule']} (severity: {severity})")
            if save_to_db and db:
                sanitized_match = sanitize_yara_match_for_db(match)
                db.insert_yara_match(sample_data['md5'], sanitized_match)
    elif 'error' in yara_results:
        logger.warning(f"    YARA error: {yara_results['error']}")
    
    # Step 6: Cuckoo sandbox (optional)
    if cuckoo_url and HAS_REQUESTS:
        logger.info(f"\n[*] Step 6: Submitting to Cuckoo sandbox...")
        logger.info(f"    This may take several minutes...")
        cuckoo_result = cuckoo_submit_and_wait(cuckoo_url, file_path)
        
        if 'error' in cuckoo_result:
            logger.warning(f"    Cuckoo error: {cuckoo_result['error']}")
        else:
            logger.info(f"    Analysis complete (Task ID: {cuckoo_result['task_id']})")
            cuckoo_iocs = extract_iocs_from_cuckoo(cuckoo_result.get('report', {}))
            analysis_results['cuckoo_iocs'] = cuckoo_iocs
            
            # Save Cuckoo IOCs to DB
            if save_to_db and db:
                for ioc_type, values in cuckoo_iocs.items():
                    if isinstance(values, list):
                        for value in values:
                            if isinstance(value, str):
                                db.insert_ioc(sample_data['md5'], ioc_type, value, source="cuckoo")
    elif cuckoo_url and not HAS_REQUESTS:
        logger.warning(f"\n[*] Step 6: Skipping Cuckoo (requests not installed)")
    
    # Step 7: Risk scoring
    logger.info(f"\n[*] Step 7: Calculating risk score...")
    risk_score = calculate_risk_score(analysis_results)
    analysis_results['risk_score'] = risk_score
    logger.info(f"    Risk Score: {risk_score}/100")
    
    if risk_score >= 75:
        logger.warning(f"    Assessment: 🔴 HIGH RISK")
    elif risk_score >= 50:
        logger.warning(f"    Assessment: 🟡 MEDIUM RISK")
    else:
        logger.info(f"    Assessment: 🟢 LOW RISK")
    
    # Step 8: Generate report
    logger.info(f"\n[*] Step 8: Generating report...")
    report_file = generate_report(sample_data, analysis_results, output_dir)
    logger.info(f"    Report saved: {report_file}")
    
    # Save full analysis to DB
    if save_to_db and db:
        db.save_report(sample_data['md5'], "full_analysis", analysis_results)
    
    logger.info(f"\n{'='*70}")
    logger.info(f"ANALYSIS COMPLETE")
    logger.info(f"{'='*70}\n")
    
    return {
        'sample': sample_data,
        'analysis': analysis_results,
        'report_file': report_file
    }


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Malware Analysis Triage Tool - Local static and dynamic analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python mal.py sample.exe
  python mal.py sample.dll --yara rules.yar
  python mal.py malware.bin --cuckoo http://127.0.0.1:8090
  python mal.py sample.exe --no-db --json output.json
  python mal.py sample.exe -v --output reports/

SAFETY WARNING:
  Only analyze malware in isolated, air-gapped environments!
  Use dedicated VMs with snapshots. Never run on production systems.
  
NETWORK WARNING:
  The --cuckoo option will connect to your local Cuckoo instance.
  Ensure it's properly isolated and not exposed to the internet!
        """
    )
    
    parser.add_argument('file', help='File to analyze')
    parser.add_argument('--yara', '-y', help='Path to YARA rules file')
    parser.add_argument('--cuckoo', '-c', help='Cuckoo sandbox URL (e.g., http://127.0.0.1:8090)')
    parser.add_argument('--no-db', action='store_true', help='Do not save to database')
    parser.add_argument('--output', '-o', default='reports', help='Output directory for reports')
    parser.add_argument('--json', '-j', help='Save results as JSON to specified file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--db-path', default='malware_analysis.db', help='Database file path')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(verbose=args.verbose)
    
    if not os.path.exists(args.file):
        logger.error(f"File not found: {args.file}")
        sys.exit(1)
    
    # Run analysis
    result = analyze_sample(
        file_path=args.file,
        cuckoo_url=args.cuckoo,
        yara_rules=args.yara,
        save_to_db=not args.no_db,
        output_dir=args.output
    )
    
    if result:
        logger.info(f"\n[✓] Analysis complete!")
        logger.info(f"[✓] Report: {result['report_file']}")
        
        if not args.no_db:
            logger.info(f"[✓] Data saved to database: {args.db_path}")
        
        # Save JSON output if requested
        if args.json:
            try:
                with open(args.json, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, default=str)
                logger.info(f"[✓] JSON output saved: {args.json}")
            except Exception as e:
                logger.error(f"Failed to save JSON output: {e}")


if __name__ == "__main__":
    main()
