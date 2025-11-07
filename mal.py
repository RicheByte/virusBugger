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
from typing import List, Dict

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

# Optional extras
try:
    import ssdeep
    HAS_SSDEEP = True
except Exception:
    HAS_SSDEEP = False

try:
    import tlsh
    HAS_TLSH = True
except Exception:
    HAS_TLSH = False

try:
    import magic  # python-magic
    HAS_MAGIC = True
except Exception:
    HAS_MAGIC = False


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
# ADVANCED BEHAVIORAL PATTERN ANALYSIS
# ============================================================================

class BehavioralAnalyzer:
    """Analyzes behavioral patterns in malware"""
    
    def __init__(self):
        self.patterns = {
            'ransomware_indicators': [
                r'\.encrypted', r'\.locked', r'\.crypto',
                r'README.*\.txt', r'DECRYPT.*\.txt',
                r'bitcoin', r'ransom', r'payment',
            ],
            'rat_indicators': [
                r'keylog', r'screenshot', r'webcam',
                r'reverse.*shell', r'remote.*control', r'cmd.*execute',
            ],
            'stealer_indicators': [
                r'password', r'cookie', r'credential',
                r'wallet', r'autofill', r'login.*data',
            ],
            'backdoor_indicators': [
                r'persistence', r'startup', r'registry.*run',
                r'scheduled.*task', r'service.*install',
            ],
        }
    
    def analyze(self, strings: List[str]) -> Dict[str, List[str]]:
        """Analyze strings for behavioral patterns"""
        results = defaultdict(list)
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                regex = re.compile(pattern, re.IGNORECASE)
                for string in strings:
                    if regex.search(string) and string not in results[category]:
                        results[category].append(string[:100])
        return dict(results)


# ============================================================================
# API CALL SEQUENCE ANALYSIS
# ============================================================================

class APISequenceAnalyzer:
    """Detects malicious API call sequences"""
    
    SUSPICIOUS_SEQUENCES = [
        {'name': 'Process Injection', 'severity': 'critical',
         'apis': ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'], 'min_match': 4},
        {'name': 'Process Hollowing', 'severity': 'critical',
         'apis': ['CreateProcess', 'NtUnmapViewOfSection', 'VirtualAllocEx', 'WriteProcessMemory', 'ResumeThread'], 'min_match': 4},
        {'name': 'Keylogging', 'severity': 'high',
         'apis': ['SetWindowsHookEx', 'GetAsyncKeyState', 'GetForegroundWindow', 'GetWindowText'], 'min_match': 2},
        {'name': 'Credential Dumping', 'severity': 'critical',
         'apis': ['LsaEnumerateLogonSessions', 'LsaGetLogonSessionData', 'CryptUnprotectData'], 'min_match': 2},
        {'name': 'Data Exfiltration', 'severity': 'high',
         'apis': ['InternetOpen', 'HttpSendRequest', 'InternetReadFile', 'WriteFile'], 'min_match': 3},
        {'name': 'Anti-Debugging', 'severity': 'medium',
         'apis': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess'], 'min_match': 2},
        {'name': 'File Encryption', 'severity': 'critical',
         'apis': ['FindFirstFile', 'CryptAcquireContext', 'CryptGenKey', 'CryptEncrypt', 'WriteFile'], 'min_match': 4},
        {'name': 'Privilege Escalation', 'severity': 'critical',
         'apis': ['OpenProcessToken', 'LookupPrivilegeValue', 'AdjustTokenPrivileges'], 'min_match': 3},
        {'name': 'Lateral Movement', 'severity': 'critical',
         'apis': ['NetShareEnum', 'NetShareGetInfo', 'WNetAddConnection2', 'CreateProcess'], 'min_match': 3},
        {'name': 'Service Manipulation', 'severity': 'high',
         'apis': ['OpenSCManager', 'CreateService', 'StartService', 'DeleteService'], 'min_match': 2},
    ]
    
    def analyze(self, imports: List[Dict]) -> List[Dict]:
        """Analyze imports for suspicious API sequences"""
        results = []
        all_apis = []
        for dll_import in imports:
            all_apis.extend(dll_import.get('functions', []))
        
        for sequence in self.SUSPICIOUS_SEQUENCES:
            matched = [api for api in sequence['apis'] if api in all_apis]
            if len(matched) >= sequence['min_match']:
                results.append({
                    'name': sequence['name'],
                    'severity': sequence['severity'],
                    'matched_apis': matched,
                    'confidence': len(matched) / len(sequence['apis']) * 100
                })
        return results


# ============================================================================
# NETWORK IOC ENRICHMENT
# ============================================================================

class NetworkIOCEnricher:
    """Enriches network IOCs with threat intelligence"""
    
    KNOWN_MALICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.win', '.bid'}
    SUSPICIOUS_PORTS = {4444: 'Metasploit', 5555: 'ADB', 6667: 'IRC C2', 8443: 'Alt HTTPS', 9999: 'Backdoor', 31337: 'Elite'}
    DGA_INDICATORS = [r'[a-z]{20,}', r'[0-9]{5,}']
    
    @staticmethod
    def analyze_domain(domain: str) -> Dict:
        """Analyze domain for suspicious characteristics"""
        result = {'domain': domain, 'suspicious': False, 'reasons': []}
        
        for tld in NetworkIOCEnricher.KNOWN_MALICIOUS_TLDS:
            if domain.endswith(tld):
                result['suspicious'] = True
                result['reasons'].append(f'Suspicious TLD: {tld}')
        
        for pattern in NetworkIOCEnricher.DGA_INDICATORS:
            if re.search(pattern, domain):
                result['suspicious'] = True
                result['reasons'].append('Possible DGA')
                break
        
        if len(domain) > 5 and len(set(domain)) / len(domain) > 0.7:
            result['suspicious'] = True
            result['reasons'].append('High entropy (DGA)')
        
        return result
    
    @staticmethod
    def analyze_url(url: str) -> Dict:
        """Analyze URL for suspicious characteristics"""
        result = {'url': url, 'suspicious': False, 'reasons': []}
        
        if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
            result['suspicious'] = True
            result['reasons'].append('Direct IP')
        
        port_match = re.search(r':(\d+)/', url)
        if port_match:
            port = int(port_match.group(1))
            if port in NetworkIOCEnricher.SUSPICIOUS_PORTS:
                result['suspicious'] = True
                result['reasons'].append(f'Port {port} ({NetworkIOCEnricher.SUSPICIOUS_PORTS[port]})')
        
        if re.search(r'\.(exe|dll|bat|ps1|vbs|scr)($|\?)', url, re.IGNORECASE):
            result['suspicious'] = True
            result['reasons'].append('Executable download')
        
        return result


# ============================================================================
# THREAT INTELLIGENCE SCORER
# ============================================================================

class ThreatIntelligenceScorer:
    """Advanced risk scoring with detailed breakdown"""
    
    WEIGHTS = {
        'yara_critical': 25,
        'yara_high': 15,
        'yara_medium': 10,
        'yara_low': 5,
        'suspicious_api_sequence': 20,
        'packer_detected': 10,
        'high_entropy': 15,
        'network_iocs': 15,
        'ransomware_indicators': 25,
        'rat_indicators': 20,
        'stealer_indicators': 18,
        'backdoor_indicators': 15,
        'apt_indicators': 25,
        'pe_suspicious_flags': 20,
    }
    
    @staticmethod
    def calculate_detailed_score(analysis_data: Dict) -> Dict:
        """Calculate detailed risk score with breakdown"""
        score_breakdown = {}
        total_score = 0
        max_score = 100

        base_score = analysis_data.get('risk_score', 0)

        if 'yara' in analysis_data and isinstance(analysis_data['yara'], list):
            severity_counts = defaultdict(int)
            for match in analysis_data['yara']:
                severity = match.get('meta', {}).get('severity', 'low')
                severity_counts[severity] += 1

            for severity, count in severity_counts.items():
                key = f'yara_{severity}'
                if key in ThreatIntelligenceScorer.WEIGHTS:
                    points = min(
                        ThreatIntelligenceScorer.WEIGHTS[key] * count,
                        ThreatIntelligenceScorer.WEIGHTS[key] * 2,
                    )
                    score_breakdown[f'YARA_{severity.upper()}'] = points
                    total_score += points

        if 'api_sequences' in analysis_data:
            seq_score = len(analysis_data['api_sequences']) * ThreatIntelligenceScorer.WEIGHTS['suspicious_api_sequence']
            seq_score = min(seq_score, 40)
            score_breakdown['Suspicious_APIs'] = seq_score
            total_score += seq_score

        if 'behavioral_patterns' in analysis_data:
            patterns = analysis_data['behavioral_patterns']
            for pattern_type in ['ransomware_indicators', 'rat_indicators', 'stealer_indicators', 'backdoor_indicators']:
                if pattern_type in patterns and patterns[pattern_type]:
                    weight = ThreatIntelligenceScorer.WEIGHTS.get(pattern_type, 0)
                    if weight:
                        score_breakdown[pattern_type.replace('_', ' ').title()] = weight
                        total_score += weight

        pe = analysis_data.get('pe_analysis')
        if isinstance(pe, dict):
            flags = pe.get('suspicious_flags', []) or []
            if flags:
                flag_weight = min(len(flags) * 5, ThreatIntelligenceScorer.WEIGHTS['pe_suspicious_flags'])
                score_breakdown['PE Suspicious Flags'] = flag_weight
                total_score += flag_weight

                overlay_size = pe.get('overlay_size', 0)
                if overlay_size > 1_000_000:
                    score_breakdown['Large Overlay Payload'] = 20
                    total_score += 20
                elif overlay_size > 100_000:
                    score_breakdown['Overlay Payload'] = 10
                    total_score += 10

        enriched = analysis_data.get('enriched_iocs') or {}
        if enriched:
            suspicious_domains = [d for d in enriched.get('domains', []) if d.get('suspicious')]
            suspicious_urls = [u for u in enriched.get('urls', []) if u.get('suspicious')]
            if suspicious_domains:
                domain_score = min(len(suspicious_domains) * 3, ThreatIntelligenceScorer.WEIGHTS['network_iocs'])
                score_breakdown['Suspicious Domains'] = domain_score
                total_score += domain_score
            if suspicious_urls:
                url_score = min(len(suspicious_urls) * 3, ThreatIntelligenceScorer.WEIGHTS['network_iocs'])
                score_breakdown['Suspicious URLs'] = url_score
                total_score += url_score

        total_score = max(total_score, base_score)
        total_score = min(total_score, max_score)

        return {
            'total_score': total_score,
            'breakdown': score_breakdown,
            'threat_level': ThreatIntelligenceScorer.get_threat_level(total_score),
            'recommendation': ThreatIntelligenceScorer.get_recommendation(total_score),
        }
    
    @staticmethod
    def get_threat_level(score: int) -> str:
        if score >= 80: return "🔴 CRITICAL - Confirmed Malicious"
        elif score >= 60: return "🟠 HIGH - Highly Suspicious"
        elif score >= 40: return "🟡 MEDIUM - Suspicious Activity"
        elif score >= 20: return "🔵 LOW - Potentially Unwanted"
        else: return "🟢 MINIMAL - Likely Benign"
    
    @staticmethod
    def get_recommendation(score: int) -> str:
        if score >= 80: return "IMMEDIATE ACTION: Isolate system, block IOCs, initiate incident response"
        elif score >= 60: return "High priority investigation. Sandbox analysis recommended."
        elif score >= 40: return "Further analysis recommended. Monitor for suspicious behavior."
        elif score >= 20: return "Low priority. Review logs and context."
        else: return "Likely safe, maintain standard security posture."


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
    fzy = None
    tls = None
    
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
    except Exception as e:
        return {"error": str(e)}
    
    # Compute fuzzy hashes if available
    try:
        if HAS_SSDEEP:
            with open(file_path, 'rb') as f:
                fzy = ssdeep.hash(f.read())
    except Exception:
        fzy = None
    try:
        if HAS_TLSH:
            with open(file_path, 'rb') as f:
                data = f.read()
                h = tlsh.hash(data)
                tls = h if h not in (None, '') else None
    except Exception:
        tls = None

    result = {
        'md5': md5.hexdigest(),
        'sha1': sha1.hexdigest(),
        'sha256': sha256.hexdigest()
    }
    if fzy:
        result['ssdeep'] = fzy
    if tls:
        result['tlsh'] = tls
    return result


# ============================================================================
# STATIC ANALYSIS - FILE TYPE DETECTION
# ============================================================================

def detect_file_type(file_path):
    """Detect file type using magic bytes"""
    # Prefer python-magic if available
    if HAS_MAGIC:
        try:
            desc = magic.from_file(file_path)
            if isinstance(desc, bytes):
                desc = desc.decode('utf-8', errors='ignore')
            return desc
        except Exception:
            pass
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
        'imphash': None,
        'is_signed': False,
        'overlay_size': 0,
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
            dt = datetime.fromtimestamp(timestamp)
            result['timestamp'] = dt.isoformat()
            # Heuristic: implausible years
            if dt.year < 2000 or dt.year > 2035:
                result['suspicious_flags'].append(f"Implausible compile time: {dt.isoformat()}")
        else:
            result['suspicious_flags'].append(f"Invalid PE timestamp: {timestamp}")
    except Exception as e:
        logger.warning(f"Could not parse PE timestamp: {e}")
        result['timestamp'] = 'Invalid'

    # imphash
    try:
        result['imphash'] = pe.get_imphash()
    except Exception:
        result['imphash'] = None
    
    # Sections
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        chars = section.Characteristics
        entropy = section.get_entropy()
        result['sections'].append({
            'name': name,
            'virtual_address': hex(section.VirtualAddress),
            'virtual_size': section.Misc_VirtualSize,
            'raw_size': section.SizeOfRawData,
            'entropy': entropy,
            'characteristics': chars
        })
        
        # Check for suspicious entropy (packed/encrypted)
        if entropy > 7.0:
            result['suspicious_flags'].append(
                f"High entropy in section {name}: "
                f"{entropy:.2f}"
            )
        # .text writable or executable anomalies
        IMAGE_SCN_MEM_WRITE = 0x80000000
        IMAGE_SCN_CNT_CODE = 0x00000020
        if name.lower().startswith('.text'):
            if chars & IMAGE_SCN_MEM_WRITE:
                result['suspicious_flags'].append(".text section is writable")
    
    # Imports
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore')
            imports = []
            for imp in entry.imports:
                if imp.name:
                    imports.append(imp.name.decode('utf-8', errors='ignore'))
                else:
                    # imported by ordinal
                    result['suspicious_flags'].append(f"Import by ordinal in {dll_name}")
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

    # Check for overlay (appended data after PE image)
    try:
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset is not None:
            file_size = os.path.getsize(file_path)
            overlay_size = max(0, file_size - overlay_offset)
            result['overlay_size'] = overlay_size
            if overlay_size > 0:
                result['suspicious_flags'].append(f"Overlay data present: {overlay_size} bytes")
    except Exception:
        pass

    # Check for Authenticode signature presence (not validation)
    try:
        sec_dir_index = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_dir_index]
        if sec_dir and sec_dir.Size > 0:
            result['is_signed'] = True
    except Exception:
        result['is_signed'] = False
    
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
        # Allow directory of rules or comma-separated files
        rule_files: Dict[str, str] = {}
        if os.path.isdir(rules_path):
            for root, _dirs, files in os.walk(rules_path):
                for fn in files:
                    if fn.lower().endswith(('.yar', '.yara')):
                        ns = os.path.splitext(fn)[0]
                        rule_files[ns] = os.path.join(root, fn)
        else:
            paths: List[str] = [p.strip() for p in rules_path.split(',') if p.strip()]
            if len(paths) == 1:
                rules = yara.compile(filepath=paths[0])
            else:
                for p in paths:
                    ns = os.path.splitext(os.path.basename(p))[0]
                    rule_files[ns] = p
        if rule_files:
            rules = yara.compile(filepaths=rule_files)
        matches = rules.match(file_path)
        
        results = []
        for match in matches:
            matched_strings = []
            for s in match.strings:
                try:
                    # s is a StringMatch object with attributes: identifier, instances
                    identifier = s.identifier if hasattr(s, 'identifier') else str(s)
                    # Get instances of the match
                    instances = s.instances if hasattr(s, 'instances') else []
                    for instance in instances[:5]:  # Limit to 5 instances per string
                        offset = instance.offset if hasattr(instance, 'offset') else 0
                        matched_data = instance.matched_data if hasattr(instance, 'matched_data') else b''
                        # Safely decode the matched data
                        if isinstance(matched_data, bytes):
                            data_str = matched_data[:100].decode('utf-8', errors='ignore')
                        else:
                            data_str = str(matched_data)[:100]
                        matched_strings.append((identifier, offset, data_str))
                except Exception as e:
                    logger.debug(f"Error processing YARA string match: {e}")
                    continue
            
            results.append({
                'rule': match.rule,
                'namespace': match.namespace,
                'tags': match.tags,
                'meta': match.meta,
                'strings': matched_strings
            })
        
        return results
    except Exception as e:
        logger.error(f"YARA scan error: {e}")
        return {"error": str(e)}


def run_default_yara_rules(file_path):
    """Run embedded YARA rules - Industry-grade detection suite"""
    if not HAS_YARA:
        return {"error": "yara-python not installed"}
    
    # ============================================================================
    # COMPREHENSIVE YARA RULES - INDUSTRY-GRADE MALWARE DETECTION
    # ============================================================================
    default_rules = """
    // ==================== ADVANCED RAT (Remote Access Trojan) Detection ====================
    
    rule RAT_RevengeRAT {
        meta:
            description = "Detects RevengeRAT malware"
            severity = "critical"
            malware_family = "RevengeRAT"
            reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.revengeRAT"
        strings:
            $s1 = "RevengeRAT" nocase
            $s2 = "Revenge-RAT" nocase
            $s3 = "RV_MUTEX" nocase
            $cmd1 = "NGRun" ascii
            $cmd2 = "LimeLogger" ascii
            $net1 = "socketio" nocase
            $net2 = "get_Pass" ascii
            $pdb = /PDB.*Revenge/i
        condition:
            any of ($s*) or 2 of ($cmd*, $net*) or $pdb
    }
    
    rule RAT_DarkComet {
        meta:
            description = "Detects DarkComet RAT"
            severity = "critical"
            malware_family = "DarkComet"
            reference = "DarkComet RAT builder artifacts"
        strings:
            $s1 = "#BOT#" ascii
            $s2 = "DARKCOMET" ascii nocase
            $s3 = "DC_MUTEX" ascii
            $cmd = "DOWNLOAD&EXECUTE" ascii
            $config = "GENCODE" ascii
            $net = "BEGIN_DOWNLOAD" ascii
        condition:
            2 of them
    }
    
    rule RAT_NanoCore {
        meta:
            description = "Detects NanoCore RAT"
            severity = "critical"
            malware_family = "NanoCore"
        strings:
            $s1 = "NanoCore" ascii
            $s2 = "Nano.Core" ascii
            $class1 = "IClientNetworkHost" ascii
            $class2 = "ClientPlugin" ascii
            $mutex = "Mutex.OpenExisting" ascii
        condition:
            any of ($s*) or 2 of ($class*, $mutex)
    }
    
    rule RAT_RemcosRAT {
        meta:
            description = "Detects Remcos RAT"
            severity = "critical"
            malware_family = "Remcos"
        strings:
            $s1 = "Remcos" ascii nocase
            $s2 = "Breaking-Security" ascii
            $mutex = "Remcos_Mutex" ascii
            $cmd1 = "get_AudioFolder" ascii
            $cmd2 = "screenshot.txt" ascii
        condition:
            any of ($s*) or ($mutex and any of ($cmd*))
    }
    
    rule RAT_njRAT {
        meta:
            description = "Detects njRAT/Bladabindi malware"
            severity = "critical"
            malware_family = "njRAT"
        strings:
            $s1 = "njRAT" ascii
            $s2 = "Bladabindi" ascii
            $cmd1 = "inv" ascii
            $cmd2 = "rn" ascii
            $cmd3 = "CAP" ascii
        condition:
            any of ($s*) or 2 of ($cmd*)
    }
    
    rule RAT_AsyncRAT {
        meta:
            description = "Detects AsyncRAT malware"
            severity = "critical"
            malware_family = "AsyncRAT"
        strings:
            $s1 = "AsyncRAT" ascii
            $s2 = "AsyncClient" ascii
            $s3 = "Async_RAT" ascii
            $pdb = "AsyncRAT" ascii wide
            $class = "ClientSocket" ascii wide
        condition:
            any of them
    }
    
    rule RAT_QuasarRAT {
        meta:
            description = "Detects QuasarRAT malware"
            severity = "critical"
            malware_family = "QuasarRAT"
        strings:
            $s1 = "Quasar.Client" ascii
            $s2 = "Quasar.Common" ascii
            $ns1 = "xServer.Forms" ascii
            $ns2 = "xClient.Core" ascii
        condition:
            any of them
    }
    
    // ==================== Ransomware Detection ====================
    
    rule Ransomware_Generic {
        meta:
            description = "Generic ransomware behavior indicators"
            severity = "critical"
            category = "Ransomware"
        strings:
            $enc1 = "encrypt" nocase
            $enc2 = "decrypt" nocase
            $enc3 = "cipher" nocase
            $pay1 = "bitcoin" nocase
            $pay2 = "wallet" nocase
            $pay3 = "ransom" nocase
            $pay4 = "payment" nocase
            $ext1 = ".locked" ascii
            $ext2 = ".encrypted" ascii
            $ext3 = ".crypt" ascii
            $note1 = "README" nocase
            $note2 = "HOW_TO_DECRYPT" nocase
            $note3 = "RECOVERY" nocase
        condition:
            2 of ($enc*) and 2 of ($pay*) or
            1 of ($enc*) and 1 of ($pay*) and 1 of ($ext*, $note*)
    }
    
    rule Ransomware_WannaCry {
        meta:
            description = "Detects WannaCry ransomware"
            severity = "critical"
            malware_family = "WannaCry"
        strings:
            $s1 = "WNcry@2ol7" ascii
            $s2 = "WANACRY!" ascii
            $s3 = "msg/m_" ascii
            $ext = ".WNCRY" ascii
            $bitcoin = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" ascii
        condition:
            any of them
    }
    
    rule Ransomware_Locky {
        meta:
            description = "Detects Locky ransomware"
            severity = "critical"
            malware_family = "Locky"
        strings:
            $ext1 = ".locky" ascii
            $ext2 = ".osiris" ascii
            $ext3 = ".aesir" ascii
            $ransom = "_Locky_recover_instructions.txt" ascii
        condition:
            any of them
    }
    
    rule Ransomware_Ryuk {
        meta:
            description = "Detects Ryuk ransomware"
            severity = "critical"
            malware_family = "Ryuk"
            reference = "High-profile targeted ransomware"
        strings:
            $ext = ".ryk" ascii
            $ext2 = ".RYK" ascii
            $note1 = "RyukReadMe.txt" ascii
            $ransom = "No system is safe" ascii
            $bitcoin = "bitcoin" nocase
            $api1 = "CryptAcquireContextW" ascii
            $api2 = "CryptGenRandom" ascii
        condition:
            any of ($ext*) or ($note1 and ($bitcoin or 2 of ($api*)))
    }
    
    rule Ransomware_Maze {
        meta:
            description = "Detects Maze ransomware"
            severity = "critical"
            malware_family = "Maze"
        strings:
            $s1 = "DECRYPT-FILES.txt" ascii
            $s2 = "maze" nocase
            $url = "mazedecrypt" nocase
            $threat = "leaked and exposed" nocase
        condition:
            2 of them
    }
    
    rule Ransomware_Sodinokibi_REvil {
        meta:
            description = "Detects Sodinokibi/REvil ransomware"
            severity = "critical"
            malware_family = "Sodinokibi"
            aka = "REvil"
        strings:
            $cfg1 = "exp" ascii
            $cfg2 = "pk" ascii
            $cfg3 = "pid" ascii
            $cfg4 = "sub" ascii
            $cfg5 = "dbg" ascii
            $note = "readme.txt" nocase
            $ext1 = ".locked" ascii
            $ext2 = ".encrypted" ascii
        condition:
            4 of ($cfg*) or ($note and any of ($ext*))
    }
    
    rule Ransomware_Conti {
        meta:
            description = "Detects Conti ransomware"
            severity = "critical"
            malware_family = "Conti"
        strings:
            $s1 = "CONTI" ascii
            $s2 = "All of your files are currently encrypted" ascii
            $readme = "readme.txt" nocase
            $api1 = "NetShareEnum" ascii
            $api2 = "NetShareGetInfo" ascii
        condition:
            any of ($s*) or ($readme and 2 of ($api*))
    }
    
    rule Ransomware_LockBit {
        meta:
            description = "Detects LockBit ransomware"
            severity = "critical"
            malware_family = "LockBit"
        strings:
            $s1 = "LockBit" nocase
            $note = "Restore-My-Files.txt" ascii
            $ext = ".lockbit" ascii
            $api1 = "GetLogicalDrives" ascii
            $api2 = "FindFirstFileW" ascii
        condition:
            any of ($s*) or ($note and $ext) or (2 of ($api*) and $note)
    }
    
    rule Ransomware_DarkSide {
        meta:
            description = "Detects DarkSide ransomware"
            severity = "critical"
            malware_family = "DarkSide"
            reference = "Colonial Pipeline attack"
        strings:
            $s1 = "darkside" nocase
            $note1 = "README" ascii
            $note2 = "---BEGIN DARKSIDE" ascii
            $avoid1 = "Armenia" ascii
            $avoid2 = "Azerbaijan" ascii
            $avoid3 = "Belarus" ascii
        condition:
            ($s1 and any of ($note*)) or (any of ($note*) and 2 of ($avoid*))
    }
    
    // ==================== Banking Trojans ====================
    
    rule BankingTrojan_Zeus {
        meta:
            description = "Detects Zeus banking trojan"
            severity = "critical"
            malware_family = "Zeus"
        strings:
            $s1 = "soft=1" ascii
            $s2 = "user.php" ascii
            $s3 = "gate.php" ascii
            $s4 = "ZEUS" ascii
            $conf = "CONFIGS" ascii
        condition:
            3 of them
    }
    
    rule BankingTrojan_Emotet {
        meta:
            description = "Detects Emotet banking trojan"
            severity = "critical"
            malware_family = "Emotet"
        strings:
            $code1 = {8B 45 ?? 8B 4D ?? 8D 54 08 ?? 89 55 ??}
            $code2 = {8B 45 ?? 33 C9 89 08 89 48 04}
            $api1 = "CreateToolhelp32Snapshot" ascii
            $api2 = "Process32First" ascii
        condition:
            all of ($code*) or all of ($api*)
    }
    
    rule BankingTrojan_Dridex {
        meta:
            description = "Detects Dridex banking trojan"
            severity = "critical"
            malware_family = "Dridex"
        strings:
            $s1 = "system32\\config\\systemprofile" ascii
            $s2 = "DRIDEX" ascii
            $api1 = "HttpSendRequestW" ascii
            $api2 = "InternetReadFile" ascii
            $inject = "WriteProcessMemory" ascii
        condition:
            ($s1 and $inject) or ($s2 and 2 of ($api*))
    }
    
    rule BankingTrojan_TrickBot {
        meta:
            description = "Detects TrickBot banking trojan"
            severity = "critical"
            malware_family = "TrickBot"
        strings:
            $module1 = "pwgrab" ascii
            $module2 = "systeminfo" ascii
            $module3 = "injectDll" ascii
            $config = "<mcconf>" ascii
            $str1 = "Start" ascii
            $str2 = "Control" ascii
        condition:
            2 of ($module*) or ($config and 2 of ($str*))
    }
    
    rule BankingTrojan_Zloader {
        meta:
            description = "Detects Zloader banking trojan"
            severity = "critical"
            malware_family = "Zloader"
            aka = "Terdot, DELoader"
        strings:
            $s1 = "user_execute.dll" ascii
            $s2 = "cmd /c start /b" ascii
            $api1 = "HttpSendRequestA" ascii
            $api2 = "InternetOpenA" ascii
            $inject = "ZwWriteVirtualMemory" ascii
        condition:
            2 of ($s*) or ($inject and 2 of ($api*))
    }
    
    rule BankingTrojan_Gozi_ISFB {
        meta:
            description = "Detects Gozi/ISFB/Ursnif banking trojan"
            severity = "critical"
            malware_family = "Gozi"
            aka = "ISFB, Ursnif"
        strings:
            $s1 = "client_id" ascii
            $s2 = "soft" ascii
            $s3 = "version" ascii
            $s4 = "user_execute" ascii
            $hash = {6A 00 68 ?? ?? ?? ?? FF 15}
        condition:
            3 of ($s*) or $hash
    }
    
    rule BankingTrojan_Carbanak {
        meta:
            description = "Detects Carbanak/Anunak banking trojan"
            severity = "critical"
            malware_family = "Carbanak"
            reference = "APT targeting financial institutions"
        strings:
            $cmd1 = "getaccounts" ascii
            $cmd2 = "checkav" ascii
            $cmd3 = "netview" ascii
            $plugin = "vnc.dll" ascii
            $api = "GetActiveWindow" ascii
        condition:
            2 of ($cmd*) or ($plugin and $api)
    }
    
    // ==================== APT & Espionage Malware ====================
    
    rule APT_Cobalt_Strike {
        meta:
            description = "Detects Cobalt Strike beacons"
            severity = "critical"
            tool = "Cobalt Strike"
            category = "Post-Exploitation Framework"
        strings:
            $s1 = "beacon.dll" ascii nocase
            $s2 = "ReflectiveLoader" ascii
            $s3 = "beacon.x64.dll" ascii nocase
            $s4 = "%s (admin)" ascii
            $ua = "Mozilla/5.0 (Windows; U; MSIE" ascii
            $pipe = "\\\\.\\pipe\\MSSE-" ascii
        condition:
            2 of them
    }
    
    rule APT_Metasploit_Meterpreter {
        meta:
            description = "Detects Metasploit Meterpreter payloads"
            severity = "high"
            tool = "Metasploit"
            category = "Post-Exploitation Framework"
        strings:
            $s1 = "meterpreter" nocase
            $s2 = "ReflectiveLoader" ascii
            $s3 = "stdapi_" ascii
            $s4 = "priv_elevate_" ascii
            $ext1 = ".dll" ascii
            $func = "DllMain" ascii
        condition:
            any of ($s*) or (3 of them)
    }
    
    rule APT_Mimikatz_Indicators {
        meta:
            description = "Advanced Mimikatz detection"
            severity = "critical"
            tool = "Mimikatz"
            category = "Credential Dumping"
        strings:
            $s1 = "sekurlsa::logonpasswords" ascii nocase
            $s2 = "lsadump::sam" ascii nocase
            $s3 = "privilege::debug" ascii nocase
            $s4 = "gentilkiwi" ascii nocase
            $s5 = "mimikatz" ascii nocase
            $func1 = "kuhl_m_" ascii
            $func2 = "kull_m_" ascii
            $api1 = "LsaCallAuthenticationPackage" ascii
            $api2 = "SamEnumerateUsersInDomain" ascii
        condition:
            2 of ($s*) or 2 of ($func*) or (any of ($s*) and any of ($api*))
    }
    
    rule APT_Empire_PowerShell {
        meta:
            description = "Detects PowerShell Empire framework"
            severity = "high"
            tool = "Empire"
            category = "Post-Exploitation Framework"
        strings:
            $s1 = "Invoke-Empire" ascii nocase
            $s2 = "Start-Negotiate" ascii
            $s3 = "routing_packet" ascii
            $s4 = "AgentResults" ascii
            $empire = "empire" nocase
        condition:
            2 of them
    }
    
    rule APT_Lazarus_Group {
        meta:
            description = "Detects Lazarus Group malware indicators"
            severity = "critical"
            threat_actor = "Lazarus Group"
            aka = "Hidden Cobra, APT38"
        strings:
            $s1 = "D9AF5C08-196B-47C4-883D-3E730600E4D9" ascii
            $s2 = "Global\\BPALPC" ascii
            $s3 = "taskhostex.exe" ascii
            $pe_timestamp = {60 72 5F 4E}
            $mutex = "ServiceEntryPointThread" ascii
        condition:
            2 of them
    }
    
    rule APT_FancyBear_Sofacy {
        meta:
            description = "Detects Fancy Bear/Sofacy/APT28 malware"
            severity = "critical"
            threat_actor = "Fancy Bear"
            aka = "APT28, Sofacy, Sednit"
        strings:
            $s1 = "XTunnel" ascii
            $s2 = "HIDEDRV" ascii
            $s3 = "XAgent" ascii
            $url = "advstoreshell.com" ascii
            $url2 = "adobeair-updates.com" ascii
        condition:
            any of them
    }
    
    rule APT_CozyBear_APT29 {
        meta:
            description = "Detects Cozy Bear/APT29 indicators"
            severity = "critical"
            threat_actor = "Cozy Bear"
            aka = "APT29, The Dukes"
        strings:
            $s1 = "SeaDuke" ascii nocase
            $s2 = "CloudDuke" ascii nocase
            $s3 = "CosmicDuke" ascii nocase
            $mutex = "Global\\{" ascii
            $api = "WinHttpOpen" ascii
        condition:
            any of ($s*) or ($mutex and $api)
    }
    
    // ==================== Information Stealers ====================
    
    rule InfoStealer_AgentTesla {
        meta:
            description = "Detects Agent Tesla information stealer"
            severity = "high"
            malware_family = "AgentTesla"
        strings:
            $s1 = "agent tesla" nocase
            $s2 = "get_OSFullName" ascii
            $s3 = "get_Clipboard" ascii
            $smtp = "SmtpClient" ascii
            $ftp = "FtpWebRequest" ascii
            $screenshot = "CopyFromScreen" ascii
        condition:
            $s1 or (2 of ($s2, $s3, $smtp, $ftp, $screenshot))
    }
    
    rule InfoStealer_Formbook {
        meta:
            description = "Detects Formbook information stealer"
            severity = "high"
            malware_family = "Formbook"
            aka = "xLoader"
        strings:
            $inject1 = {8B 45 ?? 8B 4D ?? 8D 54 08 ?? 89 55 ??}
            $inject2 = {33 C0 89 45 ?? 89 45 ?? C7 45}
            $api1 = "NtUnmapViewOfSection" ascii
            $api2 = "NtWriteVirtualMemory" ascii
            $mutex = "XLOADERMutex" ascii
        condition:
            2 of ($inject*) or 2 of ($api*) or $mutex
    }
    
    rule InfoStealer_Raccoon {
        meta:
            description = "Detects Raccoon Stealer"
            severity = "high"
            malware_family = "Raccoon"
        strings:
            $s1 = "Raccoon" ascii nocase
            $s2 = "machineId" ascii
            $s3 = "botnet" ascii
            $api1 = "sqlite3_open" ascii
            $api2 = "CryptUnprotectData" ascii
            $telegram = "api.telegram.org" ascii nocase
        condition:
            ($s1 and any of ($s2, $s3)) or (2 of ($api*) and $telegram)
    }
    
    rule InfoStealer_Vidar {
        meta:
            description = "Detects Vidar information stealer"
            severity = "high"
            malware_family = "Vidar"
        strings:
            $s1 = "Vidar" ascii nocase
            $profile = "profile.txt" ascii
            $screen = "screen.jpg" ascii
            $api1 = "GetAdaptersInfo" ascii
            $api2 = "GetVolumeInformationW" ascii
        condition:
            $s1 or (any of ($profile, $screen) and 2 of ($api*))
    }
    
    rule InfoStealer_LokiBot {
        meta:
            description = "Detects Loki Bot information stealer"
            severity = "high"
            malware_family = "LokiBot"
        strings:
            $s1 = "Loki" ascii
            $mutex = "3749282D" ascii
            $api1 = "NtSetInformationThread" ascii
            $api2 = "GetKeyboardState" ascii
            $url = "kbfvzoboss" ascii
        condition:
            ($s1 and $mutex) or 2 of ($api*) or $url
    }
    
    rule InfoStealer_AZORult_Advanced {
        meta:
            description = "Advanced Azorult stealer detection"
            severity = "high"
            malware_family = "Azorult"
        strings:
            $cfg = "config.dat" ascii
            $url = "gate.php" ascii
            $panel = "panel/login" ascii
            $mutex = "Global\\{F4" ascii
            $s1 = "azorult" ascii nocase
            $s2 = "Passwords_" ascii
            $s3 = "Autofill_" ascii
        condition:
            2 of ($cfg, $url, $panel, $s*) or ($mutex and any of ($cfg, $url))
    }
    
    rule InfoStealer_RedLine_Advanced {
        meta:
            description = "Advanced RedLine stealer detection"
            severity = "high"
            malware_family = "RedLine"
        strings:
            $s1 = "RedLine" ascii
            $s2 = "BrowserData" ascii
            $s3 = "System.Management.Automation" ascii
            $api1 = "CryptProtectData" ascii
            $cfg = "TelegramBotToken" ascii
            $path = "\\Local State" ascii
        condition:
            any of ($s*) or ($api1 and ($cfg or $path))
    }
    
    rule InfoStealer_StealC {
        meta:
            description = "Detects StealC information stealer"
            severity = "high"
            malware_family = "StealC"
            reference = "Vidar successor"
        strings:
            $s1 = "StealC" ascii nocase
            $s2 = "sqlite_" ascii
            $s3 = "Login Data" ascii wide
            $s4 = "Web Data" ascii wide
            $api = "CryptUnprotectData" ascii
        condition:
            ($s1 and any of ($s2, $s3, $s4)) or (2 of ($s2, $s3, $s4) and $api)
    }
    
    // ==================== Advanced Process Injection & Code Injection ====================
    
    rule Process_Injection_Classic {
        meta:
            description = "Classic process injection technique"
            severity = "critical"
            technique = "Process Injection"
        strings:
            $api1 = "OpenProcess" ascii
            $api2 = "VirtualAllocEx" ascii
            $api3 = "WriteProcessMemory" ascii
            $api4 = "CreateRemoteThread" ascii
            $api5 = "NtCreateThreadEx" ascii
        condition:
            all of ($api1, $api2, $api3) and any of ($api4, $api5)
    }
    
    rule Process_Hollowing {
        meta:
            description = "Process hollowing technique"
            severity = "critical"
            technique = "Process Hollowing"
        strings:
            $api1 = "CreateProcess" ascii
            $api2 = "NtUnmapViewOfSection" ascii
            $api3 = "VirtualAllocEx" ascii
            $api4 = "WriteProcessMemory" ascii
            $api5 = "SetThreadContext" ascii
            $api6 = "ResumeThread" ascii
        condition:
            4 of them
    }
    
    rule APC_Injection {
        meta:
            description = "APC queue injection technique"
            severity = "critical"
            technique = "APC Injection"
        strings:
            $api1 = "OpenThread" ascii
            $api2 = "QueueUserAPC" ascii
            $api3 = "VirtualAllocEx" ascii
            $api4 = "WriteProcessMemory" ascii
        condition:
            all of them
    }
    
    rule Reflective_DLL_Injection {
        meta:
            description = "Reflective DLL injection"
            severity = "critical"
            technique = "Reflective DLL Injection"
        strings:
            $s1 = "ReflectiveLoader" ascii
            $s2 = "GetProcAddress" ascii
            $s3 = "LoadLibrary" ascii
            $s4 = "VirtualAlloc" ascii
        condition:
            ($s1 and 2 of ($s2, $s3, $s4)) or all of ($s2, $s3, $s4)
    }
    
    rule Process_Doppelganging {
        meta:
            description = "Process Doppelganging technique"
            severity = "critical"
            technique = "Process Doppelganging"
            reference = "MITRE ATT&CK T1055.013"
        strings:
            $api1 = "NtCreateTransaction" ascii
            $api2 = "NtCreateSection" ascii
            $api3 = "NtRollbackTransaction" ascii
            $api4 = "CreateProcessEx" ascii
        condition:
            3 of them
    }
    
    rule Atom_Bombing {
        meta:
            description = "AtomBombing code injection technique"
            severity = "critical"
            technique = "AtomBombing"
        strings:
            $api1 = "GlobalAddAtom" ascii
            $api2 = "NtQueueApcThread" ascii
            $api3 = "GlobalGetAtomName" ascii
        condition:
            all of them
    }
    
    rule Thread_Execution_Hijacking {
        meta:
            description = "Thread execution hijacking"
            severity = "critical"
            technique = "Thread Execution Hijacking"
        strings:
            $api1 = "CreateToolhelp32Snapshot" ascii
            $api2 = "Thread32First" ascii
            $api3 = "SuspendThread" ascii
            $api4 = "SetThreadContext" ascii
            $api5 = "ResumeThread" ascii
        condition:
            4 of them
    }
    
    rule VDSO_Hijacking {
        meta:
            description = "VDSO hijacking (Linux)"
            severity = "critical"
            technique = "VDSO Hijacking"
            platform = "Linux"
        strings:
            $s1 = "linux-vdso" ascii
            $api1 = "ptrace" ascii
            $api2 = "process_vm_writev" ascii
        condition:
            $s1 and any of ($api*)
    }
    
    // ==================== Keyloggers ====================
    
    rule Keylogger_Hooks {
        meta:
            description = "Keyboard hook-based keylogger"
            severity = "high"
            category = "Keylogger"
        strings:
            $api1 = "SetWindowsHookEx" ascii
            $api2 = "GetAsyncKeyState" ascii
            $api3 = "GetForegroundWindow" ascii
            $api4 = "GetWindowText" ascii
            $const = {0D 00 00 00} // WH_KEYBOARD_LL = 13
        condition:
            ($api1 and $api2) or ($api1 and $api3 and $api4) or $const
    }
    
    rule Keylogger_RawInput {
        meta:
            description = "Raw input keylogger"
            severity = "high"
            category = "Keylogger"
        strings:
            $api1 = "RegisterRawInputDevices" ascii
            $api2 = "GetRawInputData" ascii
            $api3 = "DefWindowProc" ascii
        condition:
            all of them
    }
    
    // ==================== Credential Theft ====================
    
    rule Mimikatz {
        meta:
            description = "Detects Mimikatz credential dumping tool"
            severity = "critical"
            tool = "Mimikatz"
        strings:
            $s1 = "mimikatz" ascii nocase
            $s2 = "sekurlsa" ascii
            $s3 = "kerberos" ascii
            $s4 = "gentilkiwi" ascii
            $func1 = "LsaEnumerateLogonSessions" ascii
            $func2 = "SamEnumerateUsersInDomain" ascii
        condition:
            2 of ($s*) or any of ($func*)
    }
    
    rule Credential_Dumping_LSASS {
        meta:
            description = "LSASS memory credential dumping"
            severity = "critical"
            technique = "LSASS Dumping"
        strings:
            $proc = "lsass.exe" ascii nocase
            $api1 = "MiniDumpWriteDump" ascii
            $api2 = "CreateFileW" ascii
            $api3 = "OpenProcess" ascii
        condition:
            ($proc and $api1) or all of ($api*)
    }
    
    rule Browser_Password_Stealer {
        meta:
            description = "Browser password/cookie stealer"
            severity = "high"
            category = "Credential Theft"
        strings:
            $chrome1 = "Login Data" ascii wide
            $chrome2 = "Cookies" ascii wide
            $firefox = "Firefox" ascii wide
            $edge = "Edge" ascii wide
            $decrypt = "CryptUnprotectData" ascii
        condition:
            any of ($chrome*, $firefox, $edge) and $decrypt
    }
    
    // ==================== Persistence Mechanisms ====================
    
    rule Persistence_Registry_Run {
        meta:
            description = "Registry Run key persistence"
            severity = "high"
            technique = "Registry Run Keys"
        strings:
            $reg1 = "CurrentVersion" ascii wide nocase
            $api1 = "RegSetValueEx" ascii
            $api2 = "RegCreateKeyEx" ascii
        condition:
            $reg1 and any of ($api*)
    }
    
    rule Persistence_Scheduled_Task {
        meta:
            description = "Scheduled task persistence"
            severity = "high"
            technique = "Scheduled Task"
        strings:
            $cmd1 = "schtasks" ascii wide nocase
            $cmd2 = "/create" ascii wide nocase
            $api1 = "ITaskScheduler" ascii
            $api2 = "ITaskService" ascii
        condition:
            ($cmd1 and $cmd2) or any of ($api*)
    }
    
    rule Persistence_Startup_Folder {
        meta:
            description = "Startup folder persistence"
            severity = "medium"
            technique = "Startup Folder"
        strings:
            $path1 = "Startup" ascii wide nocase
            $api = "SHGetFolderPath" ascii
        condition:
            $path1 and $api
    }
    
    // ==================== Network Activity ====================
    
    rule Reverse_Shell {
        meta:
            description = "Reverse shell indicators"
            severity = "critical"
            category = "Backdoor"
        strings:
            $cmd1 = "cmd.exe" ascii wide nocase
            $cmd2 = "/bin/sh" ascii
            $cmd3 = "/bin/bash" ascii
            $net1 = "WSAStartup" ascii
            $net2 = "connect" ascii
            $net3 = "recv" ascii
            $pipe = "CreatePipe" ascii
        condition:
            any of ($cmd*) and 2 of ($net*) and $pipe
    }
    
    rule C2_Beaconing {
        meta:
            description = "Command and control beaconing"
            severity = "high"
            category = "C2 Communication"
        strings:
            $http1 = "POST" ascii nocase
            $http2 = "User-Agent:" ascii nocase
            $http3 = "Content-Type:" ascii nocase
            $enc1 = "base64" ascii nocase
            $enc2 = "AES" ascii nocase
            $enc3 = "RC4" ascii nocase
        condition:
            2 of ($http*) and any of ($enc*)
    }
    
    rule Suspicious_Network_APIs {
        meta:
            description = "Suspicious network API usage"
            severity = "high"
            category = "Network Activity"
        strings:
            $api1 = "InternetOpen" ascii
            $api2 = "InternetConnect" ascii
            $api3 = "InternetOpenUrl" ascii
            $api4 = "InternetReadFile" ascii
            $api5 = "URLDownloadToFile" ascii
            $api6 = "HttpSendRequest" ascii
        condition:
            3 of them
    }
    
    // ==================== Packers & Obfuscation ====================
    
    rule UPX_Packer {
        meta:
            description = "UPX packer detected"
            severity = "medium"
            packer = "UPX"
        strings:
            $upx1 = "UPX0" ascii
            $upx2 = "UPX1" ascii
            $upx3 = "UPX!" ascii
        condition:
            any of them
    }
    
    rule VMProtect_Packer {
        meta:
            description = "VMProtect packer detected"
            severity = "medium"
            packer = "VMProtect"
        strings:
            $s1 = ".vmp0" ascii
            $s2 = ".vmp1" ascii
            $s3 = "VMProtect" ascii
        condition:
            any of them
    }
    
    rule Themida_Packer {
        meta:
            description = "Themida/Winlicense packer detected"
            severity = "medium"
            packer = "Themida"
        strings:
            $s1 = ".themida" ascii
            $s2 = "Themida" ascii
            $s3 = "WinLicense" ascii
            $s4 = "Oreans" ascii
        condition:
            any of them
    }
    
    rule Enigma_Protector {
        meta:
            description = "Enigma Protector packer detected"
            severity = "medium"
            packer = "Enigma"
        strings:
            $s1 = ".enigma1" ascii
            $s2 = ".enigma2" ascii
            $s3 = "Enigma Protector" ascii
        condition:
            any of them
    }
    
    rule ASPack_Packer {
        meta:
            description = "ASPack packer detected"
            severity = "medium"
            packer = "ASPack"
        strings:
            $s1 = "ASPack" ascii
            $s2 = ".aspack" ascii
            $s3 = ".adata" ascii
        condition:
            any of them
    }
    
    rule PECompact_Packer {
        meta:
            description = "PECompact packer detected"
            severity = "medium"
            packer = "PECompact"
        strings:
            $s1 = "PECompact2" ascii
            $s2 = "pec1" ascii
            $s3 = "pec2" ascii
        condition:
            any of them
    }
    
    rule Armadillo_Packer {
        meta:
            description = "Armadillo/Silicon Realms packer"
            severity = "medium"
            packer = "Armadillo"
        strings:
            $s1 = "Silicon Realms" ascii
            $s2 = "Armadillo" ascii
            $s3 = ".srt" ascii
        condition:
            any of them
    }
    
    rule Dotfuscator {
        meta:
            description = "Dotfuscator .NET obfuscator"
            severity = "low"
            packer = "Dotfuscator"
            platform = ".NET"
        strings:
            $s1 = "Dotfuscator" ascii
            $s2 = "DotfuscatorAttribute" ascii
        condition:
            any of them
    }
    
    rule ConfuserEx {
        meta:
            description = "ConfuserEx .NET obfuscator"
            severity = "medium"
            packer = "ConfuserEx"
            platform = ".NET"
        strings:
            $s1 = "ConfuserEx" ascii
            $s2 = "Confuser.Runtime" ascii
        condition:
            any of them
    }
    
    rule High_Entropy_Section {
        meta:
            description = "High entropy section (possible encryption/packing)"
            severity = "medium"
            category = "Obfuscation"
        condition:
            // This is a placeholder - actual entropy checking done in PE analysis
            false
    }
    
    // ==================== Advanced Anti-Analysis Techniques ====================
    
    rule Anti_Debug_APIs {
        meta:
            description = "Anti-debugging API usage"
            severity = "high"
            technique = "Anti-Debugging"
            reference = "MITRE ATT&CK T1622"
        strings:
            $api1 = "IsDebuggerPresent" ascii
            $api2 = "CheckRemoteDebuggerPresent" ascii
            $api3 = "NtQueryInformationProcess" ascii
            $api4 = "OutputDebugString" ascii
            $api5 = "DebugActiveProcess" ascii
            $api6 = "NtSetInformationThread" ascii
            $api7 = "ZwSetInformationThread" ascii
        condition:
            2 of them
    }
    
    rule Anti_Debug_Advanced {
        meta:
            description = "Advanced anti-debugging techniques"
            severity = "high"
            technique = "Anti-Debugging"
        strings:
            $peb_check = {64 A1 30 00 00 00 8B 40 02 85 C0}
            $heap_flags = {64 A1 30 00 00 00 8B 40 18 8B 40 10}
            $api1 = "NtQuerySystemInformation" ascii
            $api2 = "NtQueryObject" ascii
            $timing = "QueryPerformanceCounter" ascii
        condition:
            any of ($peb_check, $heap_flags) or (2 of ($api*, $timing))
    }
    
    rule Anti_VM {
        meta:
            description = "Anti-VM detection techniques"
            severity = "high"
            technique = "Anti-VM"
        strings:
            $vm1 = "VMware" ascii nocase
            $vm2 = "VirtualBox" ascii nocase
            $vm3 = "VBOX" ascii nocase
            $vm4 = "QEMU" ascii nocase
            $vm5 = "Xen" ascii nocase
            $reg1 = "HARDWARE" ascii nocase
            $reg2 = "DEVICEMAP" ascii nocase
        condition:
            2 of ($vm*) or 2 of ($reg*)
    }
    
    rule Anti_Sandbox {
        meta:
            description = "Anti-sandbox techniques"
            severity = "high"
            technique = "Anti-Sandbox"
        strings:
            $sleep1 = "Sleep" ascii
            $sleep2 = "NtDelayExecution" ascii
            $time1 = "GetTickCount" ascii
            $time2 = "timeGetTime" ascii
            $time3 = "QueryPerformanceCounter" ascii
            $user1 = "GetCursorPos" ascii
            $user2 = "GetLastInputInfo" ascii
        condition:
            (any of ($sleep*) and any of ($time*)) or any of ($user*)
    }
    
    // ==================== Cryptominers ====================
    
    rule Cryptocurrency_Miner {
        meta:
            description = "Cryptocurrency miner detected"
            severity = "high"
            category = "Cryptominer"
        strings:
            $coin1 = "monero" ascii nocase
            $coin2 = "xmrig" ascii nocase
            $coin3 = "stratum+tcp" ascii nocase
            $coin4 = "cryptonight" ascii nocase
            $pool1 = "pool.minexmr" ascii nocase
            $pool2 = "pool.supportxmr" ascii nocase
        condition:
            2 of ($coin*) or any of ($pool*)
    }
    
    // ==================== Downloaders & Droppers ====================
    
    rule Downloader_Generic {
        meta:
            description = "Generic downloader behavior"
            severity = "high"
            category = "Downloader"
        strings:
            $api1 = "URLDownloadToFile" ascii
            $api2 = "InternetReadFile" ascii
            $api3 = "WinHttpReadData" ascii
            $exec1 = "ShellExecute" ascii
            $exec2 = "CreateProcess" ascii
            $exec3 = "WinExec" ascii
            $url1 = ".exe" ascii nocase
            $url2 = ".dll" ascii nocase
            $url3 = ".bat" ascii nocase
        condition:
            any of ($api*) and any of ($exec*) and any of ($url*)
    }
    
    // ==================== Document Exploits ====================
    
    rule Suspicious_Office_Macros {
        meta:
            description = "Suspicious Office macro indicators"
            severity = "high"
            category = "Macro Malware"
        strings:
            $auto1 = "AutoOpen" ascii nocase
            $auto2 = "AutoExec" ascii nocase
            $auto3 = "Document_Open" ascii nocase
            $auto4 = "Workbook_Open" ascii nocase
            $cmd1 = "WScript.Shell" ascii nocase
            $cmd2 = "Shell" ascii nocase
            $cmd3 = "CreateObject" ascii nocase
            $download = "MSXML2.XMLHTTP" ascii nocase
        condition:
            any of ($auto*) and (any of ($cmd*) or $download)
    }
    
    rule PDF_Exploit {
        meta:
            description = "Suspicious PDF with potential exploit"
            severity = "high"
            category = "Exploit"
        strings:
            $pdf = "%PDF" ascii
            $js1 = "/JavaScript" ascii
            $js2 = "/JS" ascii
            $aa = "/OpenAction" ascii
            $embed = "/EmbeddedFile" ascii
            $launch = "/Launch" ascii
        condition:
            $pdf and (($js1 or $js2) and ($aa or $embed or $launch))
    }
    
    // ==================== Webshells ====================
    
    rule Webshell_Generic_PHP {
        meta:
            description = "Generic PHP webshell"
            severity = "critical"
            category = "Webshell"
        strings:
            $php = "<?php" ascii nocase
            $exec1 = "eval(" ascii nocase
            $exec2 = "system(" ascii nocase
            $exec3 = "exec(" ascii nocase
            $exec4 = "shell_exec(" ascii nocase
            $exec5 = "passthru(" ascii nocase
            $post = "$_POST" ascii nocase
            $get = "$_GET" ascii nocase
            $request = "$_REQUEST" ascii nocase
        condition:
            $php and 2 of ($exec*) and any of ($post, $get, $request)
    }
    
    rule Webshell_Generic_ASPX {
        meta:
            description = "Generic ASPX webshell"
            severity = "critical"
            category = "Webshell"
        strings:
            $aspx1 = "<%@ Page" ascii nocase
            $aspx2 = "runat=" ascii nocase
            $exec1 = "Process.Start" ascii nocase
            $exec2 = "cmd.exe" ascii nocase
            $exec3 = "ProcessStartInfo" ascii nocase
            $request = "Request.Form" ascii nocase
        condition:
            any of ($aspx*) and any of ($exec*) and $request
    }
    
    // ==================== Suspicious Strings & Patterns ====================
    
    rule Suspicious_PowerShell {
        meta:
            description = "Suspicious PowerShell command patterns"
            severity = "high"
            category = "PowerShell"
        strings:
            $ps1 = "powershell" ascii nocase
            $enc1 = "-encodedcommand" ascii nocase
            $enc2 = "-enc" ascii nocase
            $bypass1 = "-ExecutionPolicy Bypass" ascii nocase
            $bypass2 = "-ep bypass" ascii nocase
            $hidden = "-WindowStyle Hidden" ascii nocase
            $download = "DownloadString" ascii nocase
            $invoke = "IEX" ascii nocase
        condition:
            $ps1 and (any of ($enc*) or any of ($bypass*) or $hidden or ($download and $invoke))
    }
    
    rule Suspicious_Base64 {
        meta:
            description = "Large base64 encoded data (possible payload)"
            severity = "medium"
            category = "Obfuscation"
        strings:
            $b64_1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii
            $b64_2 = "base64" ascii nocase
        condition:
            any of them
    }
    
    rule Suspicious_URL_Patterns {
        meta:
            description = "Suspicious URL patterns"
            severity = "medium"
            category = "Network IOC"
        strings:
            $http = "http://" ascii nocase
            $https = "https://" ascii nocase
            $pastebin = "pastebin.com" ascii nocase
            $discord = "discord.com/api/webhooks" ascii nocase
            $telegram = "api.telegram.org" ascii nocase
        condition:
            any of them
    }

    // ==================== Additional Threat Families ====================
    
    rule InfoStealer_Azorult {
        meta:
            description = "Detects Azorult information stealer"
            severity = "high"
            malware_family = "Azorult"
        strings:
            $cfg = "config.dat" ascii
            $url = "gate.php" ascii
            $panel = "panel/login" ascii
            $mutex = "Global\\{F4" ascii
            $panel2 = "azorult" ascii nocase
        condition:
            2 of ($cfg, $url, $panel, $panel2) or ($mutex and any of ($cfg, $url, $panel))
    }

    rule Trojan_QakBot {
        meta:
            description = "Detects QakBot/QBot banking trojan"
            severity = "critical"
            malware_family = "QakBot"
        strings:
            $str1 = "QBot" ascii
            $str2 = "qakbot" ascii nocase
            $path = "AppData\\Roaming\\Microsoft\\" ascii
            $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
            $task = "schtasks /create" ascii
        condition:
            (any of ($str*)) or ($path and ($reg1 or $task))
    }

    rule Loader_TrickBot {
        meta:
            description = "Detects TrickBot loader artifacts"
            severity = "critical"
            malware_family = "TrickBot"
        strings:
            $group = "client_id" ascii
            $config = "sinj" ascii
            $module = "megalon" ascii
            $inject = "dpost" ascii
            $mutex = "Global\\TbMutex" ascii
        condition:
            2 of ($group, $config, $module, $inject) or ($mutex and any of ($group, $module, $inject))
    }

    rule Ransomware_Cerber {
        meta:
            description = "Detects Cerber ransomware"
            severity = "critical"
            malware_family = "Cerber"
        strings:
            $ext1 = ".cerber" ascii
            $ext2 = ".cerber2" ascii
            $note1 = "_R_E_A_D___T_H_I_S_" ascii
            $note2 = "@Please_Read_Me@.txt" ascii
            $voice = "readme.hta" ascii
        condition:
            any of ($ext*) or 2 of ($note*, $voice)
    }

    rule Botnet_Mirai {
        meta:
            description = "Detects Mirai IoT botnet binaries"
            severity = "high"
            malware_family = "Mirai"
        strings:
            $str1 = "/bin/busybox" ascii
            $str2 = "Mirai" ascii
            $str3 = "/bin/echo -ne" ascii
            $cmd = "table_init" ascii
            $killed = "/proc/%d/stat" ascii
        condition:
            2 of ($str1, $str2, $str3, $cmd, $killed)
    }

    rule Stealer_RedLine {
        meta:
            description = "Detects RedLine stealer"
            severity = "high"
            malware_family = "RedLine"
        strings:
            $str1 = "RedLine" ascii
            $str2 = "BrowserData" ascii
            $api1 = "CryptProtectData" ascii
            $ps = "System.Management.Automation" ascii
            $cfg = "TelegramBotToken" ascii
        condition:
            any of ($str1, $str2) or (any of ($api1, $ps) and $cfg)
    }

    rule LateralMovement_SMBExec {
        meta:
            description = "Indicators of SMB exec style lateral movement"
            severity = "high"
            technique = "Lateral Movement"
        strings:
            $svc = "sc \\\\" ascii nocase
            $copy = "copy \\\\" ascii nocase
            $psexec = "psexec" ascii nocase
            $wmic = "wmic /node:" ascii nocase
            $creds = "cmdkey /add:" ascii nocase
        condition:
            ($svc and $copy) or ($psexec and $wmic) or ($wmic and $creds)
    }
    
    // ==================== .NET Malware Detection ====================
    
    rule DotNet_Suspicious_Obfuscation {
        meta:
            description = "Suspicious .NET obfuscation patterns"
            severity = "high"
            platform = ".NET"
        strings:
            $mz = "MZ"
            $net = "mscoree.dll" nocase
            $obf1 = /[A-Z]{50,}/ ascii
            $obf2 = /\\x00[a-z]\\x00[a-z]\\x00[a-z]\\x00[a-z]\\x00[a-z]\\x00/
            $invoke = "System.Reflection.Assembly" ascii
            $load = "Load" ascii
        condition:
            $mz at 0 and $net and ($obf1 or $obf2) and $invoke and $load
    }
    
    rule DotNet_Malicious_Capabilities {
        meta:
            description = "Suspicious .NET capabilities combination"
            severity = "high"
            platform = ".NET"
        strings:
            $mz = "MZ"
            $net = "mscoree.dll" nocase
            $download = "System.Net.WebClient" ascii
            $download2 = "DownloadFile" ascii
            $download3 = "DownloadString" ascii
            $exec1 = "Process.Start" ascii
            $exec2 = "System.Diagnostics.Process" ascii
            $persist1 = "Microsoft.Win32.Registry" ascii
            $persist2 = "CurrentVersion\\Run" ascii
        condition:
            $mz at 0 and $net and 
            (any of ($download*) and any of ($exec*)) or
            (any of ($download*) and any of ($persist*))
    }
    
    rule DotNet_RAT_Generic {
        meta:
            description = "Generic .NET RAT indicators"
            severity = "critical"
            platform = ".NET"
        strings:
            $mz = "MZ"
            $net = "mscoree.dll" nocase
            $socket = "System.Net.Sockets" ascii
            $tcp = "TcpClient" ascii
            $stream = "NetworkStream" ascii
            $cmd1 = "cmd.exe" ascii
            $cmd2 = "/c" ascii
            $screenshot = "CopyFromScreen" ascii
            $keylog = "GetAsyncKeyState" ascii
        condition:
            $mz at 0 and $net and $socket and $tcp and 
            (any of ($cmd*) or $screenshot or $keylog)
    }
    
    rule DotNet_Stealer_Credentials {
        meta:
            description = "Detects .NET credential stealing capabilities"
            severity = "critical"
            platform = ".NET"
        strings:
            $mz = "MZ"
            $net = "mscoree.dll" nocase
            $chrome = "Google\\Chrome\\User Data" ascii wide
            $firefox = "Mozilla\\Firefox\\Profiles" ascii wide
            $logindata = "Login Data" ascii wide
            $cookies = "Cookies" ascii wide
            $decrypt = "CryptUnprotectData" ascii
            $sqlite = "sqlite" ascii nocase
        condition:
            $mz at 0 and $net and 
            (any of ($chrome, $firefox) and any of ($logindata, $cookies)) and
            ($decrypt or $sqlite)
    }
    
    rule DotNet_Ransomware_Indicators {
        meta:
            description = "Detects .NET ransomware behavior"
            severity = "critical"
            platform = ".NET"
        strings:
            $mz = "MZ"
            $net = "mscoree.dll" nocase
            $crypto1 = "System.Security.Cryptography" ascii
            $crypto2 = "AesManaged" ascii
            $crypto3 = "RijndaelManaged" ascii
            $file1 = "Directory.GetFiles" ascii
            $file2 = "File.WriteAllBytes" ascii
            $ext1 = ".encrypted" ascii
            $ext2 = ".locked" ascii
            $bitcoin = "bitcoin" ascii nocase
            $ransom = "ransom" ascii nocase
        condition:
            $mz at 0 and $net and 
            any of ($crypto*) and any of ($file*) and
            (any of ($ext*) or any of ($bitcoin, $ransom))
    }
    
    rule Suspicious_Large_Overlay {
        meta:
            description = "Detects files with large overlay data (possible embedded payload)"
            severity = "medium"
            category = "Suspicious Structure"
        strings:
            $mz = "MZ"
        condition:
            $mz at 0 and filesize > 1MB
    }
    
    rule High_Entropy_Embedded_Data {
        meta:
            description = "High entropy suggests encrypted or compressed payload"
            severity = "medium"
            category = "Obfuscation"
        strings:
            $mz = "MZ"
        condition:
            $mz at 0 and filesize > 500KB
    }
    """
    
    try:
        rules = yara.compile(source=default_rules)
        matches = rules.match(file_path)
        
        results = []
        for match in matches:
            matched_strings = []
            for s in match.strings:
                try:
                    # s is a StringMatch object with attributes: identifier, instances
                    identifier = s.identifier if hasattr(s, 'identifier') else str(s)
                    # Get instances of the match
                    instances = s.instances if hasattr(s, 'instances') else []
                    for instance in instances[:5]:  # Limit to 5 instances per string
                        offset = instance.offset if hasattr(instance, 'offset') else 0
                        matched_data = instance.matched_data if hasattr(instance, 'matched_data') else b''
                        # Safely decode the matched data
                        if isinstance(matched_data, bytes):
                            data_str = matched_data[:100].decode('utf-8', errors='ignore')
                        else:
                            data_str = str(matched_data)[:100]
                        matched_strings.append((identifier, offset, data_str))
                except Exception as e:
                    logger.debug(f"Error processing YARA string match: {e}")
                    continue
            
            results.append({
                'rule': match.rule,
                'namespace': match.namespace,
                'tags': match.tags,
                'meta': match.meta,
                'strings': matched_strings
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
    
    # YARA matches (heavily weighted)
    if 'yara' in analysis_results and isinstance(analysis_results['yara'], list):
        for match in analysis_results['yara']:
            severity = match.get('meta', {}).get('severity', 'medium')
            if severity == 'critical':
                score += 25  # Increased from 20
            elif severity == 'high':
                score += 18  # Increased from 15
            elif severity == 'medium':
                score += 12  # Increased from 10
            else:
                score += 6   # Increased from 5
    
    # PE suspicious flags
    if 'pe_analysis' in analysis_results:
        pe = analysis_results['pe_analysis']
        if isinstance(pe, dict) and 'suspicious_flags' in pe:
            flags = pe['suspicious_flags']
            score += min(len(flags) * 5, 20)
            
            # Large overlay is very suspicious
            for flag in flags:
                if 'Overlay data present' in flag:
                    overlay_size = pe.get('overlay_size', 0)
                    if overlay_size > 1000000:  # > 1MB
                        score += 20  # Major red flag
                    elif overlay_size > 100000:  # > 100KB
                        score += 10
    
    # IOCs count
    if 'iocs' in analysis_results:
        iocs = analysis_results['iocs']
        score += min(len(iocs.get('urls', [])) * 3, 15)
        score += min(len(iocs.get('ips', [])) * 3, 15)
        score += min(len(iocs.get('domains', [])) * 2, 15)  # Added domains
        score += min(len(iocs.get('registry_keys', [])) * 2, 10)
    
    # High entropy sections
    if 'pe_analysis' in analysis_results and isinstance(analysis_results['pe_analysis'], dict):
        sections = analysis_results['pe_analysis'].get('sections', [])
        high_entropy_count = sum(1 for s in sections if s.get('entropy', 0) > 7.0)
        score += min(high_entropy_count * 8, 20)  # Increased from 5 to 8
    
    # File size anomalies
    file_size = analysis_results.get('sample', {}).get('size', 0)
    if file_size > 10000000:  # Files > 10MB are unusual
        score += 5
    
    return min(score, max_score)


# ============================================================================
# REPORT GENERATION
# ============================================================================

def generate_report(sample_data, analysis_results, output_dir="reports", cli_command=None):
    """Generate comprehensive analysis report"""
    os.makedirs(output_dir, exist_ok=True)
    
    md5 = sample_data['md5']
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(output_dir, f"report_{md5}_{timestamp}.md")
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(f"# Malware Analysis Report\n\n")
        f.write(f"**Generated:** {datetime.now().isoformat()}\n\n")
        
        # CLI command used
        if cli_command:
            f.write(f"**Command:** `{cli_command}`\n\n")
        
        f.write(f"---\n\n")
        
        # Executive Summary
        f.write(f"## Executive Summary\n\n")
        risk_score = analysis_results.get('risk_score', 0)
        yara_matches = analysis_results.get('yara', [])
        
        # Threat classification
        threat_level = "🟢 LOW RISK"
        if risk_score >= 75:
            threat_level = "🔴 CRITICAL THREAT"
        elif risk_score >= 50:
            threat_level = "🟡 MEDIUM THREAT"
        
        f.write(f"**Threat Level:** {threat_level} (Risk Score: {risk_score}/100)\n\n")
        
        # Key findings
        f.write(f"**Key Findings:**\n\n")
        if yara_matches:
            families = set()
            techniques = set()
            for match in yara_matches:
                meta = match.get('meta', {})
                if meta.get('malware_family'):
                    families.add(meta['malware_family'])
                if meta.get('technique'):
                    techniques.add(meta['technique'])
                if meta.get('category'):
                    techniques.add(meta['category'])
            
            if families:
                f.write(f"- **Malware Families Detected:** {', '.join(sorted(families))}\n")
            if techniques:
                f.write(f"- **Techniques/Categories:** {', '.join(sorted(techniques))}\n")
            f.write(f"- **YARA Detections:** {len(yara_matches)} rule(s) matched\n")
        
        pe = analysis_results.get('pe_analysis', {})
        if pe and not isinstance(pe, dict) or pe.get('error'):
            f.write(f"- **File Type:** Non-PE or analysis failed\n")
        elif pe:
            if pe.get('suspicious_flags'):
                f.write(f"- **Suspicious Behaviors:** {len(pe['suspicious_flags'])} flag(s)\n")
            if pe.get('is_signed'):
                f.write(f"- **Code Signature:** Present (not validated)\n")
            if pe.get('overlay_size', 0) > 0:
                f.write(f"- **Overlay Data:** {pe['overlay_size']} bytes appended\n")
        
        iocs = analysis_results.get('iocs', {})
        if iocs:
            total_iocs = sum(len(v) for k, v in iocs.items() if isinstance(v, list))
            if total_iocs > 0:
                f.write(f"- **IOCs Extracted:** {total_iocs} indicator(s)\n")
        
        cuckoo_iocs = analysis_results.get('cuckoo_iocs')
        if cuckoo_iocs:
            f.write(f"- **Dynamic Analysis:** Completed via Cuckoo Sandbox\n")
        
        f.write(f"\n---\n\n")
        
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
        f.write(f"| Risk Score | **{analysis_results.get('risk_score', 0)}/100** |\n")
        if sample_data.get('ssdeep') or sample_data.get('tlsh'):
            if sample_data.get('ssdeep'):
                f.write(f"| SSDEEP | `{sample_data['ssdeep']}` |\n")
            if sample_data.get('tlsh'):
                f.write(f"| TLSH | `{sample_data['tlsh']}` |\n")
        if analysis_results.get('pe_analysis'):
            pe = analysis_results['pe_analysis']
            if pe.get('imphash'):
                f.write(f"| imphash | `{pe['imphash']}` |\n")
            f.write("\n")
        
        # YARA matches
        if 'yara' in analysis_results and isinstance(analysis_results['yara'], list) and analysis_results['yara']:
            f.write(f"## YARA Detections\n\n")
            for match in analysis_results['yara']:
                meta = match.get('meta', {})
                severity = meta.get('severity', 'unknown')
                severity_icon = "🔴" if severity == "critical" else "🟠" if severity == "high" else "🟡" if severity == "medium" else "🔵"
                
                f.write(f"### {severity_icon} {match['rule']}\n\n")
                
                # Metadata table
                f.write(f"| Property | Value |\n")
                f.write(f"|----------|-------|\n")
                f.write(f"| **Severity** | {severity.upper()} |\n")
                if meta.get('description'):
                    f.write(f"| **Description** | {meta['description']} |\n")
                if meta.get('malware_family'):
                    f.write(f"| **Malware Family** | {meta['malware_family']} |\n")
                if meta.get('technique'):
                    f.write(f"| **Technique** | {meta['technique']} |\n")
                if meta.get('category'):
                    f.write(f"| **Category** | {meta['category']} |\n")
                if meta.get('tool'):
                    f.write(f"| **Tool** | {meta['tool']} |\n")
                if meta.get('packer'):
                    f.write(f"| **Packer** | {meta['packer']} |\n")
                if match.get('namespace'):
                    f.write(f"| **Namespace** | {match['namespace']} |\n")
                if match.get('tags'):
                    f.write(f"| **Tags** | {', '.join(match['tags'])} |\n")
                f.write(f"\n")
                
                if match.get('strings'):
                    f.write(f"**Matched Strings:** {len(match['strings'])}\n\n")
                    # Show examples with offsets
                    shown = 0
                    for ident, off, s in match['strings']:
                        f.write(f"- `{ident}` @ offset 0x{off:X}: `{s[:80]}`\n")
                        shown += 1
                        if shown >= 5:
                            break
                    if len(match['strings']) > 5:
                        f.write(f"\n*...and {len(match['strings']) - 5} more match(es)*\n")
                    f.write("\n")
        
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
            
            if iocs.get('emails'):
                f.write(f"### Email Addresses ({len(iocs['emails'])})\n\n")
                for email in iocs['emails'][:15]:
                    f.write(f"- `{email}`\n")
                if len(iocs['emails']) > 15:
                    f.write(f"\n*...and {len(iocs['emails']) - 15} more*\n")
                f.write(f"\n")
            
            if iocs.get('registry_keys'):
                f.write(f"### Registry Keys ({len(iocs['registry_keys'])})\n\n")
                for key in iocs['registry_keys'][:15]:
                    f.write(f"- `{key}`\n")
                if len(iocs['registry_keys']) > 15:
                    f.write(f"\n*...and {len(iocs['registry_keys']) - 15} more*\n")
                f.write(f"\n")
            
            if iocs.get('file_paths'):
                f.write(f"### File Paths ({len(iocs['file_paths'])})\n\n")
                for path in iocs['file_paths'][:15]:
                    f.write(f"- `{path}`\n")
                if len(iocs['file_paths']) > 15:
                    f.write(f"\n*...and {len(iocs['file_paths']) - 15} more*\n")
                f.write(f"\n")
        
        # String Analysis
        if 'strings' in analysis_results:
            strings_data = analysis_results['strings']
            f.write(f"## String Analysis\n\n")
            f.write(f"**Total Extracted:**\n")
            f.write(f"- ASCII Strings: {strings_data.get('total_ascii', 0)}\n")
            f.write(f"- Unicode Strings: {strings_data.get('total_unicode', 0)}\n\n")
            
            # Show interesting string samples
            ascii_strs = strings_data.get('ascii', [])
            unicode_strs = strings_data.get('unicode', [])
            
            if ascii_strs:
                f.write(f"**Sample ASCII Strings:**\n\n")
                for s in ascii_strs[:15]:
                    if len(s) > 8:  # Only show interesting ones
                        f.write(f"- `{s[:100]}`\n")
                f.write(f"\n")
            
            if unicode_strs:
                f.write(f"**Sample Unicode Strings:**\n\n")
                for s in unicode_strs[:10]:
                    if len(s) > 8:
                        f.write(f"- `{s[:100]}`\n")
                f.write(f"\n")
        
        # PE Analysis
        if 'pe_analysis' in analysis_results and isinstance(analysis_results['pe_analysis'], dict):
            pe = analysis_results['pe_analysis']
            f.write(f"## PE File Analysis\n\n")
            
            # PE Header Info
            f.write(f"### PE Header Information\n\n")
            f.write(f"| Property | Value |\n")
            f.write(f"|----------|-------|\n")
            if pe.get('machine') is not None:
                machine_name = {0x14c: 'i386', 0x8664: 'x64', 0x1c0: 'ARM', 0xaa64: 'ARM64'}.get(pe['machine'], f"0x{pe['machine']:X}")
                f.write(f"| **Machine Type** | {machine_name} |\n")
            if pe.get('timestamp'):
                f.write(f"| **Compile Time** | {pe['timestamp']} |\n")
            if pe.get('subsystem') is not None:
                subsys_name = {2: 'GUI', 3: 'Console', 1: 'Native'}.get(pe['subsystem'], f"{pe['subsystem']}")
                f.write(f"| **Subsystem** | {subsys_name} |\n")
            if pe.get('entry_point'):
                f.write(f"| **Entry Point** | {pe['entry_point']} |\n")
            if pe.get('image_base'):
                f.write(f"| **Image Base** | {pe['image_base']} |\n")
            if pe.get('imphash'):
                f.write(f"| **Import Hash** | `{pe['imphash']}` |\n")
            if pe.get('is_signed') is not None:
                sig_status = "✓ Signed" if pe['is_signed'] else "✗ Not Signed"
                f.write(f"| **Code Signature** | {sig_status} |\n")
            if pe.get('overlay_size', 0) > 0:
                f.write(f"| **Overlay Size** | {pe['overlay_size']:,} bytes |\n")
            if pe.get('characteristics') is not None:
                f.write(f"| **Characteristics** | 0x{pe['characteristics']:X} |\n")
            if pe.get('dll_characteristics') is not None:
                f.write(f"| **DLL Characteristics** | 0x{pe['dll_characteristics']:X} |\n")
            f.write(f"\n")
            
            if pe.get('suspicious_flags'):
                f.write(f"### ⚠️ Suspicious Indicators ({len(pe['suspicious_flags'])})\n\n")
                for flag in pe['suspicious_flags']:
                    f.write(f"- {flag}\n")
                f.write(f"\n")
            
            if pe.get('sections'):
                f.write(f"### Sections ({len(pe['sections'])})\n\n")
                f.write(f"| Name | Virtual Addr | Virtual Size | Raw Size | Entropy | Characteristics |\n")
                f.write(f"|------|-------------|--------------|----------|---------|------------------|\n")
                for sec in pe['sections']:
                    entropy = sec.get('entropy', 0)
                    entropy_str = f"**{entropy:.2f}**" if entropy > 7.0 else f"{entropy:.2f}"
                    chars = sec.get('characteristics', 0)
                    f.write(f"| {sec['name']} | {sec['virtual_address']} | {sec['virtual_size']:,} | {sec['raw_size']:,} | {entropy_str} | 0x{chars:X} |\n")
                f.write(f"\n")
            
            if pe.get('imports'):
                f.write(f"### Imported DLLs ({len(pe['imports'])})\n\n")
                # Show top imports
                for imp in pe['imports'][:15]:
                    f.write(f"#### {imp['dll']}\n\n")
                    funcs = imp['functions']
                    if funcs:
                        # Show first 10 functions
                        for func in funcs[:10]:
                            f.write(f"- `{func}`\n")
                        if len(funcs) > 10:
                            f.write(f"\n*...and {len(funcs) - 10} more function(s)*\n")
                    f.write(f"\n")
                if len(pe['imports']) > 15:
                    f.write(f"\n*...and {len(pe['imports']) - 15} more DLL(s)*\n\n")
            
            if pe.get('exports'):
                f.write(f"### Exported Functions ({len(pe['exports'])})\n\n")
                for exp in pe['exports'][:20]:
                    f.write(f"- `{exp.get('name', 'N/A')}` (Ordinal: {exp.get('ordinal', 'N/A')}, Address: {exp.get('address', 'N/A')})\n")
                if len(pe['exports']) > 20:
                    f.write(f"\n*...and {len(pe['exports']) - 20} more export(s)*\n")
                f.write(f"\n")
            
            if pe.get('resources'):
                f.write(f"### Resources ({len(pe['resources'])})\n\n")
                f.write(f"| Type | ID | Language | Size |\n")
                f.write(f"|------|----|---------:|------|\n")
                for res in pe['resources'][:20]:
                    f.write(f"| {res.get('type', 'N/A')} | {res.get('id', 'N/A')} | {res.get('lang', 'N/A')} | {res.get('size', 0):,} |\n")
                if len(pe['resources']) > 20:
                    f.write(f"\n*...and {len(pe['resources']) - 20} more resource(s)*\n")
                f.write(f"\n")
        
        # Cuckoo Sandbox Results
        if 'cuckoo_iocs' in analysis_results:
            cuckoo = analysis_results['cuckoo_iocs']
            f.write(f"## Dynamic Analysis (Cuckoo Sandbox)\n\n")
            
            if cuckoo.get('processes'):
                f.write(f"### Processes Created ({len(cuckoo['processes'])})\n\n")
                f.write(f"| Process Name | PID | Parent PID |\n")
                f.write(f"|--------------|-----|------------|\n")
                for proc in cuckoo['processes'][:20]:
                    f.write(f"| {proc.get('name', 'N/A')} | {proc.get('pid', 'N/A')} | {proc.get('parent_id', 'N/A')} |\n")
                if len(cuckoo['processes']) > 20:
                    f.write(f"\n*...and {len(cuckoo['processes']) - 20} more process(es)*\n")
                f.write(f"\n")
            
            if cuckoo.get('mutexes') and len(cuckoo['mutexes']) > 0:
                f.write(f"### Mutexes ({len(cuckoo['mutexes'])})\n\n")
                for mutex in cuckoo['mutexes'][:15]:
                    f.write(f"- `{mutex}`\n")
                if len(cuckoo['mutexes']) > 15:
                    f.write(f"\n*...and {len(cuckoo['mutexes']) - 15} more*\n")
                f.write(f"\n")
            
            if cuckoo.get('files') and len(cuckoo['files']) > 0:
                f.write(f"### Dropped Files ({len(cuckoo['files'])})\n\n")
                for fil in cuckoo['files'][:15]:
                    f.write(f"- `{fil}`\n")
                if len(cuckoo['files']) > 15:
                    f.write(f"\n*...and {len(cuckoo['files']) - 15} more*\n")
                f.write(f"\n")
            
            if cuckoo.get('registry') and len(cuckoo['registry']) > 0:
                f.write(f"### Registry Keys Accessed ({len(cuckoo['registry'])})\n\n")
                for reg in cuckoo['registry'][:15]:
                    f.write(f"- `{reg}`\n")
                if len(cuckoo['registry']) > 15:
                    f.write(f"\n*...and {len(cuckoo['registry']) - 15} more*\n")
                f.write(f"\n")
            
            if cuckoo.get('domains') and len(cuckoo['domains']) > 0:
                f.write(f"### Network - Domains Contacted ({len(cuckoo['domains'])})\n\n")
                for dom in cuckoo['domains'][:20]:
                    f.write(f"- `{dom}`\n")
                if len(cuckoo['domains']) > 20:
                    f.write(f"\n*...and {len(cuckoo['domains']) - 20} more*\n")
                f.write(f"\n")
            
            if cuckoo.get('ips') and len(cuckoo['ips']) > 0:
                f.write(f"### Network - IP Addresses ({len(cuckoo['ips'])})\n\n")
                for ip in cuckoo['ips'][:20]:
                    f.write(f"- `{ip}`\n")
                if len(cuckoo['ips']) > 20:
                    f.write(f"\n*...and {len(cuckoo['ips']) - 20} more*\n")
                f.write(f"\n")
            
            if cuckoo.get('urls') and len(cuckoo['urls']) > 0:
                f.write(f"### Network - URLs Accessed ({len(cuckoo['urls'])})\n\n")
                for url in cuckoo['urls'][:20]:
                    f.write(f"- `{url}`\n")
                if len(cuckoo['urls']) > 20:
                    f.write(f"\n*...and {len(cuckoo['urls']) - 20} more*\n")
                f.write(f"\n")
        
        # Advanced Analysis Results
        if 'behavioral_patterns' in analysis_results or 'api_sequences' in analysis_results or 'enriched_iocs' in analysis_results:
            f.write(f"## 🔬 Advanced Analysis\n\n")
            
            # Detailed scoring breakdown
            if 'detailed_scoring' in analysis_results:
                detailed = analysis_results['detailed_scoring']
                f.write(f"### Threat Assessment\n\n")
                f.write(f"**Threat Level:** {detailed['threat_level']}\n\n")
                f.write(f"**Recommendation:** {detailed['recommendation']}\n\n")
                
                if detailed.get('breakdown'):
                    f.write(f"**Score Breakdown:**\n\n")
                    f.write(f"| Factor | Points |\n")
                    f.write(f"|--------|--------|\n")
                    for factor, score in detailed['breakdown'].items():
                        f.write(f"| {factor} | +{score} |\n")
                    f.write(f"| **TOTAL** | **{detailed['total_score']}/100** |\n\n")
            
            # Behavioral patterns
            if 'behavioral_patterns' in analysis_results:
                patterns = analysis_results['behavioral_patterns']
                f.write(f"### Behavioral Indicators\n\n")
                
                for pattern_type, matches in patterns.items():
                    if matches:
                        icon = "🚨" if 'ransomware' in pattern_type or 'rat' in pattern_type else "⚠️"
                        f.write(f"#### {icon} {pattern_type.replace('_', ' ').title()}\n\n")
                        for match in matches[:10]:
                            f.write(f"- `{match}`\n")
                        if len(matches) > 10:
                            f.write(f"\n*...and {len(matches) - 10} more*\n")
                        f.write(f"\n")
            
            # API sequences
            if 'api_sequences' in analysis_results:
                sequences = analysis_results['api_sequences']
                f.write(f"### Suspicious API Call Sequences\n\n")
                
                for seq in sequences:
                    severity_icon = "🔴" if seq['severity'] == "critical" else "🟠" if seq['severity'] == "high" else "🟡"
                    f.write(f"#### {severity_icon} {seq['name']}\n\n")
                    f.write(f"- **Severity:** {seq['severity'].upper()}\n")
                    f.write(f"- **Confidence:** {seq['confidence']:.0f}%\n")
                    f.write(f"- **Matched APIs:** {', '.join(seq['matched_apis'])}\n\n")
            
            # Enriched IOCs
            if 'enriched_iocs' in analysis_results:
                enriched = analysis_results['enriched_iocs']
                f.write(f"### Suspicious Network Indicators\n\n")
                
                if 'domains' in enriched and enriched['domains']:
                    f.write(f"#### Suspicious Domains\n\n")
                    for domain_info in enriched['domains'][:15]:
                        f.write(f"- **{domain_info['domain']}**\n")
                        for reason in domain_info['reasons']:
                            f.write(f"  - ⚠️ {reason}\n")
                    f.write(f"\n")
                
                if 'urls' in enriched and enriched['urls']:
                    f.write(f"#### Suspicious URLs\n\n")
                    for url_info in enriched['urls'][:15]:
                        f.write(f"- **{url_info['url'][:80]}**\n")
                        for reason in url_info['reasons']:
                            f.write(f"  - ⚠️ {reason}\n")
                    f.write(f"\n")
        
        # Recommendations
        f.write(f"## Recommended Actions\n\n")
        
        # Use detailed scoring if available
        if 'detailed_scoring' in analysis_results:
            recommendation = analysis_results['detailed_scoring']['recommendation']
            total_score = analysis_results['detailed_scoring']['total_score']
        else:
            total_score = analysis_results.get('risk_score', 0)
            recommendation = None
        
        if total_score >= 75:
            f.write(f"### 🔴 HIGH RISK - IMMEDIATE ACTION REQUIRED\n\n")
            f.write(f"1. **Quarantine immediately** - Isolate affected systems\n")
            f.write(f"2. **Block all IOCs** - Add to firewall/IDS/IPS rules\n")
            f.write(f"3. **Hunt for additional infections** - Check for lateral movement\n")
            f.write(f"4. **Preserve evidence** - Create forensic images\n")
            f.write(f"5. **Incident response** - Escalate to security team\n\n")
            if recommendation:
                f.write(f"**Detailed Recommendation:** {recommendation}\n\n")
        elif total_score >= 50:
            f.write(f"### 🟡 MEDIUM RISK - INVESTIGATION REQUIRED\n\n")
            f.write(f"1. **Contain** - Limit network access for affected systems\n")
            f.write(f"2. **Monitor** - Watch for suspicious activity\n")
            f.write(f"3. **Investigate** - Perform deeper analysis\n")
            f.write(f"4. **Block IOCs** - Add to monitoring systems\n\n")
            if recommendation:
                f.write(f"**Detailed Recommendation:** {recommendation}\n\n")
        else:
            f.write(f"### 🟢 LOW RISK - MONITORING RECOMMENDED\n\n")
            f.write(f"1. **Log** - Keep records of the sample\n")
            f.write(f"2. **Monitor** - Watch for related activity\n")
            f.write(f"3. **Update signatures** - Add to detection systems\n\n")
            if recommendation:
                f.write(f"**Detailed Recommendation:** {recommendation}\n\n")
        
        f.write(f"---\n\n")
        f.write(f"*Report generated by Malware Analysis Triage Tool*\n")
    
    return report_file


# ============================================================================
# MAIN ANALYSIS WORKFLOW
# ============================================================================

def analyze_sample(file_path, cuckoo_url=None, yara_rules=None, save_to_db=True, output_dir="reports", cli_command=None):
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
    
    # Step 6.5: Advanced behavioral and API analysis
    logger.info(f"\n[*] Step 6.5: Running advanced analysis...")
    
    # Behavioral pattern analysis
    if 'strings' in analysis_results:
        logger.info(f"    Analyzing behavioral patterns...")
        strings = []
        string_sets = analysis_results.get('strings') or {}

        for key in ('ascii', 'unicode'):
            values = string_sets.get(key)
            if isinstance(values, list):
                strings.extend([s for s in values if isinstance(s, str)])
            elif isinstance(values, str):
                strings.append(values)

        behavioral_analyzer = BehavioralAnalyzer()
        behavioral_patterns = behavioral_analyzer.analyze(strings)

        if behavioral_patterns:
            analysis_results['behavioral_patterns'] = behavioral_patterns
            for pattern_type, matches in behavioral_patterns.items():
                if matches:
                    logger.info(f"      {pattern_type}: {len(matches)} indicator(s)")
    
    # API sequence analysis
    pe_info = analysis_results.get('pe_analysis')
    if isinstance(pe_info, dict) and 'imports' in pe_info:
        logger.info(f"    Analyzing API call sequences...")
        api_analyzer = APISequenceAnalyzer()
        imports_data = pe_info.get('imports')
        imports_list = [entry for entry in imports_data if isinstance(entry, dict)] if isinstance(imports_data, list) else []
        api_sequences = api_analyzer.analyze(imports_list)

        if api_sequences:
            analysis_results['api_sequences'] = api_sequences
            for seq in api_sequences:
                logger.info(f"      {seq['name']} ({seq['severity']}): {seq['confidence']:.0f}% confidence")
    
    # Network IOC enrichment
    if 'iocs' in analysis_results:
        logger.info(f"    Enriching network IOCs...")
        enriched_iocs = {}
        
        if 'domains' in analysis_results['iocs'] and analysis_results['iocs']['domains']:
            enricher = NetworkIOCEnricher()
            enriched_domains = [enricher.analyze_domain(d) for d in analysis_results['iocs']['domains'][:20]]
            suspicious_domains = [d for d in enriched_domains if d['suspicious']]
            if suspicious_domains:
                enriched_iocs['domains'] = suspicious_domains
                logger.info(f"      Suspicious domains: {len(suspicious_domains)}")
        
        if 'urls' in analysis_results['iocs'] and analysis_results['iocs']['urls']:
            enricher = NetworkIOCEnricher()
            enriched_urls = [enricher.analyze_url(u) for u in analysis_results['iocs']['urls'][:20]]
            suspicious_urls = [u for u in enriched_urls if u['suspicious']]
            if suspicious_urls:
                enriched_iocs['urls'] = suspicious_urls
                logger.info(f"      Suspicious URLs: {len(suspicious_urls)}")
        
        if enriched_iocs:
            analysis_results['enriched_iocs'] = enriched_iocs
    
    # Attach sample metadata for scoring/reporting reference
    analysis_results['sample'] = sample_data

    # Step 7: Advanced risk scoring with detailed breakdown
    logger.info(f"\n[*] Step 7: Calculating advanced risk score...")
    
    # Original risk score
    risk_score = calculate_risk_score(analysis_results)
    analysis_results['risk_score'] = risk_score
    
    # Detailed scoring with breakdown
    scorer = ThreatIntelligenceScorer()
    detailed_scoring = scorer.calculate_detailed_score(analysis_results)
    analysis_results['detailed_scoring'] = detailed_scoring
    
    logger.info(f"    Risk Score: {detailed_scoring['total_score']}/100")
    logger.info(f"    Threat Level: {detailed_scoring['threat_level']}")
    
    if detailed_scoring['breakdown']:
        logger.info(f"    Score Breakdown:")
        for factor, score in detailed_scoring['breakdown'].items():
            logger.info(f"      {factor}: +{score}")
    
    logger.info(f"    Recommendation: {detailed_scoring['recommendation']}")
    
    # Legacy compatibility
    if risk_score >= 75:
        logger.warning(f"    Assessment: 🔴 HIGH RISK")
    elif risk_score >= 50:
        logger.warning(f"    Assessment: 🟡 MEDIUM RISK")
    else:
        logger.info(f"    Assessment: 🟢 LOW RISK")
    
    # Step 8: Generate report
    logger.info(f"\n[*] Step 8: Generating report...")
    report_file = generate_report(sample_data, analysis_results, output_dir, cli_command)
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
    parser.add_argument('--yara', '-y', help='Path to YARA rules file, a directory of .yar files, or a comma-separated list')
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
    
    # Reconstruct CLI command for report
    cli_command = ' '.join(sys.argv)
    
    # Run analysis
    result = analyze_sample(
        file_path=args.file,
        cuckoo_url=args.cuckoo,
        yara_rules=args.yara,
        save_to_db=not args.no_db,
        output_dir=args.output,
        cli_command=cli_command
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
