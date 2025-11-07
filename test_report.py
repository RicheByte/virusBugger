!/usr/bin/env python3
"""
Quick test to verify enhanced report structure
"""

# Create mock data to test report generation
sample_data = {
    'filename': 'test_malware.exe',
    'filepath': 'C:\\samples\\test_malware.exe',
    'md5': 'abc123def456',
    'sha1': 'abc123def456789',
    'sha256': 'abc123def456789abc123def456789',
    'size': 102400,
    'file_type': 'PE/DOS Executable',
    'ssdeep': '1536:test:fuzzy:hash',
    'tlsh': 'T1234567890ABCDEF'
}

analysis_results = {
    'risk_score': 85,
    'yara': [
        {
            'rule': 'RAT_RevengeRAT',
            'namespace': 'default',
            'tags': ['RAT', 'RevengeRAT'],
            'meta': {
                'description': 'Detects RevengeRAT malware',
                'severity': 'critical',
                'malware_family': 'RevengeRAT',
                'technique': 'Remote Access'
            },
            'strings': [
                ('$s1', 0x1000, 'RevengeRAT'),
                ('$s2', 0x2000, 'Revenge-RAT')
            ]
        }
    ],
    'iocs': {
        'urls': ['http://evil.example.com/payload.exe', 'http://c2.example.com/beacon'],
        'ips': ['192.0.2.1', '198.51.100.1'],
        'domains': ['evil.example.com', 'c2.example.com'],
        'emails': ['attacker@example.com'],
        'registry_keys': ['HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'],
        'file_paths': ['C:\\Windows\\Temp\\malware.exe']
    },
    'strings': {
        'ascii': ['Password', 'Admin123', 'http://example.com', 'C:\\Windows\\System32'],
        'unicode': ['Passwordü', 'Adminユーザー'],
        'total_ascii': 150,
        'total_unicode': 45
    },
    'pe_analysis': {
        'machine': 0x14c,
        'timestamp': '2024-01-15T10:30:00',
        'subsystem': 2,
        'entry_point': '0x1000',
        'image_base': '0x400000',
        'imphash': 'abc123def456',
        'is_signed': False,
        'overlay_size': 2048,
        'characteristics': 0x0102,
        'dll_characteristics': 0x8140,
        'suspicious_flags': [
            'High entropy in section .text: 7.8',
            '.text section is writable',
            'Suspicious import: kernel32.dll!VirtualAlloc'
        ],
        'sections': [
            {'name': '.text', 'virtual_address': '0x1000', 'virtual_size': 8192, 'raw_size': 8192, 'entropy': 7.8, 'characteristics': 0x60000020},
            {'name': '.data', 'virtual_address': '0x3000', 'virtual_size': 4096, 'raw_size': 4096, 'entropy': 3.2, 'characteristics': 0x40000040}
        ],
        'imports': [
            {'dll': 'kernel32.dll', 'functions': ['VirtualAlloc', 'VirtualProtect', 'CreateProcess']},
            {'dll': 'ws2_32.dll', 'functions': ['socket', 'connect', 'send', 'recv']}
        ],
        'exports': [
            {'name': 'DllMain', 'ordinal': 1, 'address': '0x1234'}
        ],
        'resources': [
            {'type': 3, 'id': 1, 'lang': 1033, 'size': 1024}
        ]
    },
    'cuckoo_iocs': {
        'processes': [
            {'name': 'malware.exe', 'pid': 1234, 'parent_id': 5678},
            {'name': 'cmd.exe', 'pid': 1235, 'parent_id': 1234}
        ],
        'mutexes': ['Global\\RevengeRAT_Mutex'],
        'files': ['C:\\Users\\User\\AppData\\Roaming\\malware.dat'],
        'registry': ['HKEY_CURRENT_USER\\Software\\RevengeRAT'],
        'domains': ['c2.example.com'],
        'ips': ['192.0.2.1'],
        'urls': ['http://c2.example.com/beacon']
    }
}

print("Report structure test data created successfully!")
print(f"\nSample: {sample_data['filename']}")
print(f"Risk Score: {analysis_results['risk_score']}/100")
print(f"YARA Matches: {len(analysis_results['yara'])}")
print(f"IOCs: {sum(len(v) for v in analysis_results['iocs'].values() if isinstance(v, list))}")
print(f"PE Suspicious Flags: {len(analysis_results['pe_analysis']['suspicious_flags'])}")
print(f"Cuckoo Processes: {len(analysis_results['cuckoo_iocs']['processes'])}")
print("\n✓ All report sections populated with test data")
