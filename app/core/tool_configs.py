"""Configuration data for enumeration tool control panels"""

TOOL_CONFIGS = {
    'dns': {
        'rows': [
            {
                'label': 'Types:',
                'controls': [
                    {'type': 'checkbox', 'name': 'all_checkbox', 'text': 'ALL'},
                    {'type': 'checkbox', 'name': 'a_checkbox', 'text': 'A'},
                    {'type': 'checkbox', 'name': 'cname_checkbox', 'text': 'CNAME'},
                    {'type': 'checkbox', 'name': 'mx_checkbox', 'text': 'MX'},
                    {'type': 'checkbox', 'name': 'txt_checkbox', 'text': 'TXT'},
                    {'type': 'checkbox', 'name': 'ns_checkbox', 'text': 'NS'},
                    {'type': 'checkbox', 'name': 'ptr_checkbox', 'text': 'PTR', 'visible': False}
                ]
            },
            {
                'label': 'DNS:',
                'controls': [
                    {'type': 'lineedit', 'name': 'dns_input', 'placeholder': 'DNS Server (optional)', 'width': 400}
                ]
            },
            {
                'label': 'Method:',
                'controls': [
                    {'type': 'combobox', 'name': 'method_combo', 'items': ['Wordlist', 'Bruteforce'], 'width': 150},
                    {'type': 'combobox', 'name': 'wordlist_combo', 'items': [], 'stretch': True}
                ]
            }
        ]
    },
    
    'port': {
        'rows': [
            {
                'label': 'Scan Type:',
                'controls': [
                    {'type': 'combobox', 'name': 'scan_type_combo', 'items': ['TCP Connect', 'Network Sweep'], 'width': 150}
                ]
            },
            {
                'label': 'Ports:',
                'controls': [
                    {'type': 'lineedit', 'name': 'port_input', 'placeholder': '80,443,1-1000 or leave empty for common ports', 'stretch': True}
                ]
            },
            {
                'label': 'Quick:',
                'buttons': [
                    {'text': 'Common'},
                    {'text': 'Top 100'},
                    {'text': 'Top 1000'}
                ]
            }
        ]
    },
    
    'smb': {
        'rows': [
            {
                'label': 'Scan Type:',
                'controls': [
                    {'type': 'combobox', 'name': 'smb_scan_type', 'items': ['Basic Info', 'Share Enumeration', 'Vulnerability Scan'], 'width': 150}
                ]
            },
            {
                'label': 'Auth:',
                'controls': [
                    {'type': 'combobox', 'name': 'smb_auth_combo', 'items': ['Anonymous', 'Credentials'], 'width': 150}
                ]
            },
            {
                'label': 'Username:',
                'controls': [
                    {'type': 'lineedit', 'name': 'smb_username', 'placeholder': 'Domain\\username or username', 'visible': False, 'stretch': True}
                ]
            },
            {
                'label': 'Password:',
                'controls': [
                    {'type': 'lineedit', 'name': 'smb_password', 'placeholder': 'Password', 'password': True, 'visible': False, 'stretch': True}
                ]
            }
        ]
    },
    
    'smtp': {
        'rows': [
            {
                'label': 'Port:',
                'controls': [
                    {'type': 'lineedit', 'name': 'smtp_port', 'default': '25', 'width': 100}
                ]
            },
            {
                'label': 'Domain:',
                'controls': [
                    {'type': 'lineedit', 'name': 'smtp_domain', 'placeholder': 'Target domain for RCPT TO (optional)', 'stretch': True}
                ]
            },
            {
                'label': 'HELO Name:',
                'controls': [
                    {'type': 'lineedit', 'name': 'smtp_helo', 'default': 'test.local', 'placeholder': 'HELO/EHLO identifier', 'stretch': True}
                ]
            },
            {
                'label': 'Wordlist:',
                'controls': [
                    {'type': 'combobox', 'name': 'smtp_wordlist', 'items': [], 'stretch': True}
                ]
            }
        ]
    },
    
    'snmp': {
        'rows': [
            {
                'label': 'Version:',
                'controls': [
                    {'type': 'combobox', 'name': 'snmp_version', 'items': ['2c', '1', '3'], 'width': 100}
                ]
            },
            {
                'label': 'Scan Type:',
                'controls': [
                    {'type': 'combobox', 'name': 'snmp_scan_type', 'items': ['Basic Info', 'Users', 'Processes', 'Software', 'Network', 'Full Enumeration'], 'width': 150}
                ]
            },
            {
                'label': 'Communities:',
                'controls': [
                    {'type': 'lineedit', 'name': 'snmp_communities', 'default': 'public,private,community', 'placeholder': 'Comma-separated community strings', 'stretch': True}
                ]
            },
            {
                'label': 'Quick:',
                'buttons': [
                    {'text': 'Default'},
                    {'text': 'Extended'}
                ]
            }
        ]
    }
}