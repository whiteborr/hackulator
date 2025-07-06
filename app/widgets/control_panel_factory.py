"""Generic control panel factory for enumeration tools"""
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QComboBox, QCheckBox, QPushButton, QSpinBox)
from typing import Dict, List, Any, Callable, Optional

class ControlPanelFactory:
    """Factory for creating standardized control panels"""
    
    @staticmethod
    def create_control_panel(config: Dict[str, Any], parent: QWidget = None) -> QWidget:
        """Create control panel from configuration"""
        widget = QWidget(parent)
        layout = QVBoxLayout(widget)
        layout.setSpacing(5)
        
        controls = {}
        
        for control_config in config.get('controls', []):
            control_type = control_config['type']
            control_id = control_config['id']
            
            if control_type == 'row':
                row_layout = QHBoxLayout()
                
                # Add label
                if 'label' in control_config:
                    label = QLabel(control_config['label'])
                    label.setFixedWidth(control_config.get('label_width', 110))
                    row_layout.addWidget(label)
                
                # Add controls to row
                for item in control_config.get('items', []):
                    control = ControlPanelFactory._create_control(item, parent)
                    if control:
                        controls[item['id']] = control
                        if item.get('stretch'):
                            row_layout.addWidget(control, 1)
                        else:
                            row_layout.addWidget(control)
                
                row_layout.addStretch()
                layout.addLayout(row_layout)
            
            elif control_type == 'checkbox_group':
                row_layout = QHBoxLayout()
                
                # Add label
                if 'label' in control_config:
                    label = QLabel(control_config['label'])
                    label.setFixedWidth(control_config.get('label_width', 110))
                    row_layout.addWidget(label)
                
                # Add checkboxes
                for cb_config in control_config.get('checkboxes', []):
                    checkbox = QCheckBox(cb_config['text'])
                    checkbox.setChecked(cb_config.get('checked', False))
                    controls[cb_config['id']] = checkbox
                    row_layout.addWidget(checkbox)
                
                row_layout.addStretch()
                layout.addLayout(row_layout)
        
        layout.addStretch()
        
        # Store controls reference on widget
        widget.controls = controls
        return widget
    
    @staticmethod
    def _create_control(config: Dict[str, Any], parent: QWidget) -> Optional[QWidget]:
        """Create individual control from config"""
        control_type = config['type']
        
        if control_type == 'lineedit':
            control = QLineEdit(parent)
            if 'placeholder' in config:
                control.setPlaceholderText(config['placeholder'])
            if 'text' in config:
                control.setText(config['text'])
            if 'width' in config:
                control.setFixedWidth(config['width'])
            return control
        
        elif control_type == 'combobox':
            control = QComboBox(parent)
            for item in config.get('items', []):
                if isinstance(item, dict):
                    control.addItem(item['text'], item.get('data'))
                else:
                    control.addItem(str(item))
            if 'width' in config:
                control.setFixedWidth(config['width'])
            return control
        
        elif control_type == 'checkbox':
            control = QCheckBox(config.get('text', ''), parent)
            control.setChecked(config.get('checked', False))
            return control
        
        elif control_type == 'button':
            control = QPushButton(config.get('text', ''), parent)
            if 'width' in config:
                control.setFixedWidth(config['width'])
            return control
        
        elif control_type == 'spinbox':
            control = QSpinBox(parent)
            control.setRange(config.get('min', 0), config.get('max', 100))
            control.setValue(config.get('value', 0))
            if 'width' in config:
                control.setFixedWidth(config['width'])
            return control
        
        return None

# Control panel configurations
CONTROL_CONFIGS = {
    'dns_enum': {
        'controls': [
            {
                'type': 'checkbox_group',
                'label': 'Types:',
                'checkboxes': [
                    {'id': 'all_checkbox', 'text': 'ALL', 'checked': False},
                    {'id': 'a_checkbox', 'text': 'A', 'checked': False},
                    {'id': 'cname_checkbox', 'text': 'CNAME', 'checked': False},
                    {'id': 'mx_checkbox', 'text': 'MX', 'checked': False},
                    {'id': 'txt_checkbox', 'text': 'TXT', 'checked': False},
                    {'id': 'ns_checkbox', 'text': 'NS', 'checked': False},
                    {'id': 'ptr_checkbox', 'text': 'PTR', 'checked': False}
                ]
            },
            {
                'type': 'row',
                'label': 'DNS:',
                'items': [
                    {
                        'id': 'dns_input',
                        'type': 'lineedit',
                        'placeholder': 'DNS Server (optional)',
                        'width': 400
                    }
                ]
            },
            {
                'type': 'row',
                'label': 'Method:',
                'items': [
                    {
                        'id': 'method_combo',
                        'type': 'combobox',
                        'items': ['Wordlist', 'Bruteforce'],
                        'width': 150
                    },
                    {
                        'id': 'wordlist_combo',
                        'type': 'combobox',
                        'items': [{'text': 'Default subdomains', 'data': None}],
                        'stretch': True
                    }
                ]
            }
        ]
    },
    
    'port_scan': {
        'controls': [
            {
                'type': 'row',
                'label': 'Scan Type:',
                'items': [
                    {
                        'id': 'scan_type_combo',
                        'type': 'combobox',
                        'items': ['TCP Connect', 'Network Sweep'],
                        'width': 150
                    }
                ]
            },
            {
                'type': 'row',
                'label': 'Ports:',
                'items': [
                    {
                        'id': 'port_input',
                        'type': 'lineedit',
                        'placeholder': '80,443,1-1000 or leave empty for common ports',
                        'stretch': True
                    }
                ]
            },
            {
                'type': 'row',
                'label': 'Quick:',
                'items': [
                    {'id': 'common_ports_btn', 'type': 'button', 'text': 'Common'},
                    {'id': 'top100_btn', 'type': 'button', 'text': 'Top 100'},
                    {'id': 'top1000_btn', 'type': 'button', 'text': 'Top 1000'}
                ]
            }
        ]
    },
    
    'smtp_enum': {
        'controls': [
            {
                'type': 'row',
                'label': 'Port:',
                'items': [
                    {
                        'id': 'smtp_port',
                        'type': 'lineedit',
                        'text': '25',
                        'width': 100
                    }
                ]
            },
            {
                'type': 'row',
                'label': 'Domain:',
                'items': [
                    {
                        'id': 'smtp_domain',
                        'type': 'lineedit',
                        'placeholder': 'Target domain for RCPT TO (optional)',
                        'stretch': True
                    }
                ]
            },
            {
                'type': 'row',
                'label': 'Wordlist:',
                'items': [
                    {
                        'id': 'smtp_wordlist',
                        'type': 'combobox',
                        'items': [{'text': 'Default usernames', 'data': None}],
                        'stretch': True
                    }
                ]
            }
        ]
    },
    
    'snmp_enum': {
        'controls': [
            {
                'type': 'row',
                'label': 'Version:',
                'items': [
                    {
                        'id': 'snmp_version',
                        'type': 'combobox',
                        'items': ['2c', '1', '3'],
                        'width': 100
                    }
                ]
            },
            {
                'type': 'row',
                'label': 'Scan Type:',
                'items': [
                    {
                        'id': 'snmp_scan_type',
                        'type': 'combobox',
                        'items': ['Basic Info', 'Users', 'Processes', 'Software', 'Network', 'Full Enumeration'],
                        'width': 150
                    }
                ]
            },
            {
                'type': 'row',
                'label': 'Communities:',
                'items': [
                    {
                        'id': 'snmp_communities',
                        'type': 'lineedit',
                        'text': 'public,private,community',
                        'placeholder': 'Comma-separated community strings',
                        'stretch': True
                    }
                ]
            }
        ]
    }
}