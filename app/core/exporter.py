# app/core/exporter.py
import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from app.core.logger import logger
from app.core.config import config
from app.core.validators import InputValidator

class ScanExporter:
    """Handles exporting scan results to various formats"""
    
    def __init__(self):
        self.export_config = config.get_export_config()
    
    def export_results(self, results, target, format_type="json", filename=None):
        """
        Export scan results to specified format
        Returns: (success: bool, filepath: str, error_message: str)
        """
        try:
            # Generate filename if not provided
            if not filename:
                timestamp = int(datetime.now().timestamp())
                filename = f"scan_results_{InputValidator.sanitize_filename(target)}_{timestamp}"
            
            # Create exports directory
            export_dir = Path("exports")
            export_dir.mkdir(exist_ok=True)
            
            # Export based on format
            if format_type.lower() == "json":
                filepath = self._export_json_simple(results, export_dir, filename)
            elif format_type.lower() == "csv":
                filepath = self._export_csv_simple(results, export_dir, filename)
            elif format_type.lower() == "xml":
                filepath = self._export_xml_simple(results, export_dir, filename)
            else:
                return False, "", f"Unsupported export format: {format_type}"
            
            logger.info(f"Results exported to {filepath}")
            return True, str(filepath), "Export successful"
            
        except Exception as e:
            logger.error(f"Export failed: {str(e)}")
            return False, "", f"Export failed: {str(e)}"
    
    def save_results(self, results, target, format_type, project_root=None):
        """
        Backward compatibility method for save_results
        Returns: filename only (for compatibility)
        """
        success, filepath, message = self.export_results(results, target, format_type)
        if success:
            return Path(filepath).name
        else:
            raise Exception(message)
    

    
    def _export_json_simple(self, results, export_dir, filename):
        """Export results to JSON format (simple version)"""
        filepath = export_dir / f"{filename}.json"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    def _export_csv_simple(self, results, export_dir, filename):
        """Export results to CSV format (simple version)"""
        filepath = export_dir / f"{filename}.csv"
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Handle flat structure (like RPC results)
            if isinstance(results, dict) and any(not isinstance(v, dict) for v in results.values()):
                writer.writerow(["Field", "Value"])
                for key, value in results.items():
                    if isinstance(value, list):
                        for item in value:
                            writer.writerow([key, str(item)])
                    else:
                        writer.writerow([key, str(value)])
            else:
                # Handle nested structure (like DNS results)
                writer.writerow(["Domain", "Type", "Value"])
                for domain, record_types in results.items():
                    if isinstance(record_types, dict):
                        for record_type, values in record_types.items():
                            if isinstance(values, list):
                                for value in values:
                                    writer.writerow([domain, record_type, value])
                            else:
                                writer.writerow([domain, record_type, values])
                    else:
                        writer.writerow([domain, "info", str(record_types)])
        
        return filepath
    
    def _export_xml_simple(self, results, export_dir, filename):
        """Export results to XML format (simple version)"""
        filepath = export_dir / f"{filename}.xml"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('<?xml version="1.0" encoding="UTF-8"?>\n<scan_results>\n')
            
            # Handle flat structure (like RPC results)
            if isinstance(results, dict) and any(not isinstance(v, dict) for v in results.values()):
                for key, value in results.items():
                    safe_key = key.replace(' ', '_').replace(':', '').lower()
                    f.write(f'  <{safe_key}>\n')
                    if isinstance(value, list):
                        for item in value:
                            f.write(f'    <item>{self._escape_xml(str(item))}</item>\n')
                    else:
                        f.write(f'    {self._escape_xml(str(value))}\n')
                    f.write(f'  </{safe_key}>\n')
            else:
                # Handle nested structure (like DNS results)
                for domain, record_types in results.items():
                    f.write(f'  <domain name="{self._escape_xml(domain)}">\n')
                    if isinstance(record_types, dict):
                        for record_type, values in record_types.items():
                            safe_type = record_type.lower().replace(' ', '_')
                            f.write(f'    <{safe_type}_records>\n')
                            if isinstance(values, list):
                                for value in values:
                                    f.write(f'      <record>{self._escape_xml(str(value))}</record>\n')
                            else:
                                f.write(f'      <record>{self._escape_xml(str(values))}</record>\n')
                            f.write(f'    </{safe_type}_records>\n')
                    else:
                        f.write(f'    <info>{self._escape_xml(str(record_types))}</info>\n')
                    f.write('  </domain>\n')
            
            f.write('</scan_results>\n')
        
        return filepath
    
    def _escape_xml(self, text):
        """Escape XML special characters"""
        return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&apos;')

# Global exporter instance
exporter = ScanExporter()