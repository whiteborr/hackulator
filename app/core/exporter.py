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
            writer.writerow(["Domain", "Type", "Value"])
            
            for domain, record_types in results.items():
                for record_type, values in record_types.items():
                    for value in values:
                        writer.writerow([domain, record_type, value])
        
        return filepath
    
    def _export_xml_simple(self, results, export_dir, filename):
        """Export results to XML format (simple version)"""
        filepath = export_dir / f"{filename}.xml"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('<?xml version="1.0" encoding="UTF-8"?>\n<scan_results>\n')
            for domain, record_types in results.items():
                f.write(f'  <domain name="{domain}">\n')
                for record_type, values in record_types.items():
                    f.write(f'    <{record_type.lower()}_records>\n')
                    for value in values:
                        f.write(f'      <record>{value}</record>\n')
                    f.write(f'    </{record_type.lower()}_records>\n')
                f.write('  </domain>\n')
            f.write('</scan_results>\n')
        
        return filepath

# Global exporter instance
exporter = ScanExporter()