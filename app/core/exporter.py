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
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"hackulator_scan_{InputValidator.sanitize_filename(target)}_{timestamp}"
            
            # Create exports directory
            export_dir = Path("exports")
            export_dir.mkdir(exist_ok=True)
            
            # Prepare metadata
            metadata = self._create_metadata(target, results)
            
            # Export based on format
            if format_type.lower() == "json":
                filepath = self._export_json(results, metadata, export_dir, filename)
            elif format_type.lower() == "csv":
                filepath = self._export_csv(results, metadata, export_dir, filename)
            elif format_type.lower() == "xml":
                filepath = self._export_xml(results, metadata, export_dir, filename)
            else:
                return False, "", f"Unsupported export format: {format_type}"
            
            logger.info(f"Results exported to {filepath}")
            return True, str(filepath), "Export successful"
            
        except Exception as e:
            logger.error(f"Export failed: {str(e)}")
            return False, "", f"Export failed: {str(e)}"
    
    def _create_metadata(self, target, results):
        """Create metadata for the scan"""
        total_results = sum(len(records) for domain_data in results.values() 
                          for records in domain_data.values())
        
        metadata = {
            "scan_info": {
                "target": target,
                "timestamp": datetime.now().isoformat(),
                "total_domains": len(results),
                "total_records": total_results,
                "export_version": "1.0"
            }
        }
        
        if self.export_config.get("include_metadata", True):
            metadata["scan_info"]["tool"] = "Hackulator"
            metadata["scan_info"]["record_types"] = list(set(
                record_type for domain_data in results.values() 
                for record_type in domain_data.keys()
            ))
        
        return metadata
    
    def _export_json(self, results, metadata, export_dir, filename):
        """Export results to JSON format"""
        filepath = export_dir / f"{filename}.json"
        
        export_data = {
            "metadata": metadata,
            "results": results
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    def _export_csv(self, results, metadata, export_dir, filename):
        """Export results to CSV format"""
        filepath = export_dir / f"{filename}.csv"
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(["Domain", "Record Type", "Value"])
            
            # Write metadata as comments if enabled
            if self.export_config.get("include_metadata", True):
                writer.writerow([f"# Target: {metadata['scan_info']['target']}", "", ""])
                writer.writerow([f"# Timestamp: {metadata['scan_info']['timestamp']}", "", ""])
                writer.writerow([f"# Total Domains: {metadata['scan_info']['total_domains']}", "", ""])
                writer.writerow(["", "", ""])  # Empty row
            
            # Write results
            for domain, record_types in results.items():
                for record_type, values in record_types.items():
                    for value in values:
                        writer.writerow([domain, record_type, value])
        
        return filepath
    
    def _export_xml(self, results, metadata, export_dir, filename):
        """Export results to XML format"""
        filepath = export_dir / f"{filename}.xml"
        
        # Create root element
        root = ET.Element("hackulator_scan")
        
        # Add metadata
        if self.export_config.get("include_metadata", True):
            metadata_elem = ET.SubElement(root, "metadata")
            for key, value in metadata["scan_info"].items():
                elem = ET.SubElement(metadata_elem, key)
                elem.text = str(value)
        
        # Add results
        results_elem = ET.SubElement(root, "results")
        
        for domain, record_types in results.items():
            domain_elem = ET.SubElement(results_elem, "domain")
            domain_elem.set("name", domain)
            
            for record_type, values in record_types.items():
                for value in values:
                    record_elem = ET.SubElement(domain_elem, "record")
                    record_elem.set("type", record_type)
                    record_elem.text = value
        
        # Write to file
        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ", level=0)
        tree.write(filepath, encoding='utf-8', xml_declaration=True)
        
        return filepath

# Global exporter instance
exporter = ScanExporter()