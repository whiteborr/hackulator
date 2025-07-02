# app/core/scan_database.py
import sqlite3
import json
import os
from datetime import datetime
from typing import Dict, List, Optional

class ScanDatabase:
    """Database manager for scan history and results"""
    
    def __init__(self, db_path: str = "scan_history.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    duration INTEGER,
                    results_count INTEGER,
                    status TEXT DEFAULT 'completed',
                    results TEXT,
                    summary TEXT,
                    tags TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_name TEXT NOT NULL,
                    created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    description TEXT,
                    scan_ids TEXT
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_target ON scans(target);
                CREATE INDEX IF NOT EXISTS idx_scan_type ON scans(scan_type);
                CREATE INDEX IF NOT EXISTS idx_timestamp ON scans(timestamp);
            """)
    
    def save_scan(self, target: str, scan_type: str, results: Dict, 
                  duration: int = 0, tags: List[str] = None) -> int:
        """Save scan results to database"""
        
        try:
            results_json = json.dumps(results, default=str)
            summary = self._generate_summary(results, scan_type)
            tags_str = json.dumps(tags or [])
            results_count = self._count_results(results)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    INSERT INTO scans (target, scan_type, duration, results_count, 
                                     results, summary, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (target, scan_type, duration, results_count, 
                      results_json, summary, tags_str))
                
                return cursor.lastrowid
        
        except Exception as e:
            print(f"Error saving scan: {e}")
            return 0
    
    def get_scan_history(self, limit: int = 50, target: str = None, 
                        scan_type: str = None) -> List[Dict]:
        """Retrieve scan history with optional filters"""
        
        query = "SELECT * FROM scans WHERE 1=1"
        params = []
        
        if target:
            query += " AND target LIKE ?"
            params.append(f"%{target}%")
        
        if scan_type:
            query += " AND scan_type = ?"
            params.append(scan_type)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(query, params)
                
                scans = []
                for row in cursor.fetchall():
                    scan = dict(row)
                    scan['tags'] = json.loads(scan.get('tags', '[]'))
                    scans.append(scan)
                
                return scans
        
        except Exception as e:
            print(f"Error retrieving scan history: {e}")
            return []
    
    def get_scan_by_id(self, scan_id: int) -> Optional[Dict]:
        """Retrieve specific scan by ID"""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
                row = cursor.fetchone()
                
                if row:
                    scan = dict(row)
                    scan['results'] = json.loads(scan.get('results', '{}'))
                    scan['tags'] = json.loads(scan.get('tags', '[]'))
                    return scan
                
                return None
        
        except Exception as e:
            print(f"Error retrieving scan: {e}")
            return None
    
    def delete_scan(self, scan_id: int) -> bool:
        """Delete scan from database"""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
                return cursor.rowcount > 0
        
        except Exception as e:
            print(f"Error deleting scan: {e}")
            return False
    
    def update_scan_tags(self, scan_id: int, tags: List[str]) -> bool:
        """Update scan tags"""
        
        try:
            tags_str = json.dumps(tags)
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("UPDATE scans SET tags = ? WHERE id = ?", 
                                    (tags_str, scan_id))
                return cursor.rowcount > 0
        
        except Exception as e:
            print(f"Error updating tags: {e}")
            return False
    
    def get_scan_statistics(self) -> Dict:
        """Get database statistics"""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT 
                        COUNT(*) as total_scans,
                        COUNT(DISTINCT target) as unique_targets,
                        scan_type,
                        COUNT(*) as type_count
                    FROM scans 
                    GROUP BY scan_type
                """)
                
                type_stats = {}
                total_scans = 0
                unique_targets = 0
                
                for row in cursor.fetchall():
                    if not total_scans:  # First row
                        total_scans = row[0]
                        unique_targets = row[1]
                    type_stats[row[2]] = row[3]
                
                # Get recent activity
                cursor = conn.execute("""
                    SELECT DATE(timestamp) as date, COUNT(*) as count
                    FROM scans 
                    WHERE timestamp >= date('now', '-30 days')
                    GROUP BY DATE(timestamp)
                    ORDER BY date DESC
                    LIMIT 7
                """)
                
                recent_activity = {row[0]: row[1] for row in cursor.fetchall()}
                
                return {
                    'total_scans': total_scans,
                    'unique_targets': unique_targets,
                    'scan_types': type_stats,
                    'recent_activity': recent_activity
                }
        
        except Exception as e:
            print(f"Error getting statistics: {e}")
            return {}
    
    def search_scans(self, query: str) -> List[Dict]:
        """Search scans by target or results content"""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT * FROM scans 
                    WHERE target LIKE ? OR results LIKE ? OR summary LIKE ?
                    ORDER BY timestamp DESC
                    LIMIT 20
                """, (f"%{query}%", f"%{query}%", f"%{query}%"))
                
                scans = []
                for row in cursor.fetchall():
                    scan = dict(row)
                    scan['tags'] = json.loads(scan.get('tags', '[]'))
                    scans.append(scan)
                
                return scans
        
        except Exception as e:
            print(f"Error searching scans: {e}")
            return []
    
    def _generate_summary(self, results: Dict, scan_type: str) -> str:
        """Generate summary text for scan results"""
        
        if scan_type == 'dns_enum':
            count = len(results) if isinstance(results, dict) else 0
            return f"DNS enumeration found {count} subdomains"
        
        elif scan_type == 'port_scan':
            if isinstance(results, dict) and 'open_ports' in results:
                count = len(results['open_ports'])
                return f"Port scan found {count} open ports"
            return "Port scan completed"
        
        elif scan_type == 'vuln_scan':
            if isinstance(results, dict) and 'vulnerabilities' in results:
                vulns = results['vulnerabilities']
                high = sum(1 for v in vulns if v.get('severity') == 'high')
                return f"Vulnerability scan found {len(vulns)} issues ({high} high severity)"
            return "Vulnerability scan completed"
        
        elif scan_type == 'osint':
            if isinstance(results, dict) and 'findings' in results:
                count = len(results['findings'])
                return f"OSINT collection gathered {count} intelligence findings"
            return "OSINT collection completed"
        
        else:
            return f"{scan_type} scan completed"
    
    def _count_results(self, results: Dict) -> int:
        """Count results for different scan types"""
        
        if isinstance(results, dict):
            if 'vulnerabilities' in results:
                return len(results['vulnerabilities'])
            elif 'findings' in results:
                return len(results['findings'])
            elif 'subdomains' in results:
                return len(results['subdomains'])
            else:
                return len(results)
        elif isinstance(results, list):
            return len(results)
        else:
            return 1

# Global instance
scan_db = ScanDatabase()