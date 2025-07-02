# app/core/session_manager.py
import json
import os
from datetime import datetime
from typing import Dict, List, Optional
from app.core.scan_database import scan_db

class SessionManager:
    """Manage scanning sessions and project organization"""
    
    def __init__(self):
        self.current_session = None
        self.sessions_file = "sessions.json"
        self.sessions = self.load_sessions()
    
    def create_session(self, name: str, description: str = "", targets: List[str] = None) -> Dict:
        """Create a new scanning session"""
        
        session = {
            'id': self._generate_session_id(),
            'name': name,
            'description': description,
            'created_date': datetime.now().isoformat(),
            'targets': targets or [],
            'scan_ids': [],
            'status': 'active',
            'tags': [],
            'notes': ""
        }
        
        self.sessions[session['id']] = session
        self.save_sessions()
        
        return session
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session by ID"""
        return self.sessions.get(session_id)
    
    def get_all_sessions(self) -> List[Dict]:
        """Get all sessions"""
        return list(self.sessions.values())
    
    def update_session(self, session_id: str, updates: Dict) -> bool:
        """Update session information"""
        
        if session_id in self.sessions:
            self.sessions[session_id].update(updates)
            self.sessions[session_id]['modified_date'] = datetime.now().isoformat()
            self.save_sessions()
            return True
        
        return False
    
    def delete_session(self, session_id: str) -> bool:
        """Delete session"""
        
        if session_id in self.sessions:
            del self.sessions[session_id]
            self.save_sessions()
            return True
        
        return False
    
    def add_scan_to_session(self, session_id: str, scan_id: int) -> bool:
        """Add scan to session"""
        
        if session_id in self.sessions:
            if scan_id not in self.sessions[session_id]['scan_ids']:
                self.sessions[session_id]['scan_ids'].append(scan_id)
                self.save_sessions()
            return True
        
        return False
    
    def remove_scan_from_session(self, session_id: str, scan_id: int) -> bool:
        """Remove scan from session"""
        
        if session_id in self.sessions:
            if scan_id in self.sessions[session_id]['scan_ids']:
                self.sessions[session_id]['scan_ids'].remove(scan_id)
                self.save_sessions()
            return True
        
        return False
    
    def get_session_scans(self, session_id: str) -> List[Dict]:
        """Get all scans for a session"""
        
        session = self.get_session(session_id)
        if not session:
            return []
        
        scans = []
        for scan_id in session['scan_ids']:
            scan = scan_db.get_scan_by_id(scan_id)
            if scan:
                scans.append(scan)
        
        return scans
    
    def set_current_session(self, session_id: str) -> bool:
        """Set current active session"""
        
        if session_id in self.sessions:
            self.current_session = session_id
            return True
        
        return False
    
    def get_current_session(self) -> Optional[Dict]:
        """Get current active session"""
        
        if self.current_session:
            return self.get_session(self.current_session)
        
        return None
    
    def get_session_statistics(self, session_id: str) -> Dict:
        """Get statistics for a session"""
        
        session = self.get_session(session_id)
        if not session:
            return {}
        
        scans = self.get_session_scans(session_id)
        
        stats = {
            'total_scans': len(scans),
            'targets_scanned': len(set(scan['target'] for scan in scans)),
            'scan_types': {},
            'total_results': 0,
            'date_range': {'start': None, 'end': None}
        }
        
        for scan in scans:
            # Count scan types
            scan_type = scan['scan_type']
            if scan_type not in stats['scan_types']:
                stats['scan_types'][scan_type] = 0
            stats['scan_types'][scan_type] += 1
            
            # Count results
            stats['total_results'] += scan.get('results_count', 0)
            
            # Track date range
            scan_date = scan['timestamp']
            if not stats['date_range']['start'] or scan_date < stats['date_range']['start']:
                stats['date_range']['start'] = scan_date
            if not stats['date_range']['end'] or scan_date > stats['date_range']['end']:
                stats['date_range']['end'] = scan_date
        
        return stats
    
    def export_session(self, session_id: str, export_path: str) -> bool:
        """Export session data to file"""
        
        session = self.get_session(session_id)
        if not session:
            return False
        
        scans = self.get_session_scans(session_id)
        
        export_data = {
            'session': session,
            'scans': scans,
            'statistics': self.get_session_statistics(session_id),
            'exported_date': datetime.now().isoformat()
        }
        
        try:
            with open(export_path, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            return True
        except Exception:
            return False
    
    def import_session(self, import_path: str) -> Optional[str]:
        """Import session from file"""
        
        try:
            with open(import_path, 'r') as f:
                import_data = json.load(f)
            
            session_data = import_data.get('session', {})
            scans_data = import_data.get('scans', [])
            
            # Create new session
            new_session = self.create_session(
                name=f"Imported: {session_data.get('name', 'Unknown')}",
                description=session_data.get('description', ''),
                targets=session_data.get('targets', [])
            )
            
            # Import scans
            for scan_data in scans_data:
                scan_id = scan_db.save_scan(
                    target=scan_data['target'],
                    scan_type=scan_data['scan_type'],
                    results=scan_data.get('results', {}),
                    duration=scan_data.get('duration', 0)
                )
                
                if scan_id:
                    self.add_scan_to_session(new_session['id'], scan_id)
            
            return new_session['id']
        
        except Exception:
            return None
    
    def save_sessions(self):
        """Save sessions to file"""
        
        try:
            with open(self.sessions_file, 'w') as f:
                json.dump(self.sessions, f, indent=2, default=str)
        except Exception:
            pass
    
    def load_sessions(self) -> Dict:
        """Load sessions from file"""
        
        try:
            if os.path.exists(self.sessions_file):
                with open(self.sessions_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        
        return {}
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        
        import uuid
        return str(uuid.uuid4())[:8]

# Global instance
session_manager = SessionManager()