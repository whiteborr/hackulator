# app/core/wordlist_manager.py
import os
import json
from typing import Dict, List, Optional
from datetime import datetime

class WordlistManager:
    """Manage custom wordlists for scanning"""
    
    def __init__(self):
        self.wordlists_dir = "wordlists"
        self.metadata_file = "wordlist_metadata.json"
        self.ensure_directories()
        self.metadata = self.load_metadata()
    
    def ensure_directories(self):
        """Ensure wordlist directories exist"""
        os.makedirs(self.wordlists_dir, exist_ok=True)
        os.makedirs(os.path.join(self.wordlists_dir, "custom"), exist_ok=True)
    
    def create_wordlist(self, name: str, content: List[str], category: str = "custom", 
                       description: str = "") -> bool:
        """Create new custom wordlist"""
        
        try:
            # Generate filename
            filename = f"{name.lower().replace(' ', '_')}.txt"
            filepath = os.path.join(self.wordlists_dir, "custom", filename)
            
            # Write wordlist content
            with open(filepath, 'w', encoding='utf-8') as f:
                for word in content:
                    f.write(f"{word.strip()}\n")
            
            # Update metadata
            wordlist_id = self._generate_id()
            self.metadata[wordlist_id] = {
                'name': name,
                'filename': filename,
                'filepath': filepath,
                'category': category,
                'description': description,
                'word_count': len(content),
                'created_date': datetime.now().isoformat(),
                'type': 'custom'
            }
            
            self.save_metadata()
            return True
            
        except Exception:
            return False
    
    def get_wordlists(self, category: str = None) -> List[Dict]:
        """Get available wordlists"""
        
        wordlists = []
        
        # Add custom wordlists from metadata
        for wl_id, wl_data in self.metadata.items():
            if category is None or wl_data.get('category') == category:
                wordlists.append({
                    'id': wl_id,
                    'name': wl_data['name'],
                    'filepath': wl_data['filepath'],
                    'category': wl_data.get('category', 'custom'),
                    'word_count': wl_data.get('word_count', 0),
                    'type': 'custom'
                })
        
        # Add built-in wordlists
        builtin_dir = os.path.join("resources", "wordlists")
        if os.path.exists(builtin_dir):
            for filename in os.listdir(builtin_dir):
                if filename.endswith('.txt'):
                    filepath = os.path.join(builtin_dir, filename)
                    word_count = self._count_words(filepath)
                    
                    wordlists.append({
                        'id': f"builtin_{filename}",
                        'name': filename.replace('.txt', '').replace('_', ' ').title(),
                        'filepath': filepath,
                        'category': 'builtin',
                        'word_count': word_count,
                        'type': 'builtin'
                    })
        
        return sorted(wordlists, key=lambda x: x['name'])
    
    def get_wordlist_content(self, wordlist_id: str) -> Optional[List[str]]:
        """Get wordlist content"""
        
        try:
            if wordlist_id.startswith('builtin_'):
                filename = wordlist_id.replace('builtin_', '')
                filepath = os.path.join("resources", "wordlists", filename)
            else:
                wordlist_data = self.metadata.get(wordlist_id)
                if not wordlist_data:
                    return None
                filepath = wordlist_data['filepath']
            
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    return [line.strip() for line in f if line.strip()]
            
            return None
            
        except Exception:
            return None
    
    def update_wordlist(self, wordlist_id: str, name: str = None, content: List[str] = None, 
                       description: str = None) -> bool:
        """Update existing wordlist"""
        
        if wordlist_id not in self.metadata:
            return False
        
        try:
            wordlist_data = self.metadata[wordlist_id]
            
            # Update content if provided
            if content is not None:
                with open(wordlist_data['filepath'], 'w', encoding='utf-8') as f:
                    for word in content:
                        f.write(f"{word.strip()}\n")
                wordlist_data['word_count'] = len(content)
            
            # Update metadata
            if name is not None:
                wordlist_data['name'] = name
            if description is not None:
                wordlist_data['description'] = description
            
            wordlist_data['modified_date'] = datetime.now().isoformat()
            
            self.save_metadata()
            return True
            
        except Exception:
            return False
    
    def delete_wordlist(self, wordlist_id: str) -> bool:
        """Delete custom wordlist"""
        
        if wordlist_id not in self.metadata:
            return False
        
        try:
            wordlist_data = self.metadata[wordlist_id]
            
            # Delete file
            if os.path.exists(wordlist_data['filepath']):
                os.remove(wordlist_data['filepath'])
            
            # Remove from metadata
            del self.metadata[wordlist_id]
            self.save_metadata()
            
            return True
            
        except Exception:
            return False
    
    def import_wordlist(self, filepath: str, name: str, category: str = "imported", 
                       description: str = "") -> bool:
        """Import wordlist from file"""
        
        try:
            # Read content
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = [line.strip() for line in f if line.strip()]
            
            return self.create_wordlist(name, content, category, description)
            
        except Exception:
            return False
    
    def export_wordlist(self, wordlist_id: str, export_path: str) -> bool:
        """Export wordlist to file"""
        
        content = self.get_wordlist_content(wordlist_id)
        if not content:
            return False
        
        try:
            with open(export_path, 'w', encoding='utf-8') as f:
                for word in content:
                    f.write(f"{word}\n")
            return True
            
        except Exception:
            return False
    
    def merge_wordlists(self, wordlist_ids: List[str], new_name: str, 
                       remove_duplicates: bool = True) -> bool:
        """Merge multiple wordlists into one"""
        
        try:
            merged_content = []
            
            for wl_id in wordlist_ids:
                content = self.get_wordlist_content(wl_id)
                if content:
                    merged_content.extend(content)
            
            if remove_duplicates:
                merged_content = list(set(merged_content))
            
            return self.create_wordlist(
                name=new_name,
                content=sorted(merged_content),
                category="merged",
                description=f"Merged from {len(wordlist_ids)} wordlists"
            )
            
        except Exception:
            return False
    
    def get_wordlist_statistics(self) -> Dict:
        """Get wordlist statistics"""
        
        stats = {
            'total_wordlists': 0,
            'custom_wordlists': 0,
            'builtin_wordlists': 0,
            'total_words': 0,
            'categories': {}
        }
        
        wordlists = self.get_wordlists()
        
        for wl in wordlists:
            stats['total_wordlists'] += 1
            stats['total_words'] += wl.get('word_count', 0)
            
            if wl['type'] == 'custom':
                stats['custom_wordlists'] += 1
            else:
                stats['builtin_wordlists'] += 1
            
            category = wl.get('category', 'unknown')
            if category not in stats['categories']:
                stats['categories'][category] = 0
            stats['categories'][category] += 1
        
        return stats
    
    def save_metadata(self):
        """Save metadata to file"""
        
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2, default=str)
        except Exception:
            pass
    
    def load_metadata(self) -> Dict:
        """Load metadata from file"""
        
        try:
            if os.path.exists(self.metadata_file):
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        
        return {}
    
    def _count_words(self, filepath: str) -> int:
        """Count words in wordlist file"""
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for line in f if line.strip())
        except Exception:
            return 0
    
    def _generate_id(self) -> str:
        """Generate unique wordlist ID"""
        
        import uuid
        return str(uuid.uuid4())[:8]

# Global instance
wordlist_manager = WordlistManager()