# app/ui/themes/enhanced_theme_manager.py
import json
import os
from pathlib import Path
from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QApplication
from app.core.unified_theme_manager import UnifiedThemeManager
from app.core.license_manager import license_manager

class EnhancedThemeManager(UnifiedThemeManager):
    """Enhanced theme manager with licensing and advanced features"""
    
    theme_locked = pyqtSignal(str, str)  # theme_name, upgrade_message
    
    def __init__(self, project_root):
        super().__init__(project_root)
        self.license_manager = license_manager
        self.theme_tiers = {
            'free': ['dark', 'light'],
            'professional': ['matrix', 'dark_pro', 'cyber_blue', 'terminal_green', 'cyberpunk', 'neon_hacker', 'corporate', 'high_contrast', 'ocean']
        }
        
        # Load enhanced themes
        self._load_enhanced_themes()
    
    def _load_enhanced_themes(self):
        """Load enhanced theme configurations with animations and effects"""
        enhanced_themes = {
            "dark_pro": {
                "name": "Dark Professional",
                "tier": "professional",
                "primary": "#64C8FF",
                "secondary": "#00FF41", 
                "accent": "#FFAA00",
                "background": "#0A0A0A",
                "surface": "#1e1e1e",
                "surface_variant": "#2d2d2d",
                "text": "#DCDCDC",
                "text_secondary": "#888888",
                "border": "#555555",
                "success": "#00AA00",
                "warning": "#FF6600",
                "error": "#FF4444",
                "animations": {
                    "scan_pulse": "#64C8FF",
                    "glow_effects": True,
                    "hover_scale": 1.05
                }
            },
            "cyber_blue": {
                "name": "Cybersecurity Blue",
                "tier": "professional",
                "primary": "#0077BE",
                "secondary": "#00AAFF",
                "accent": "#00DDAA",
                "background": "#001122",
                "surface": "#001A33",
                "surface_variant": "#002244",
                "text": "#E0F6FF",
                "text_secondary": "#B0D6E6",
                "border": "#0077BE",
                "success": "#00DDAA",
                "warning": "#FFAA00",
                "error": "#FF6B6B",
                "animations": {
                    "scan_pulse": "#00AAFF",
                    "wave_effects": True,
                    "hover_scale": 1.03
                }
            },
            "terminal_green": {
                "name": "Terminal Green",
                "tier": "professional",
                "primary": "#00FF00",
                "secondary": "#00CC00",
                "accent": "#AAFF00",
                "background": "#000000",
                "surface": "#001100",
                "surface_variant": "#002200",
                "text": "#00FF00",
                "text_secondary": "#00AA00",
                "border": "#00FF00",
                "success": "#00FF00",
                "warning": "#FFFF00",
                "error": "#FF4400",
                "animations": {
                    "scan_pulse": "#00FF00",
                    "terminal_effects": True,
                    "typing_animation": True
                }
            },
            "neon_hacker": {
                "name": "Neon Hacker",
                "tier": "professional",
                "primary": "#FF0080",
                "secondary": "#00FFFF",
                "accent": "#FFFF00",
                "background": "#000000",
                "surface": "#0A0A0A",
                "surface_variant": "#1A0A1A",
                "text": "#FF0080",
                "text_secondary": "#00FFFF",
                "border": "#FF0080",
                "success": "#00FF00",
                "warning": "#FFFF00",
                "error": "#FF0040",
                "animations": {
                    "scan_pulse": "#FF0080",
                    "neon_glow": True,
                    "holographic_effects": True,
                    "particle_field": True
                }
            },
            "corporate": {
                "name": "Corporate Professional",
                "tier": "professional",
                "primary": "#2E86AB",
                "secondary": "#A23B72",
                "accent": "#F18F01",
                "background": "#F5F5F5",
                "surface": "#FFFFFF",
                "surface_variant": "#E0E0E0",
                "text": "#212121",
                "text_secondary": "#757575",
                "border": "#CCCCCC",
                "success": "#4CAF50",
                "warning": "#FF9800",
                "error": "#F44336",
                "animations": {
                    "scan_pulse": "#2E86AB",
                    "subtle_effects": True,
                    "professional_transitions": True
                }
            },
            "high_contrast": {
                "name": "High Contrast Accessibility",
                "tier": "professional",
                "primary": "#FFFFFF",
                "secondary": "#FFFF00",
                "accent": "#00FFFF",
                "background": "#000000",
                "surface": "#000000",
                "surface_variant": "#333333",
                "text": "#FFFFFF",
                "text_secondary": "#CCCCCC",
                "border": "#FFFFFF",
                "success": "#00FF00",
                "warning": "#FFFF00",
                "error": "#FF0000",
                "animations": {
                    "scan_pulse": "#FFFFFF",
                    "high_contrast_mode": True,
                    "accessibility_focus": True
                }
            }
        }
        
        # Update existing themes with tier information
        self.themes["matrix"]["tier"] = "professional"
        self.themes["cyberpunk"]["tier"] = "professional"
        self.themes["ocean"]["tier"] = "professional"
        
        # Add enhanced themes
        self.themes.update(enhanced_themes)
    
    def get_available_themes(self):
        """Get themes based on license level"""
        available_themes = []
        
        for theme_key, theme_data in self.themes.items():
            tier = theme_data.get("tier", "free")
            
            if tier == "free":
                available_themes.append((theme_key, theme_data["name"]))
            elif tier == "professional" and 'Professional' in self.license_manager.license_data.get('license_type', ''):
                available_themes.append((theme_key, theme_data["name"]))
            elif tier == "enterprise" and self.license_manager.is_feature_enabled('enterprise_license'):
                available_themes.append((theme_key, theme_data["name"]))
        
        return available_themes
    
    def get_all_themes(self):
        """Get all themes regardless of license (for UI display)"""
        return [(key, theme["name"]) for key, theme in self.themes.items()]
    
    def can_use_theme(self, theme_name):
        """Check if user can use specific theme"""
        if theme_name not in self.themes:
            return False
            
        tier = self.themes[theme_name].get("tier", "free")
        
        if tier == "free":
            return True
        elif tier == "professional":
            return 'Professional' in self.license_manager.license_data.get('license_type', '')
        elif tier == "enterprise":
            return self.license_manager.is_feature_enabled('enterprise_license')
        
        return False
    
    def is_theme_available(self, theme_name):
        """Check if theme is available (alias for can_use_theme)"""
        return self.can_use_theme(theme_name)
    
    def set_theme(self, theme_name):
        """Set theme with license validation"""
        if not self.can_use_theme(theme_name):
            upgrade_msg = self.get_upgrade_message(theme_name)
            self.theme_locked.emit(theme_name, upgrade_msg)
            return False
            
        return super().set_theme(theme_name)
    
    def get_upgrade_message(self, theme_name):
        """Get upgrade message for locked themes"""
        if theme_name not in self.themes:
            return "Theme not found"
            
        tier = self.themes[theme_name].get("tier", "free")
        
        if tier == "professional":
            return "Upgrade to Professional license to unlock premium themes"
        elif tier == "enterprise":
            return "Upgrade to Professional license to unlock premium themes"
        
        return ""
    
    def get_theme_tier(self, theme_name):
        """Get theme tier"""
        return self.themes.get(theme_name, {}).get("tier", "free")
    
    def get_theme_animations(self, theme_name=None):
        """Get animation settings for theme"""
        theme_name = theme_name or self.current_theme
        return self.themes.get(theme_name, {}).get("animations", {})
    
    def _generate_enhanced_stylesheet(self, colors, animations=None):
        """Generate enhanced QSS stylesheet with animations support"""
        animations = animations or {}
        
        # Base stylesheet from parent
        base_stylesheet = self._generate_stylesheet(colors)
        
        # Enhanced styles without unsupported CSS properties
        enhanced_styles = f"""
        /* Enhanced Progress Bars */
        QProgressBar {{
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 {colors['surface']}, stop:1 {colors['surface_variant']});
        }}
        
        QProgressBar::chunk {{
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 {colors['primary']}, stop:1 {colors['accent']});
            border-radius: 3px;
        }}
        
        /* Enhanced Frames */
        QFrame {{
            border: 2px solid {colors['primary']};
            border-radius: 8px;
        }}
        """
        
        # Add theme-specific effects
        if animations.get('neon_glow'):
            enhanced_styles += f"""
            /* Neon Glow Effects */
            QPushButton:hover {{
                border: 2px solid {colors['primary']};
                background-color: {colors['surface']};
            }}
            """
        
        if animations.get('terminal_effects'):
            enhanced_styles += f"""
            /* Terminal Effects */
            QTextEdit {{
                font-family: 'Courier New', monospace;
            }}
            """
        
        return base_stylesheet + enhanced_styles
    
    def apply_theme(self, theme_name=None):
        """Apply theme with enhanced features"""
        theme_name = theme_name or self.current_theme
        if theme_name not in self.themes:
            return False
            
        colors = self.themes[theme_name]
        animations = colors.get("animations", {})
        
        stylesheet = self._generate_enhanced_stylesheet(colors, animations)
        
        app = QApplication.instance()
        if app:
            app.setStyleSheet(stylesheet)
        return True

# Global enhanced theme manager instance
enhanced_theme_manager = None

def get_enhanced_theme_manager(project_root=None):
    """Get global enhanced theme manager instance"""
    global enhanced_theme_manager
    if enhanced_theme_manager is None and project_root:
        enhanced_theme_manager = EnhancedThemeManager(project_root)
    return enhanced_theme_manager