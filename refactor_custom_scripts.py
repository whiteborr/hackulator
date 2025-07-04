# refactor_custom_scripts.py
"""
Migration script for custom_scripts.py refactoring

This script helps migrate from the monolithic custom_scripts.py to the new modular structure.
"""

import os
import shutil
from pathlib import Path

def backup_original_file():
    """Backup the original custom_scripts.py file"""
    project_root = Path(__file__).parent
    original_file = project_root / "app" / "core" / "custom_scripts.py"
    backup_file = project_root / "backup_custom_scripts.py"
    
    if original_file.exists():
        shutil.copy2(original_file, backup_file)
        print(f"Backed up original file to: {backup_file}")
        return True
    return False

def remove_original_file():
    """Remove the original custom_scripts.py file"""
    project_root = Path(__file__).parent
    original_file = project_root / "app" / "core" / "custom_scripts.py"
    
    if original_file.exists():
        original_file.unlink()
        print(f"Removed original file: {original_file}")
        return True
    return False

def main():
    """Run the refactoring migration"""
    print("Custom Scripts Refactoring Migration")
    print("=" * 40)
    
    # Step 1: Backup original file
    print("\n1. Backing up original custom_scripts.py...")
    if backup_original_file():
        print("Original file backed up successfully")
    else:
        print("Original file not found")
    
    # Step 2: Remove original file
    print("\n2. Removing original custom_scripts.py...")
    if remove_original_file():
        print("Original file removed successfully")
    else:
        print("Original file not found")
    
    print("\nRefactoring completed successfully!")
    print("\nNew structure:")
    print("• app/tools/recon.py - Subdomain enumeration and DNS reconnaissance")
    print("• app/tools/dns_utils.py - DNS utility functions")
    print("\nImport changes:")
    print("Before: from app.core import custom_scripts")
    print("After:  from app.tools import dns_utils")
    print("\nOriginal file backed up as: backup_custom_scripts.py")

if __name__ == "__main__":
    main()