#!/usr/bin/env python3
"""
Test script to verify cleanup functionality works properly
"""

import sys
import os
import time
import threading

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.local_dns_server import local_dns_server
from app.core.vpn_manager import vpn_manager
from app.core.logger import logger

def test_cleanup():
    """Test the cleanup functionality"""
    print("Testing cleanup functionality...")
    
    # Test DNS server cleanup
    print("\n1. Testing DNS server cleanup:")
    if local_dns_server.is_licensed():
        print("   - Starting DNS server...")
        if local_dns_server.start_server():
            print(f"   - DNS server started on port {local_dns_server.port}")
            time.sleep(1)
            print("   - Stopping DNS server...")
            local_dns_server.stop_server()
            print("   - DNS server stopped successfully")
        else:
            print("   - Failed to start DNS server")
    else:
        print("   - DNS server requires Professional/Enterprise license")
    
    # Test VPN cleanup
    print("\n2. Testing VPN cleanup:")
    status = vpn_manager.get_status()
    if status['connected']:
        print("   - VPN is connected, testing disconnect...")
        result = vpn_manager.disconnect()
        if result['success']:
            print("   - VPN disconnected successfully")
        else:
            print(f"   - VPN disconnect failed: {result.get('error', 'Unknown error')}")
    else:
        print("   - No active VPN connection to test")
    
    print("\n3. Testing cleanup functions:")
    
    # Import cleanup function
    from main import cleanup_on_exit
    
    print("   - Running cleanup_on_exit()...")
    cleanup_on_exit()
    print("   - Cleanup completed successfully")
    
    print("\nCleanup test completed!")

if __name__ == "__main__":
    test_cleanup()