#!/usr/bin/env python3
"""
Installation verification script for LNURL-pay server
Checks that all dependencies and configuration are correct
"""

import sys
import os
import json

def check_python_version():
    """Verify Python version is 3.7+"""
    if sys.version_info < (3, 7):
        print("❌ Python 3.7+ required")
        print(f"   Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    return True

def check_dependencies():
    """Check if required Python packages are installed"""
    try:
        import requests
        print(f"✅ requests module installed (version {requests.__version__})")
        return True
    except ImportError:
        print("❌ requests module not installed")
        print("   Run: pip install -r requirements.txt")
        return False

def check_config_file():
    """Verify config.json exists and is valid"""
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    
    if not os.path.exists(config_path):
        print("❌ config.json not found")
        print("   Run: cp config.json.example config.json")
        return False
    
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        print("✅ config.json found and valid")
        
        # Check required fields
        required_fields = {
            "server": ["host", "port"],
            "lnd": ["onion_address", "port", "macaroon_path"],
            "tor": ["proxy"],
            "lnurlp": ["domain", "min_sendable", "max_sendable", "comment_allowed"]
        }
        
        missing = []
        for section, fields in required_fields.items():
            if section not in config:
                missing.append(f"{section}.*")
            else:
                for field in fields:
                    if field not in config[section]:
                        missing.append(f"{section}.{field}")
        
        if missing:
            print(f"⚠️  Missing config fields: {', '.join(missing)}")
            return False
        
        print("✅ All required config fields present")
        return True
        
    except json.JSONDecodeError as e:
        print(f"❌ config.json is invalid JSON: {e}")
        return False

def check_macaroon_file():
    """Verify macaroon file exists and is readable"""
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    
    if not os.path.exists(config_path):
        print("⚠️  Skipping macaroon check (no config.json)")
        return True
    
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        macaroon_path = config.get("lnd", {}).get("macaroon_path", "")
        
        if not macaroon_path:
            print("⚠️  Macaroon path not configured")
            return True
        
        if not os.path.exists(macaroon_path):
            print(f"❌ Macaroon file not found: {macaroon_path}")
            print("   Update config.json with correct path")
            return False
        
        # Try to read it
        try:
            with open(macaroon_path, 'rb') as f:
                data = f.read()
                if len(data) == 0:
                    print(f"❌ Macaroon file is empty: {macaroon_path}")
                    return False
                print(f"✅ Macaroon file readable ({len(data)} bytes)")
                return True
        except PermissionError:
            print(f"❌ Cannot read macaroon file (permission denied): {macaroon_path}")
            return False
            
    except Exception as e:
        print(f"⚠️  Could not verify macaroon: {e}")
        return True

def check_server_file():
    """Verify server.py exists"""
    server_path = os.path.join(os.path.dirname(__file__), "server.py")
    
    if not os.path.exists(server_path):
        print("❌ server.py not found")
        return False
    
    print("✅ server.py found")
    return True

def main():
    print("=" * 60)
    print("LNURL-pay Server - Installation Verification")
    print("=" * 60)
    print()
    
    checks = [
        ("Python Version", check_python_version),
        ("Dependencies", check_dependencies),
        ("Server File", check_server_file),
        ("Configuration File", check_config_file),
        ("Macaroon File", check_macaroon_file),
    ]
    
    results = []
    for name, check_func in checks:
        print(f"\nChecking {name}...")
        results.append(check_func())
    
    print("\n" + "=" * 60)
    
    if all(results):
        print("✅ All checks passed! Server is ready to start.")
        print("\nTo start the server, run:")
        print("  python server.py")
        return 0
    else:
        print("❌ Some checks failed. Please fix the issues above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
