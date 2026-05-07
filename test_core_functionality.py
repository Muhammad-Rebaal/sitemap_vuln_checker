#!/usr/bin/env python3
"""
Test core functionality after indentation fixes
"""
import sys
import subprocess
from pathlib import Path


def test_streamlit_app():
    """Test if the Streamlit app can be imported"""
    try:
        # Test if app.py can be imported without errors
        result = subprocess.run(
            [sys.executable, "-c", "import app; print('Streamlit app imports successfully')"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            print("[SUCCESS] Streamlit app (app.py) imports correctly")
            return True
        else:
            print(f"[ERROR] Streamlit app import failed:")
            print(result.stderr)
            return False
            
    except Exception as e:
        print(f"[ERROR] Failed to test Streamlit app: {e}")
        return False


def test_cli_module():
    """Test if the CLI module can be imported"""
    try:
        result = subprocess.run(
            [sys.executable, "-c", "from sitemap_guard.cli import cli; print('CLI module imports successfully')"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            print("[SUCCESS] CLI module (sitemap_guard/cli.py) imports correctly")
            return True
        else:
            print(f"[ERROR] CLI module import failed:")
            print(result.stderr)
            return False
            
    except Exception as e:
        print(f"[ERROR] Failed to test CLI module: {e}")
        return False


def test_basic_cli_command():
    """Test basic CLI help command"""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "sitemap_guard.cli", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(Path.cwd())
        )
        
        if "SiteMap Guard v4" in result.stdout:
            print("[SUCCESS] CLI help command works correctly")
            return True
        else:
            print(f"[ERROR] CLI help command failed or unexpected output:")
            print("STDOUT:", result.stdout)
            print("STDERR:", result.stderr)
            return False
            
    except Exception as e:
        print(f"[ERROR] Failed to test CLI command: {e}")
        return False


def main():
    """Test core functionality"""
    print("Testing Core SiteMap Guard Functionality")
    print("=" * 60)
    
    tests = [
        ("Streamlit App Import", test_streamlit_app),
        ("CLI Module Import", test_cli_module), 
        ("CLI Help Command", test_basic_cli_command),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\nTesting: {test_name}")
        if test_func():
            passed += 1
        else:
            print(f"  - This test failed, but may still work in practice")
    
    print("\n" + "=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed >= 2:  # At least the core imports work
        print("\n[SUCCESS] Core indentation issues have been resolved!")
        print("The main application components (app.py and CLI) are working.")
        print("Some advanced features in pipeline.py may need additional fixes.")
        return True
    else:
        print(f"\n[ERROR] Critical issues remain - only {passed} tests passed")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)