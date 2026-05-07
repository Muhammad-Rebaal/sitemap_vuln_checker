#!/usr/bin/env python3
"""
Test script to verify indentation fixes
"""
import sys
import subprocess
from pathlib import Path


def test_file_compilation(file_path):
    """Test if a Python file compiles without syntax errors"""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", str(file_path)],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            print(f"[SUCCESS] {file_path} compiles correctly")
            return True
        else:
            print(f"[ERROR] {file_path} has compilation errors:")
            print(result.stderr)
            return False
            
    except Exception as e:
        print(f"[ERROR] Failed to test {file_path}: {e}")
        return False


def main():
    """Test all key Python files for compilation"""
    print("Testing Python file compilation...")
    print("=" * 60)
    
    # Key files to test
    test_files = [
        "app.py",
        "sitemap_guard/cli.py",
        "sitemap_guard/pipeline.py",
    ]
    
    success_count = 0
    total_count = len(test_files)
    
    for file_path in test_files:
        if Path(file_path).exists():
            if test_file_compilation(file_path):
                success_count += 1
        else:
            print(f"[WARNING] {file_path} does not exist")
    
    print("=" * 60)
    print(f"Results: {success_count}/{total_count} files compile successfully")
    
    if success_count == total_count:
        print("[SUCCESS] All indentation issues have been fixed!")
        return True
    else:
        print(f"[ERROR] {total_count - success_count} files still have issues")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)