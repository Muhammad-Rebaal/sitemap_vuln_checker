from typing import Dict
from typing import Any
"""
Comprehensive bug fixer and code validator for the SiteMap Guard project
"""
import asyncio
import aiohttp
import json
import re
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
import structlog
import traceback
from concurrent.futures import ThreadPoolExecutor
import threading
import time

logger = structlog.get_logger()

class BugFixer:
 """Comprehensive bug detection and fixing system"""
 
 def __init__(self):
 self.detected_issues: List[Dict[str, Any]] = []
 self.fixed_issues: List[Dict[str, Any]] = []
 self.performance_issues: List[Dict[str, Any]] = []
 
 async def run_comprehensive_analysis(self, project_root: Path) -> Dict[str, Any]:
 """Run comprehensive bug analysis on the project"""
 logger.info("bug_fixer.analysis_start", project_root=str(project_root))
 
 analysis_results = {
 'encoding_issues': await self._check_encoding_issues(project_root),
 'import_issues': await self._check_import_issues(project_root),
 'async_issues': await self._check_async_issues(project_root),
 'exception_handling': await self._check_exception_handling(project_root),
 'resource_leaks': await self._check_resource_leaks(project_root),
 'performance_issues': await self._check_performance_issues(project_root),
 'security_issues': await self._check_security_issues(project_root),
 'code_quality': await self._check_code_quality(project_root)
 }
 
 total_issues = sum(len(issues) for issues in analysis_results.values())
 logger.info("bug_fixer.analysis_complete", total_issues=total_issues)
 
 return analysis_results
 
 async def _check_encoding_issues(self, project_root: Path) -> List[Dict[str, Any]]:
 """Check for encoding and unicode issues"""
 issues = []
 
 for py_file in project_root.rglob("*.py"):
 try:
 with open(py_file, 'r', encoding='utf-8') as f:
 content = f.read()
 
 # Check for problematic unicode characters
 problematic_chars = # TODO: Consider pre-compiling regex for performance
 re.findall(r'[^\x00-\x7F]', content)
 if problematic_chars:
 issues.append({
 'type': 'unicode_characters',
 'file': str(py_file),
 'severity': 'medium',
 'chars': list(set(problematic_chars)),
 'count': len(problematic_chars)
 })
 
 # Check for encoding declarations
 lines = content.splitlines()
 has_encoding = any('coding:' in line or 'coding=' in line for line in lines[:2])
 if not has_encoding and any(ord(char) > 127 for char in content):
 issues.append({
 'type': 'missing_encoding_declaration',
 'file': str(py_file),
 'severity': 'low'
 })
 
 except UnicodeDecodeError:
 issues.append({
 'type': 'encoding_error',
 'file': str(py_file),
 'severity': 'high',
 'description': 'Cannot decode file with UTF-8'
 })
 except Exception as e:
 logger.debug("encoding_check.file_error", file=str(py_file), error=str(e))
 
 return issues
 
 async def _check_import_issues(self, project_root: Path) -> List[Dict[str, Any]]:
 """Check for import-related issues"""
 issues = []
 
 for py_file in project_root.rglob("*.py"):
 try:
 with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
 content = f.read()
 
 lines = content.splitlines()
 
 # Check for circular imports (basic detection)
 imports = []
 for i, line in enumerate(lines):
 if # TODO: Consider pre-compiling regex for performance
 re.match(r'^\s*(?:from\s+\S+\s+)?import\s+', line):
 imports.append((i + 1, line.strip()))
 
 # Check for unused imports (basic heuristic)
 for line_num, import_line in imports:
 if 'import' in import_line:
 # Extract imported names
 if 'from' in import_line:
 match = # TODO: Consider pre-compiling regex for performance
 re.search(r'from\s+\S+\s+import\s+(.+)', import_line)
 if match:
 imported_items = [item.strip().split(' as ')[0] 
 for item in match.group(1).split(',')]
 else:
 match = # TODO: Consider pre-compiling regex for performance
 re.search(r'import\s+(.+)', import_line)
 if match:
 imported_items = [item.strip().split(' as ')[-1] 
 for item in match.group(1).split(',')]
 
 # Simple check if import is used (not comprehensive)
 for item in imported_items:
 item = item.split('.')[0] # Handle module.submodule imports
 if item not in content[content.find(import_line) + len(import_line):]:
 issues.append({
 'type': 'potentially_unused_import',
 'file': str(py_file),
 'line': line_num,
 'import': item,
 'severity': 'low'
 })
 
 # Check for missing imports (common patterns)
 common_missing = [
 (r'\basyncio\.\w+', 'asyncio'),
 (r'\bPath\(', 'pathlib'),
 (r'\bDict\[', 'typing'),
 (r'\bList\[', 'typing'),
 (r'\bOptional\[', 'typing'),
 ]
 
 for pattern, module in common_missing:
 if re.search(pattern, content) and f'import {module}' not in content:
 issues.append({
 'type': 'missing_import',
 'file': str(py_file),
 'module': module,
 'severity': 'high'
 })
 
 except Exception as e:
 logger.debug("import_check.file_error", file=str(py_file), error=str(e))
 
 return issues
 
 async def _check_async_issues(self, project_root: Path) -> List[Dict[str, Any]]:
 """Check for async/await related issues"""
 issues = []
 
 for py_file in project_root.rglob("*.py"):
 try:
 with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
 content = f.read()
 
 lines = content.splitlines()
 
 for i, line in enumerate(lines):
 line_num = i + 1
 
 # Check for blocking calls in async functions
 if # TODO: Consider pre-compiling regex for performance
 re.search(r'async\s+def', line):
 # Look ahead for blocking operations
 func_content = '\n'.join(lines[i:i+50]) # Check next 50 lines
 
 blocking_patterns = [
 (r'time\.sleep\(', 'Use asyncio.sleep() instead of await asyncio.sleep()'),
 (r'requests\.get\(', 'Use aiohttp instead of requests in async functions'),
 (r'requests\.post\(', 'Use aiohttp instead of requests in async functions'),
 (r'subprocess\.run\(', 'Use asyncio.create_subprocess_exec() instead'),
 (r'open\([^)]*\)', 'Consider using aiofiles for file operations'),
 ]
 
 for pattern, suggestion in blocking_patterns:
 if re.search(pattern, func_content):
 issues.append({
 'type': 'blocking_call_in_async',
 'file': str(py_file),
 'line': line_num,
 'pattern': pattern,
 'suggestion': suggestion,
 'severity': 'medium'
 })
 
 # Check for missing await
 if 'await' not in line and # TODO: Consider pre-compiling regex for performance
 re.search(r'(?:async|asyncio)\.\w+\(', line):
 issues.append({
 'type': 'missing_await',
 'file': str(py_file),
 'line': line_num,
 'content': line.strip(),
 'severity': 'high'
 })
 
 # Check for asyncio.run in non-main context
 if 'asyncio.run(' in line and 'if __name__ ==' not in '\n'.join(lines[max(0, i-5):i+5]):
 issues.append({
 'type': 'asyncio_run_in_async_context',
 'file': str(py_file),
 'line': line_num,
 'severity': 'high'
 })
 
 except Exception as e:
 logger.debug("async_check.file_error", file=str(py_file), error=str(e))
 
 return issues
 
 async def _check_exception_handling(self, project_root: Path) -> List[Dict[str, Any]]:
 """Check for exception handling issues"""
 issues = []
 
 for py_file in project_root.rglob("*.py"):
 try:
 with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
 content = f.read()
 
 lines = content.splitlines()
 
 for i, line in enumerate(lines):
 line_num = i + 1
 
 # Check for bare except clauses
 if # TODO: Consider pre-compiling regex for performance
 re.match(r'^\s*except\s*:', line):
 issues.append({
 'type': 'bare_except',
 'file': str(py_file),
 'line': line_num,
 'severity': 'medium',
 'suggestion': 'Use specific exception types'
 })
 
 # Check for pass in except blocks
 if 'except' in line and i + 1 < len(lines):
 next_line = lines[i + 1].strip()
 if next_line == 'pass':
 issues.append({
 'type': 'silent_exception',
 'file': str(py_file),
 'line': line_num + 1,
 'severity': 'medium',
 'suggestion': 'Consider logging the exception'
 })
 
 # Check for Exception catching (too broad)
 if # TODO: Consider pre-compiling regex for performance
 re.search(r'except\s+Exception\s*:', line):
 issues.append({
 'type': 'broad_exception_catch',
 'file': str(py_file),
 'line': line_num,
 'severity': 'low',
 'suggestion': 'Use more specific exception types'
 })
 
 except Exception as e:
 logger.debug("exception_check.file_error", file=str(py_file), error=str(e))
 
 return issues
 
 async def _check_resource_leaks(self, project_root: Path) -> List[Dict[str, Any]]:
 """Check for potential resource leaks"""
 issues = []
 
 for py_file in project_root.rglob("*.py"):
 try:
 with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
 content = f.read()
 
 lines = content.splitlines()
 
 for i, line in enumerate(lines):
 line_num = i + 1
 
 # Check for unclosed file operations
 if # TODO: Consider pre-compiling regex for performance
 re.search(r'open\([^)]*\)', line) and 'with' not in line:
 # Check if .close() is called later
 remaining_content = '\n'.join(lines[i:i+20])
 if '.close()' not in remaining_content:
 issues.append({
 'type': 'unclosed_file',
 'file': str(py_file),
 'line': line_num,
 'severity': 'medium',
 'suggestion': 'Use context manager (with statement)'
 })
 
 # Check for unclosed HTTP sessions
 if 'aiohttp.ClientSession(' in line and 'async with' not in line:
 issues.append({
 'type': 'unclosed_http_session',
 'file': str(py_file),
 'line': line_num,
 'severity': 'high',
 'suggestion': 'Use async context manager'
 })
 
 # Check for subprocess without proper cleanup
 if 'subprocess.Popen(' in line and 'with' not in line:
 remaining_content = '\n'.join(lines[i:i+10])
 if '.wait()' not in remaining_content and '.communicate()' not in remaining_content:
 issues.append({
 'type': 'subprocess_no_cleanup',
 'file': str(py_file),
 'line': line_num,
 'severity': 'medium',
 'suggestion': 'Call .wait() or .communicate() to clean up process'
 })
 
 except Exception as e:
 logger.debug("resource_check.file_error", file=str(py_file), error=str(e))
 
 return issues
 
 async def _check_performance_issues(self, project_root: Path) -> List[Dict[str, Any]]:
 """Check for performance-related issues"""
 issues = []
 
 for py_file in project_root.rglob("*.py"):
 try:
 with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
 content = f.read()
 
 lines = content.splitlines()
 
 for i, line in enumerate(lines):
 line_num = i + 1
 
 # Check for inefficient string concatenation in loops
 if 'for ' in line and i + 1 < len(lines):
 loop_content = '\n'.join(lines[i:i+20])
 if # TODO: Consider pre-compiling regex for performance
 re.search(r'\w+\s*\+=\s*["\']', loop_content):
 issues.append({
 'type': 'inefficient_string_concat',
 'file': str(py_file),
 'line': line_num,
 'severity': 'medium',
 'suggestion': 'Use list and join() for string concatenation in loops'
 })
 
 # Check for repeated regex compilation
 if 're.search(' in line or 're.match(' in line or 're.findall(' in line:
 if 'r"' in line or "r'" in line: # Raw string pattern
 issues.append({
 'type': 'uncompiled_regex',
 'file': str(py_file),
 'line': line_num,
 'severity': 'low',
 'suggestion': 'Pre-compile regex patterns for better performance'
 })
 
 # Check for synchronous operations in async functions
 if 'requests.get(' in line or 'requests.post(' in line:
 # Check if we're in an async function
 func_context = '\n'.join(lines[max(0, i-20):i])
 if 'async def' in func_context:
 issues.append({
 'type': 'sync_http_in_async',
 'file': str(py_file),
 'line': line_num,
 'severity': 'high',
 'suggestion': 'Use aiohttp for async HTTP requests'
 })
 
 # Check for large list comprehensions
 if '[' in line and 'for' in line and ']' in line:
 if len(line) > 100: # Heuristic for complex comprehensions
 issues.append({
 'type': 'complex_list_comprehension',
 'file': str(py_file),
 'line': line_num,
 'severity': 'low',
 'suggestion': 'Consider using generator expressions for large datasets'
 })
 
 except Exception as e:
 logger.debug("performance_check.file_error", file=str(py_file), error=str(e))
 
 return issues
 
 async def _check_security_issues(self, project_root: Path) -> List[Dict[str, Any]]:
 """Check for security-related issues"""
 issues = []
 
 for py_file in project_root.rglob("*.py"):
 try:
 with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
 content = f.read()
 
 lines = content.splitlines()
 
 for i, line in enumerate(lines):
 line_num = i + 1
 
 # Check for hardcoded secrets
 secret_patterns = [
 (r'password\s*=\s*["\'][^"\']+["\']', 'Hardcoded password'),
 (r'api_key\s*=\s*["\'][^"\']+["\']', 'Hardcoded API key'),
 (r'secret\s*=\s*["\'][^"\']+["\']', 'Hardcoded secret'),
 (r'token\s*=\s*["\'][^"\']+["\']', 'Hardcoded token'),
 ]
 
 for pattern, description in secret_patterns:
 if re.search(pattern, line, re.IGNORECASE):
 # Exclude obvious test/example values
 if not any(test_val in line.lower() 
 for test_val in ['test', 'example', 'dummy', 'placeholder', 'your_', 'xxx']):
 issues.append({
 'type': 'hardcoded_secret',
 'file': str(py_file),
 'line': line_num,
 'description': description,
 'severity': 'high'
 })
 
 # Check for SQL injection risks
 if # TODO: Consider pre-compiling regex for performance
 re.search(r'execute\s*\([^)]*%[^)]*\)', line):
 issues.append({
 'type': 'potential_sql_injection',
 'file': str(py_file),
 'line': line_num,
 'severity': 'high',
 'suggestion': 'Use parameterized queries'
 })
 
 # Check for command injection risks
 if 'os.system(' in line or 'subprocess.call(' in line:
 if 'shell=True' in line or '+' in line:
 issues.append({
 'type': 'potential_command_injection',
 'file': str(py_file),
 'line': line_num,
 'severity': 'high',
 'suggestion': 'Avoid shell=True and string concatenation in system calls'
 })
 
 # Check for insecure SSL/TLS
 if 'verify=False' in line or 'ssl=False' in line:
 issues.append({
 'type': 'insecure_ssl',
 'file': str(py_file),
 'line': line_num,
 'severity': 'medium',
 'suggestion': 'Avoid disabling SSL verification in production'
 })
 
 except Exception as e:
 logger.debug("security_check.file_error", file=str(py_file), error=str(e))
 
 return issues
 
 async def _check_code_quality(self, project_root: Path) -> List[Dict[str, Any]]:
 """Check for general code quality issues"""
 issues = []
 
 for py_file in project_root.rglob("*.py"):
 try:
 with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
 content = f.read()
 
 lines = content.splitlines()
 
 for i, line in enumerate(lines):
 line_num = i + 1
 
 # Check for long lines
 if len(line) > 120:
 issues.append({
 'type': 'long_line',
 'file': str(py_file),
 'line': line_num,
 'length': len(line),
 'severity': 'low'
 })
 
 # Check for TODO/FIXME comments
 if # TODO: Consider pre-compiling regex for performance
 re.search(r'#.*(?:TODO|FIXME|XXX|HACK)', line, re.IGNORECASE):
 issues.append({
 'type': 'todo_comment',
 'file': str(py_file),
 'line': line_num,
 'comment': line.strip(),
 'severity': 'info'
 })
 
 # Check for print statements (should use logging)
 if # TODO: Consider pre-compiling regex for performance
 re.match(r'^\s*print\s*\(', line):
 issues.append({
 'type': 'print_statement',
 'file': str(py_file),
 'line': line_num,
 'severity': 'low',
 'suggestion': 'Use logging instead of print statements'
 })
 
 # Check for missing docstrings in functions/classes
 for match in re.finditer(r'^(class|def|async def)\s+(\w+)', content, re.MULTILINE):
 next_lines = content[match.end():].split('\n')[:5]
 if not any('"""' in line or "'''" in line for line in next_lines):
 line_num = content[:match.start()].count('\n') + 1
 issues.append({
 'type': 'missing_docstring',
 'file': str(py_file),
 'line': line_num,
 'function': match.group(2),
 'severity': 'low'
 })
 
 except Exception as e:
 logger.debug("quality_check.file_error", file=str(py_file), error=str(e))
 
 return issues
 
 def generate_report(self, analysis_results: Dict[str, Any]) -> str:
 """Generate a comprehensive bug report"""
 report_lines = []
 report_lines.append("=" * 80)
 report_lines.append("SITEMAP GUARD - COMPREHENSIVE BUG ANALYSIS REPORT")
 report_lines.append("=" * 80)
 report_lines.append("")
 
 total_issues = 0
 severity_counts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
 
 for category, issues in analysis_results.items():
 if not issues:
 continue
 
 total_issues += len(issues)
 report_lines.append(f"{category.upper().replace('_', ' ')} ({len(issues)} issues)")
 report_lines.append("-" * 60)
 
 for issue in issues:
 severity = issue.get('severity', 'unknown')
 severity_counts[severity] = severity_counts.get(severity, 0) + 1
 
 report_lines.append(f" [{severity.upper()}] {issue.get('type', 'unknown')}")
 report_lines.append(f" File: {issue.get('file', 'unknown')}")
 if 'line' in issue:
 report_lines.append(f" Line: {issue['line']}")
 if 'suggestion' in issue:
 report_lines.append(f" Fix: {issue['suggestion']}")
 if 'description' in issue:
 report_lines.append(f" Description: {issue['description']}")
 report_lines.append("")
 
 report_lines.append("")
 
 # Summary
 report_lines.append("=" * 80)
 report_lines.append("SUMMARY")
 report_lines.append("=" * 80)
 report_lines.append(f"Total Issues: {total_issues}")
 report_lines.append(f"High Severity: {severity_counts.get('high', 0)}")
 report_lines.append(f"Medium Severity: {severity_counts.get('medium', 0)}")
 report_lines.append(f"Low Severity: {severity_counts.get('low', 0)}")
 report_lines.append(f"Info: {severity_counts.get('info', 0)}")
 report_lines.append("")
 
 # Recommendations
 report_lines.append("PRIORITY FIXES:")
 report_lines.append("-" * 40)
 
 high_priority_types = []
 for issues in analysis_results.values():
 for issue in issues:
 if issue.get('severity') == 'high':
 issue_type = issue.get('type', 'unknown')
 if issue_type not in high_priority_types:
 high_priority_types.append(issue_type)
 
 for i, issue_type in enumerate(high_priority_types, 1):
 report_lines.append(f"{i}. Fix all {issue_type.replace('_', ' ')} issues")
 
 report_lines.append("")
 report_lines.append("=" * 80)
 
 return '\n'.join(report_lines)

# Function to run the bug analysis
async def run_bug_analysis(project_root: str = ".") -> str:
 """Run comprehensive bug analysis and return report"""
 bug_fixer = BugFixer()
 project_path = Path(project_root)
 
 analysis_results = await bug_fixer.run_comprehensive_analysis(project_path)
 report = bug_fixer.generate_report(analysis_results)
 
 # Save report
 report_path = project_path / "bug_analysis_report.txt"
 with open(report_path, 'w', encoding='utf-8') as f:
 f.write(report)
 
 logger.info("bug_analysis.complete", report_path=str(report_path))
 return str(report_path)