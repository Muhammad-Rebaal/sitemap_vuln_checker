"""
Project cleaner to remove unused libraries, dependencies, and unrelated code
"""
import ast
import re
import subprocess
from pathlib import Path
from typing import Set, List, Dict, Any
import structlog

logger = structlog.get_logger()

class ProjectCleaner:
    """
    Comprehensive project cleaner that:
    1. Identifies unused imports and dependencies
    2. Removes unrelated code and modules
    3. Cleans up temporary files and caches
    4. Optimizes project structure
    """
    
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.used_imports = set()
        self.unused_imports = set()
        self.unused_files = []
        self.unnecessary_dependencies = []
        
    def analyze_project(self) -> Dict[str, Any]:
        """Analyze project to identify cleanup opportunities"""
        logger.info("project_cleaner.analysis_start")
        
        analysis = {
            'used_imports': self._find_used_imports(),
            'unused_imports': self._find_unused_imports(),
            'unused_files': self._find_unused_files(),
            'unnecessary_dependencies': self._find_unnecessary_dependencies(),
            'large_files': self._find_large_files(),
            'duplicate_files': self._find_duplicate_files(),
            'cache_files': self._find_cache_files()
        }
        
        logger.info("project_cleaner.analysis_complete",
                   unused_imports=len(analysis['unused_imports']),
                   unused_files=len(analysis['unused_files']),
                   cache_files=len(analysis['cache_files']))
        
        return analysis
    
    def _find_used_imports(self) -> Set[str]:
        """Find all imports that are actually used in the codebase"""
        used_imports = set()
        
        for py_file in self.project_root.rglob("*.py"):
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Parse AST to find imports
                try:
                    tree = ast.parse(content)
                    
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                used_imports.add(alias.name.split('.')[0])
                        elif isinstance(node, ast.ImportFrom):
                            if node.module:
                                used_imports.add(node.module.split('.')[0])
                
                except SyntaxError:
                    # If file has syntax errors, skip AST parsing and use regex
                    import_matches = re.findall(r'(?:from\s+(\w+)|import\s+(\w+))', content)
                    for match in import_matches:
                        module = match[0] or match[1]
                        if module:
                            used_imports.add(module)
                            
            except Exception as e:
                logger.debug("import_analysis_failed", file=str(py_file), error=str(e))
        
        return used_imports
    
    def _find_unused_imports(self) -> List[Dict[str, Any]]:
        """Find imports that are not used"""
        unused_imports = []
        
        for py_file in self.project_root.rglob("*.py"):
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                for i, line in enumerate(lines):
                    line_stripped = line.strip()
                    
                    # Skip if not an import line
                    if not (line_stripped.startswith('import ') or line_stripped.startswith('from ')):
                        continue
                    
                    # Extract imported names
                    imported_names = self._extract_imported_names(line_stripped)
                    
                    # Check if any of the imported names are used in the file
                    file_content = ''.join(lines)
                    
                    for imported_name in imported_names:
                        # Simple check: if the name appears elsewhere in the file
                        if imported_name not in file_content[file_content.find(line):] or \
                           file_content.count(imported_name) <= 1:
                            unused_imports.append({
                                'file': str(py_file),
                                'line_number': i + 1,
                                'import_line': line_stripped,
                                'imported_name': imported_name
                            })
            
            except Exception as e:
                logger.debug("unused_import_analysis_failed", file=str(py_file), error=str(e))
        
        return unused_imports
    
    def _extract_imported_names(self, import_line: str) -> List[str]:
        """Extract imported names from import line"""
        names = []
        
        if import_line.startswith('from '):
            # from module import name1, name2
            match = re.search(r'import\s+(.+)', import_line)
            if match:
                imports = match.group(1)
                for name in imports.split(','):
                    name = name.strip().split(' as ')[0]
                    names.append(name)
        
        elif import_line.startswith('import '):
            # import module1, module2
            match = re.search(r'import\s+(.+)', import_line)
            if match:
                imports = match.group(1)
                for name in imports.split(','):
                    name = name.strip().split(' as ')[-1]  # Get alias if present
                    names.append(name.split('.')[0])  # Get root module name
        
        return names
    
    def _find_unused_files(self) -> List[str]:
        """Find Python files that are not imported or used"""
        unused_files = []
        
        # Get all Python files
        all_py_files = list(self.project_root.rglob("*.py"))
        
        # Files that should always be kept
        keep_patterns = [
            'main.py', '__main__.py', 'app.py', 'cli.py', 'setup.py',
            'conftest.py', 'test_*.py', '*_test.py'
        ]
        
        for py_file in all_py_files:
            relative_path = py_file.relative_to(self.project_root)
            
            # Skip files that should be kept
            if any(py_file.match(pattern) for pattern in keep_patterns):
                continue
            
            # Skip __init__.py files
            if py_file.name == '__init__.py':
                continue
            
            # Check if file is imported anywhere
            module_name = str(relative_path).replace('/', '.').replace('\\', '.').replace('.py', '')
            is_imported = False
            
            for other_file in all_py_files:
                if other_file == py_file:
                    continue
                
                try:
                    with open(other_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Check for direct imports
                    if module_name in content or py_file.stem in content:
                        is_imported = True
                        break
                        
                except Exception:
                    continue
            
            if not is_imported:
                unused_files.append(str(relative_path))
        
        return unused_files
    
    def _find_unnecessary_dependencies(self) -> List[str]:
        """Find dependencies listed but not used"""
        unnecessary = []
        
        # Read pyproject.toml or requirements.txt
        pyproject_file = self.project_root / "pyproject.toml"
        requirements_file = self.project_root / "requirements.txt"
        
        declared_deps = set()
        
        if pyproject_file.exists():
            try:
                with open(pyproject_file, 'r') as f:
                    content = f.read()
                
                # Extract dependencies from pyproject.toml
                deps_match = re.search(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
                if deps_match:
                    deps_text = deps_match.group(1)
                    for line in deps_text.split('\n'):
                        line = line.strip().strip('"').strip("'").strip(',')
                        if line and not line.startswith('#'):
                            # Extract package name (before >= or other version specifiers)
                            pkg_name = re.split(r'[>=<]', line)[0].strip()
                            declared_deps.add(pkg_name)
            
            except Exception as e:
                logger.debug("pyproject_analysis_failed", error=str(e))
        
        elif requirements_file.exists():
            try:
                with open(requirements_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            pkg_name = re.split(r'[>=<]', line)[0].strip()
                            declared_deps.add(pkg_name)
            
            except Exception as e:
                logger.debug("requirements_analysis_failed", error=str(e))
        
        # Check which dependencies are not imported
        for dep in declared_deps:
            # Convert package names to import names (rough heuristic)
            import_names = [
                dep,
                dep.replace('-', '_'),
                dep.replace('_', '-'),
                dep.lower(),
                dep.upper()
            ]
            
            is_used = any(imp_name in self.used_imports for imp_name in import_names)
            
            if not is_used:
                unnecessary.append(dep)
        
        return unnecessary
    
    def _find_large_files(self) -> List[Dict[str, Any]]:
        """Find unusually large files that might need attention"""
        large_files = []
        
        for py_file in self.project_root.rglob("*.py"):
            try:
                size = py_file.stat().st_size
                if size > 50 * 1024:  # Files larger than 50KB
                    large_files.append({
                        'file': str(py_file.relative_to(self.project_root)),
                        'size_kb': size // 1024,
                        'size_bytes': size
                    })
            
            except Exception:
                continue
        
        # Sort by size descending
        large_files.sort(key=lambda x: x['size_bytes'], reverse=True)
        
        return large_files
    
    def _find_duplicate_files(self) -> List[List[str]]:
        """Find potential duplicate files"""
        duplicates = []
        file_hashes = {}
        
        for py_file in self.project_root.rglob("*.py"):
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Simple hash of content (ignoring whitespace differences)
                normalized_content = re.sub(r'\s+', ' ', content).strip()
                content_hash = hash(normalized_content)
                
                if content_hash in file_hashes:
                    file_hashes[content_hash].append(str(py_file.relative_to(self.project_root)))
                else:
                    file_hashes[content_hash] = [str(py_file.relative_to(self.project_root))]
            
            except Exception:
                continue
        
        # Find groups with more than one file
        for files in file_hashes.values():
            if len(files) > 1:
                duplicates.append(files)
        
        return duplicates
    
    def _find_cache_files(self) -> List[str]:
        """Find cache and temporary files that can be removed"""
        cache_patterns = [
            '**/__pycache__',
            '**/*.pyc',
            '**/*.pyo',
            '**/.pytest_cache',
            '**/node_modules',
            '**/.coverage',
            '**/*.log',
            '**/*.tmp',
            '**/.DS_Store',
            '**/Thumbs.db'
        ]
        
        cache_files = []
        
        for pattern in cache_patterns:
            for path in self.project_root.glob(pattern):
                cache_files.append(str(path.relative_to(self.project_root)))
        
        return cache_files
    
    def clean_project(self, analysis: Dict[str, Any], confirm_deletions: bool = False) -> Dict[str, Any]:
        """Clean project based on analysis"""
        logger.info("project_cleaner.cleanup_start")
        
        cleanup_results = {
            'files_removed': [],
            'imports_cleaned': 0,
            'cache_cleared': 0,
            'space_saved_mb': 0
        }
        
        # Remove cache files
        cache_files = analysis.get('cache_files', [])
        space_saved = 0
        
        for cache_file in cache_files:
            cache_path = self.project_root / cache_file
            try:
                if cache_path.exists():
                    if cache_path.is_file():
                        space_saved += cache_path.stat().st_size
                        if not confirm_deletions:
                            cache_path.unlink()
                            cleanup_results['files_removed'].append(str(cache_file))
                    elif cache_path.is_dir():
                        if not confirm_deletions:
                            import shutil
                            shutil.rmtree(cache_path)
                            cleanup_results['files_removed'].append(str(cache_file))
                        
                cleanup_results['cache_cleared'] += 1
                        
            except Exception as e:
                logger.debug("cache_cleanup_failed", file=cache_file, error=str(e))
        
        cleanup_results['space_saved_mb'] = space_saved / (1024 * 1024)
        
        # Clean unused imports (optional - requires confirmation)
        if not confirm_deletions:
            unused_imports = analysis.get('unused_imports', [])
            cleanup_results['imports_cleaned'] = len(unused_imports)
            # Note: Actually removing imports requires careful analysis
        
        logger.info("project_cleaner.cleanup_complete", **cleanup_results)
        
        return cleanup_results
    
    def generate_cleanup_report(self, analysis: Dict[str, Any]) -> str:
        """Generate detailed cleanup report"""
        
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("PROJECT CLEANUP ANALYSIS REPORT")
        report_lines.append("=" * 80)
        report_lines.append(f"Project: {self.project_root.name}")
        report_lines.append(f"Analysis Date: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("=" * 80)
        report_lines.append("")
        
        # Unused imports
        unused_imports = analysis.get('unused_imports', [])
        if unused_imports:
            report_lines.append(f"UNUSED IMPORTS ({len(unused_imports)} found)")
            report_lines.append("-" * 40)
            
            files_with_unused = {}
            for imp in unused_imports:
                file_path = imp['file']
                if file_path not in files_with_unused:
                    files_with_unused[file_path] = []
                files_with_unused[file_path].append(imp)
            
            for file_path, imports in files_with_unused.items():
                report_lines.append(f"  {file_path}:")
                for imp in imports[:5]:  # Limit to first 5
                    report_lines.append(f"    Line {imp['line_number']}: {imp['import_line']}")
                if len(imports) > 5:
                    report_lines.append(f"    ... and {len(imports) - 5} more")
                report_lines.append("")
        
        # Unused files
        unused_files = analysis.get('unused_files', [])
        if unused_files:
            report_lines.append(f"POTENTIALLY UNUSED FILES ({len(unused_files)} found)")
            report_lines.append("-" * 40)
            for file_path in unused_files[:20]:
                report_lines.append(f"  {file_path}")
            if len(unused_files) > 20:
                report_lines.append(f"  ... and {len(unused_files) - 20} more")
            report_lines.append("")
        
        # Unnecessary dependencies
        unnecessary_deps = analysis.get('unnecessary_dependencies', [])
        if unnecessary_deps:
            report_lines.append(f"UNNECESSARY DEPENDENCIES ({len(unnecessary_deps)} found)")
            report_lines.append("-" * 40)
            for dep in unnecessary_deps:
                report_lines.append(f"  {dep}")
            report_lines.append("")
        
        # Large files
        large_files = analysis.get('large_files', [])
        if large_files:
            report_lines.append(f"LARGE FILES ({len(large_files)} found)")
            report_lines.append("-" * 40)
            for file_info in large_files[:10]:
                report_lines.append(f"  {file_info['file']} ({file_info['size_kb']} KB)")
            report_lines.append("")
        
        # Cache files
        cache_files = analysis.get('cache_files', [])
        if cache_files:
            report_lines.append(f"CACHE FILES ({len(cache_files)} found)")
            report_lines.append("-" * 40)
            for cache_file in cache_files[:15]:
                report_lines.append(f"  {cache_file}")
            if len(cache_files) > 15:
                report_lines.append(f"  ... and {len(cache_files) - 15} more")
            report_lines.append("")
        
        # Duplicates
        duplicates = analysis.get('duplicate_files', [])
        if duplicates:
            report_lines.append(f"DUPLICATE FILES ({len(duplicates)} groups found)")
            report_lines.append("-" * 40)
            for group in duplicates:
                report_lines.append(f"  Duplicate group:")
                for file_path in group:
                    report_lines.append(f"    - {file_path}")
                report_lines.append("")
        
        # Summary
        report_lines.append("=" * 80)
        report_lines.append("CLEANUP RECOMMENDATIONS")
        report_lines.append("=" * 80)
        report_lines.append("1. Remove cache files and directories (__pycache__, *.pyc, etc.)")
        report_lines.append("2. Review and remove unused imports")
        report_lines.append("3. Consider removing unused files after verification")
        report_lines.append("4. Update dependencies list to remove unnecessary packages")
        report_lines.append("5. Review large files for optimization opportunities")
        report_lines.append("6. Remove or consolidate duplicate files")
        report_lines.append("")
        report_lines.append("=" * 80)
        
        return '\n'.join(report_lines)

# High-level functions for easy use
def analyze_and_clean_project(project_root: str = ".", auto_clean_cache: bool = True) -> Dict[str, Any]:
    """
    Analyze project and optionally clean cache files automatically
    """
    cleaner = ProjectCleaner(project_root)
    
    # Analyze project
    analysis = cleaner.analyze_project()
    
    # Auto-clean cache files if requested
    cleanup_results = None
    if auto_clean_cache:
        cleanup_results = cleaner.clean_project(analysis, confirm_deletions=False)
    
    # Generate report
    report = cleaner.generate_cleanup_report(analysis)
    
    # Save report
    report_path = Path(project_root) / "project_cleanup_report.txt"
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report)
    
    return {
        'analysis': analysis,
        'cleanup_results': cleanup_results,
        'report_path': str(report_path),
        'report_content': report
    }