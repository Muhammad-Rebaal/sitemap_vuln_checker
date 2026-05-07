from typing import Dict
from typing import Optional
from typing import Any
"""
Advanced security tool integrator with multiple external tools
Integrates: subfinder, amass, nmap, masscan, gobuster, ffuf, nikto, sqlmap, dirb
"""
import os
import json
import asyncio
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
import structlog
from concurrent.futures import ThreadPoolExecutor
import tempfile
import re

logger = structlog.get_logger()

class AdvancedSecurityScanner:
 """Integrates multiple security tools for comprehensive scanning"""
 
 def __init__(self, target_url: str, output_dir: str = "./reports"):
 self.target_url = target_url.rstrip('/')
 self.domain = self._extract_domain(target_url)
 self.output_dir = Path(output_dir)
 self.output_dir.mkdir(exist_ok=True)
 self.bin_dir = Path(__file__).parent.parent.parent / "bin"
 self.tools_available = self._check_tool_availability()
 
 def _extract_domain(self, url: str) -> str:
 """Extract domain from URL"""
 from urllib.parse import urlparse
 parsed = urlparse(url)
 return parsed.netloc or parsed.path
 
 def _check_tool_availability(self) -> Dict[str, bool]:
 """Check which security tools are available"""
 tools = {
 'subfinder': self._check_binary('subfinder'),
 'amass': self._check_binary('amass'),
 'nmap': self._check_binary('nmap'),
 'masscan': self._check_binary('masscan'),
 'gobuster': self._check_binary('gobuster'),
 'nikto': self._check_binary('nikto'),
 'dirb': self._check_binary('dirb'),
 'wpscan': self._check_binary('wpscan'),
 'sqlmap': self._check_binary('sqlmap'),
 'nuclei': self._check_binary('nuclei'),
 'httpx': self._check_binary('httpx'),
 'ffuf': self._check_binary('ffuf')
 }
 
 available = [tool for tool, status in tools.items() if status]
 if available:
 logger.info("tools.available", tools=available)
 else:
 logger.warning("tools.none_available", msg="No external security tools found")
 
 return tools
 
 def _check_binary(self, tool_name: str) -> bool:
 """Check if a binary is available in PATH or bin directory"""
 # Check system PATH
 try:
 subprocess.run([tool_name, '--help'], 
 capture_output=True, 
 timeout=5)
 return True
 except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
 pass
 
 # Check local bin directory
 if os.name == 'nt': # Windows
 tool_path = self.bin_dir / f"{tool_name}.exe"
 else: # Unix-like
 tool_path = self.bin_dir / tool_name
 
 return tool_path.exists() and os.access(tool_path, os.X_OK)
 
 def _get_tool_path(self, tool_name: str) -> Optional[str]:
 """Get full path to tool binary"""
 if not self.tools_available.get(tool_name):
 return None
 
 # Try system PATH first
 try:
 result = subprocess.run(['which', tool_name] if os.name != 'nt' else ['where', tool_name],
 capture_output=True, text=True, timeout=5)
 if result.returncode == 0 and result.stdout.strip():
 return result.stdout.strip().split('\n')[0]
 except (subprocess.SubprocessError, subprocess.TimeoutExpired):
 pass
 
 # Try local bin directory
 if os.name == 'nt':
 tool_path = self.bin_dir / f"{tool_name}.exe"
 else:
 tool_path = self.bin_dir / tool_name
 
 if tool_path.exists():
 return str(tool_path)
 
 return tool_name # Fallback to system PATH
 
 async def run_comprehensive_scan(self) -> Dict[str, Any]:
 """Run comprehensive security scan using available tools"""
 logger.info("advanced_scan.starting", domain=self.domain, tools=list(self.tools_available.keys()))
 
 results = {
 'subdomains': [],
 'ports': [],
 'directories': [],
 'vulnerabilities': [],
 'web_technologies': [],
 'ssl_issues': [],
 'dns_records': []
 }
 
 # Phase 1: Subdomain enumeration (parallel)
 subdomain_tasks = []
 if self.tools_available.get('subfinder'):
 subdomain_tasks.append(self._run_subfinder())
 if self.tools_available.get('amass'):
 subdomain_tasks.append(self._run_amass())
 
 if subdomain_tasks:
 subdomain_results = await asyncio.gather(*subdomain_tasks, return_exceptions=True)
 for result in subdomain_results:
 if isinstance(result, list):
 results['subdomains'].extend(result)
 
 # Deduplicate subdomains
 results['subdomains'] = list(set(results['subdomains']))
 
 # Phase 2: Port scanning (if subdomains found)
 targets_for_port_scan = [self.domain] + results['subdomains'][:10] # Limit to top 10
 if self.tools_available.get('nmap'):
 port_results = await self._run_nmap_scan(targets_for_port_scan)
 results['ports'] = port_results
 elif self.tools_available.get('masscan'):
 port_results = await self._run_masscan(targets_for_port_scan)
 results['ports'] = port_results
 
 # Phase 3: Directory/file enumeration (parallel)
 web_targets = [f"http://{self.domain}", f"https://{self.domain}"]
 directory_tasks = []
 
 if self.tools_available.get('gobuster'):
 directory_tasks.append(self._run_gobuster(web_targets))
 if self.tools_available.get('ffuf'):
 directory_tasks.append(self._run_ffuf(web_targets))
 if self.tools_available.get('dirb'):
 directory_tasks.append(self._run_dirb(web_targets))
 
 if directory_tasks:
 dir_results = await asyncio.gather(*directory_tasks, return_exceptions=True)
 for result in dir_results:
 if isinstance(result, list):
 results['directories'].extend(result)
 
 # Phase 4: Vulnerability scanning
 vuln_tasks = []
 if self.tools_available.get('nikto'):
 vuln_tasks.append(self._run_nikto(web_targets))
 if self.tools_available.get('nuclei'):
 vuln_tasks.append(self._run_nuclei_advanced(web_targets + results['directories'][:50]))
 if self.tools_available.get('wpscan') and self._detect_wordpress():
 vuln_tasks.append(self._run_wpscan())
 
 if vuln_tasks:
 vuln_results = await asyncio.gather(*vuln_tasks, return_exceptions=True)
 for result in vuln_results:
 if isinstance(result, list):
 results['vulnerabilities'].extend(result)
 
 logger.info("advanced_scan.completed", 
 subdomains=len(results['subdomains']),
 ports=len(results['ports']),
 directories=len(results['directories']),
 vulnerabilities=len(results['vulnerabilities']))
 
 return results
 
 async def _run_subfinder(self) -> List[str]:
 """Run subfinder for subdomain enumeration"""
 tool_path = self._get_tool_path('subfinder')
 if not tool_path:
 return []
 
 cmd = [tool_path, '-d', self.domain, '-silent', '-o', '-']
 
 try:
 process = await asyncio.create_subprocess_exec(
 *cmd,
 stdout=asyncio.subprocess.PIPE,
 stderr=asyncio.subprocess.DEVNULL
 )
 stdout, _ = await asyncio.wait_for(process.communicate(), timeout=120)
 
 subdomains = []
 for line in stdout.decode('utf-8', errors='ignore').splitlines():
 line = line.strip()
 if line and '.' in line:
 subdomains.append(line)
 
 logger.info("subfinder.completed", count=len(subdomains))
 return subdomains
 
 except Exception as e:
 logger.error("subfinder.failed", error=str(e))
 return []
 
 async def _run_amass(self) -> List[str]:
 """Run amass for subdomain enumeration"""
 tool_path = self._get_tool_path('amass')
 if not tool_path:
 return []
 
 cmd = [tool_path, 'enum', '-d', self.domain, '-silent']
 
 try:
 process = await asyncio.create_subprocess_exec(
 *cmd,
 stdout=asyncio.subprocess.PIPE,
 stderr=asyncio.subprocess.DEVNULL
 )
 stdout, _ = await asyncio.wait_for(process.communicate(), timeout=300)
 
 subdomains = []
 for line in stdout.decode('utf-8', errors='ignore').splitlines():
 line = line.strip()
 if line and '.' in line:
 subdomains.append(line)
 
 logger.info("amass.completed", count=len(subdomains))
 return subdomains
 
 except Exception as e:
 logger.error("amass.failed", error=str(e))
 return []
 
 async def _run_nmap_scan(self, targets: List[str]) -> List[Dict[str, Any]]:
 """Run nmap port scan"""
 tool_path = self._get_tool_path('nmap')
 if not tool_path:
 return []
 
 # Limit targets and use efficient scanning
 limited_targets = targets[:5]
 target_str = ' '.join(limited_targets)
 
 cmd = [tool_path, '-sS', '-T4', '--top-ports', '1000', 
 '-oX', '-', '--open'] + limited_targets
 
 try:
 process = await asyncio.create_subprocess_exec(
 *cmd,
 stdout=asyncio.subprocess.PIPE,
 stderr=asyncio.subprocess.DEVNULL
 )
 stdout, _ = await asyncio.wait_for(process.communicate(), timeout=180)
 
 ports = self._parse_nmap_xml(stdout.decode('utf-8', errors='ignore'))
 logger.info("nmap.completed", targets=len(limited_targets), ports=len(ports))
 return ports
 
 except Exception as e:
 logger.error("nmap.failed", error=str(e))
 return []
 
 def _parse_nmap_xml(self, xml_output: str) -> List[Dict[str, Any]]:
 """Parse nmap XML output"""
 ports = []
 try:
 import xml.etree.ElementTree as ET
 root = ET.fromstring(xml_output)
 
 for host in root.findall('.//host'):
 address = host.find('.//address[@addrtype="ipv4"]')
 if address is None:
 continue
 
 ip = address.get('addr')
 hostname_elem = host.find('.//hostname')
 hostname = hostname_elem.get('name') if hostname_elem is not None else ip
 
 for port in host.findall('.//port'):
 port_id = port.get('portid')
 protocol = port.get('protocol')
 state = port.find('state').get('state')
 service = port.find('service')
 
 if state == 'open':
 port_info = {
 'host': hostname,
 'ip': ip,
 'port': int(port_id),
 'protocol': protocol,
 'state': state,
 'service': service.get('name') if service is not None else 'unknown'
 }
 ports.append(port_info)
 
 except Exception as e:
 logger.debug("nmap_parse.failed", error=str(e))
 
 return ports
 
 async def _run_masscan(self, targets: List[str]) -> List[Dict[str, Any]]:
 """Run masscan for fast port scanning"""
 tool_path = self._get_tool_path('masscan')
 if not tool_path or not targets:
 return []
 
 # Create target list file
 with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
 for target in targets[:5]: # Limit targets
 f.write(f"{target}\n")
 target_file = f.name
 
 try:
 cmd = [tool_path, '-iL', target_file, '--top-ports', '100', 
 '--rate', '1000', '-oJ', '-']
 
 process = await asyncio.create_subprocess_exec(
 *cmd,
 stdout=asyncio.subprocess.PIPE,
 stderr=asyncio.subprocess.DEVNULL
 )
 stdout, _ = await asyncio.wait_for(process.communicate(), timeout=60)
 
 ports = []
 for line in stdout.decode('utf-8', errors='ignore').splitlines():
 if line.strip():
 try:
 data = json.loads(line)
 if 'ip' in data and 'ports' in data:
 for port_data in data['ports']:
 ports.append({
 'host': data['ip'],
 'ip': data['ip'],
 'port': port_data['port'],
 'protocol': port_data.get('proto', 'tcp'),
 'state': 'open',
 'service': 'unknown'
 })
 except json.JSONDecodeError:
 continue
 
 logger.info("masscan.completed", targets=len(targets), ports=len(ports))
 return ports
 
 except Exception as e:
 logger.error("masscan.failed", error=str(e))
 return []
 finally:
 try:
 os.unlink(target_file)
 except OSError:
 pass
 
 async def _run_gobuster(self, targets: List[str]) -> List[str]:
 """Run gobuster for directory enumeration"""
 tool_path = self._get_tool_path('gobuster')
 if not tool_path:
 return []
 
 # Create or use wordlist
 wordlist_path = self._get_wordlist()
 if not wordlist_path:
 return []
 
 directories = []
 for target in targets[:3]: # Limit targets
 try:
 cmd = [tool_path, 'dir', '-u', target, '-w', wordlist_path, 
 '-t', '20', '--no-error', '-q']
 
 process = await asyncio.create_subprocess_exec(
 *cmd,
 stdout=asyncio.subprocess.PIPE,
 stderr=asyncio.subprocess.DEVNULL
 )
 stdout, _ = await asyncio.wait_for(process.communicate(), timeout=120)
 
 for line in stdout.decode('utf-8', errors='ignore').splitlines():
 if line.startswith(target):
 directories.append(line.split()[0])
 
 except Exception as e:
 logger.debug("gobuster.target_failed", target=target, error=str(e))
 
 logger.info("gobuster.completed", targets=len(targets), directories=len(directories))
 return directories
 
 async def _run_ffuf(self, targets: List[str]) -> List[str]:
 """Run ffuf for fuzzing"""
 tool_path = self._get_tool_path('ffuf')
 if not tool_path:
 return []
 
 wordlist_path = self._get_wordlist()
 if not wordlist_path:
 return []
 
 directories = []
 for target in targets[:3]:
 try:
 url = f"{target}/FUZZ"
 cmd = [tool_path, '-u', url, '-w', wordlist_path, 
 '-t', '20', '-s', '-o', '-', '-of', 'json']
 
 process = await asyncio.create_subprocess_exec(
 *cmd,
 stdout=asyncio.subprocess.PIPE,
 stderr=asyncio.subprocess.DEVNULL
 )
 stdout, _ = await asyncio.wait_for(process.communicate(), timeout=120)
 
 try:
 data = json.loads(stdout.decode('utf-8', errors='ignore'))
 for result in data.get('results', []):
 directories.append(result['url'])
 except json.JSONDecodeError:
 pass
 
 except Exception as e:
 logger.debug("ffuf.target_failed", target=target, error=str(e))
 
 logger.info("ffuf.completed", targets=len(targets), directories=len(directories))
 return directories
 
 async def _run_dirb(self, targets: List[str]) -> List[str]:
 """Run dirb for directory enumeration"""
 tool_path = self._get_tool_path('dirb')
 if not tool_path:
 return []
 
 directories = []
 for target in targets[:2]: # Limit targets as dirb is slower
 try:
 cmd = [tool_path, target, '-S', '-w']
 
 process = await asyncio.create_subprocess_exec(
 *cmd,
 stdout=asyncio.subprocess.PIPE,
 stderr=asyncio.subprocess.DEVNULL
 )
 stdout, _ = await asyncio.wait_for(process.communicate(), timeout=180)
 
 for line in stdout.decode('utf-8', errors='ignore').splitlines():
 if '==>' in line and 'DIRECTORY:' in line:
 dir_url = line.split('DIRECTORY:')[1].strip()
 directories.append(dir_url)
 elif line.startswith('+ '):
 file_url = line.split()[1]
 directories.append(file_url)
 
 except Exception as e:
 logger.debug("dirb.target_failed", target=target, error=str(e))
 
 logger.info("dirb.completed", targets=len(targets), directories=len(directories))
 return directories
 
 async def _run_nikto(self, targets: List[str]) -> List[Dict[str, Any]]:
 """Run nikto web vulnerability scanner"""
 tool_path = self._get_tool_path('nikto')
 if not tool_path:
 return []
 
 vulnerabilities = []
 for target in targets[:3]:
 try:
 cmd = [tool_path, '-h', target, '-Format', 'json', '-output', '-']
 
 process = await asyncio.create_subprocess_exec(
 *cmd,
 stdout=asyncio.subprocess.PIPE,
 stderr=asyncio.subprocess.DEVNULL
 )
 stdout, _ = await asyncio.wait_for(process.communicate(), timeout=300)
 
 try:
 data = json.loads(stdout.decode('utf-8', errors='ignore'))
 for vuln in data.get('vulnerabilities', []):
 vulnerabilities.append({
 'tool': 'nikto',
 'target': target,
 'severity': 'medium', # Nikto doesn't provide severity
 'title': vuln.get('msg', ''),
 'description': vuln.get('msg', ''),
 'uri': vuln.get('uri', ''),
 'method': vuln.get('method', 'GET')
 })
 except json.JSONDecodeError:
 # Nikto sometimes outputs non-JSON, parse text format
 for line in stdout.decode('utf-8', errors='ignore').splitlines():
 if '+ ' in line and target in line:
 vulnerabilities.append({
 'tool': 'nikto',
 'target': target,
 'severity': 'medium',
 'title': line.strip(),
 'description': line.strip()
 })
 
 except Exception as e:
 logger.debug("nikto.target_failed", target=target, error=str(e))
 
 logger.info("nikto.completed", targets=len(targets), vulns=len(vulnerabilities))
 return vulnerabilities
 
 async def _run_nuclei_advanced(self, targets: List[str]) -> List[Dict[str, Any]]:
 """Run nuclei with advanced templates"""
 tool_path = self._get_tool_path('nuclei')
 if not tool_path:
 return []
 
 # Create target file
 with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
 for target in targets[:100]: # Limit to avoid overwhelming
 f.write(f"{target}\n")
 target_file = f.name
 
 try:
 cmd = [tool_path, '-l', target_file, '-json', '-silent',
 '-c', '50', '-rl', '100', '-timeout', '5',
 '-severity', 'critical,high,medium']
 
 process = await asyncio.create_subprocess_exec(
 *cmd,
 stdout=asyncio.subprocess.PIPE,
 stderr=asyncio.subprocess.DEVNULL
 )
 stdout, _ = await asyncio.wait_for(process.communicate(), timeout=600)
 
 vulnerabilities = []
 for line in stdout.decode('utf-8', errors='ignore').splitlines():
 if line.strip():
 try:
 data = json.loads(line)
 vulnerabilities.append({
 'tool': 'nuclei',
 'target': data.get('matched-at', data.get('host', '')),
 'severity': data.get('info', {}).get('severity', 'unknown'),
 'title': data.get('info', {}).get('name', ''),
 'description': data.get('info', {}).get('description', ''),
 'template_id': data.get('template-id', ''),
 'tags': data.get('info', {}).get('tags', [])
 })
 except json.JSONDecodeError:
 continue
 
 logger.info("nuclei_advanced.completed", targets=len(targets), vulns=len(vulnerabilities))
 return vulnerabilities
 
 except Exception as e:
 logger.error("nuclei_advanced.failed", error=str(e))
 return []
 finally:
 try:
 os.unlink(target_file)
 except OSError:
 pass
 
 def _detect_wordpress(self) -> bool:
 """Simple WordPress detection"""
 try:
 import requests
 resp = # TODO: Replace with aiohttp
 # requests.get(f"{self.target_url}/wp-admin/", timeout=10, verify=False)
 return 'wordpress' in resp.text.lower() or resp.status_code == 200
 except Exception:
 return False
 
 async def _run_wpscan(self) -> List[Dict[str, Any]]:
 """Run WPScan for WordPress vulnerabilities"""
 tool_path = self._get_tool_path('wpscan')
 if not tool_path:
 return []
 
 try:
 cmd = [tool_path, '--url', self.target_url, '--format', 'json',
 '--random-user-agent', '--disable-tls-checks']
 
 process = await asyncio.create_subprocess_exec(
 *cmd,
 stdout=asyncio.subprocess.PIPE,
 stderr=asyncio.subprocess.DEVNULL
 )
 stdout, _ = await asyncio.wait_for(process.communicate(), timeout=300)
 
 vulnerabilities = []
 try:
 data = json.loads(stdout.decode('utf-8', errors='ignore'))
 
 # Parse various vulnerability types
 for vuln_type in ['vulnerabilities', 'plugins', 'themes']:
 items = data.get(vuln_type, {})
 for name, details in items.items():
 if isinstance(details, dict) and 'vulnerabilities' in details:
 for vuln in details['vulnerabilities']:
 vulnerabilities.append({
 'tool': 'wpscan',
 'target': self.target_url,
 'severity': 'medium',
 'title': vuln.get('title', ''),
 'description': f"{vuln_type.title()} vulnerability in {name}",
 'references': vuln.get('references', {})
 })
 
 except json.JSONDecodeError:
 pass
 
 logger.info("wpscan.completed", vulns=len(vulnerabilities))
 return vulnerabilities
 
 except Exception as e:
 logger.error("wpscan.failed", error=str(e))
 return []
 
 def _get_wordlist(self) -> Optional[str]:
 """Get or create a wordlist for directory enumeration"""
 # Check for common wordlist locations
 common_wordlists = [
 '/usr/share/wordlists/dirb/common.txt',
 '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
 '/usr/share/seclists/Discovery/Web-Content/common.txt',
 str(self.bin_dir / 'wordlist.txt')
 ]
 
 for wordlist in common_wordlists:
 if os.path.exists(wordlist):
 return wordlist
 
 # Create a basic wordlist if none found
 basic_wordlist = self.output_dir / 'basic_wordlist.txt'
 if not basic_wordlist.exists():
 basic_paths = [
 'admin', 'administrator', 'login', 'dashboard', 'panel', 'control',
 'wp-admin', 'wp-login.php', 'wp-content', 'wp-includes',
 'api', 'v1', 'v2', 'docs', 'documentation', 'swagger',
 'config', 'configuration', 'settings', 'setup', 'install',
 'backup', 'backups', 'db', 'database', 'sql', 'dump',
 'test', 'dev', 'development', 'staging', 'prod', 'production',
 'uploads', 'files', 'images', 'assets', 'static', 'resources',
 'logs', 'log', 'error', 'debug', 'tmp', 'temp', 'cache'
 ]
 
 with open(basic_wordlist, 'w') as f:
 for path in basic_paths:
 f.write(f"{path}\n")
 
 return str(basic_wordlist)