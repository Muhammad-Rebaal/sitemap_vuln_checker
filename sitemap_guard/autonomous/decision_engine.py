from typing import List
from typing import Optional
from typing import Any
"""
Autonomous decision engine for intelligent scanning and vulnerability assessment
"""
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import structlog
import json
from pathlib import Path
import time

logger = structlog.get_logger()

class ThreatLevel(Enum):
 CRITICAL = "critical"
 HIGH = "high"
 MEDIUM = "medium"
 LOW = "low"
 INFO = "info"
 CLEAN = "clean"

class ScanStrategy(Enum):
 AGGRESSIVE = "aggressive"
 BALANCED = "balanced" 
 STEALTH = "stealth"
 PASSIVE = "passive"

@dataclass
class ScanDecision:
 """Represents an autonomous scanning decision"""
 action: str
 strategy: ScanStrategy
 priority: int
 reasoning: str
 parameters: Dict[str, Any]
 estimated_time: float
 risk_level: str

class AutonomousDecisionEngine:
 """
 Intelligent decision engine that analyzes targets and makes
 autonomous decisions about scanning approach and priorities
 """
 
 def __init__(self):
 self.scan_history: Dict[str, List[Dict]] = {}
 self.threat_intelligence: Dict[str, Dict] = {}
 self.performance_metrics: Dict[str, float] = {}
 self._load_threat_intelligence()
 
 def _load_threat_intelligence(self):
 """Load threat intelligence data"""
 # Basic threat patterns - can be enhanced with real threat feeds
 self.threat_patterns = {
 'high_risk_paths': [
 '/admin', '/wp-admin', '/administrator', '/panel', '/dashboard',
 '/phpmyadmin', '/phpinfo.php', '/.env', '/config.php',
 '/backup', '/database', '/db_backup', '/sql'
 ],
 'vulnerable_technologies': [
 'wordpress', 'joomla', 'drupal', 'magento', 'prestashop',
 'phpbb', 'mediawiki', 'concrete5'
 ],
 'suspicious_responses': [
 'server: apache/2.2', 'server: nginx/1.0', 'server: iis/6.0',
 'x-powered-by: php/5.', 'server: microsoft-iis/7.5'
 ]
 }
 
 async def analyze_target(self, target_url: str, initial_response: Optional[Dict] = None) -> Dict[str, Any]:
 """
 Analyze target and determine optimal scanning approach
 """
 logger.info("autonomous.analyze_target", target=target_url)
 
 analysis = {
 'target_url': target_url,
 'threat_level': ThreatLevel.MEDIUM,
 'technologies': [],
 'risk_indicators': [],
 'recommended_strategy': ScanStrategy.BALANCED,
 'priority_areas': [],
 'estimated_scan_time': 300.0, # 5 minutes default
 'confidence': 0.7
 }
 
 # Analyze initial response if available
 if initial_response:
 analysis.update(await self._analyze_initial_response(initial_response))
 
 # Technology detection and risk assessment
 tech_analysis = await self._detect_technologies(target_url)
 analysis['technologies'] = tech_analysis['technologies']
 analysis['risk_indicators'].extend(tech_analysis['risk_indicators'])
 
 # Determine threat level based on indicators
 analysis['threat_level'] = self._calculate_threat_level(analysis['risk_indicators'])
 
 # Choose optimal strategy
 analysis['recommended_strategy'] = self._choose_scan_strategy(analysis)
 
 # Identify priority scanning areas
 analysis['priority_areas'] = self._identify_priority_areas(analysis)
 
 # Estimate scan time based on complexity
 analysis['estimated_scan_time'] = self._estimate_scan_time(analysis)
 
 logger.info("autonomous.analysis_complete", 
 threat_level=analysis['threat_level'].value,
 strategy=analysis['recommended_strategy'].value,
 priorities=len(analysis['priority_areas']))
 
 return analysis
 
 async def _analyze_initial_response(self, response: Dict) -> Dict[str, Any]:
 """Analyze initial HTTP response for intelligence gathering"""
 analysis = {
 'server_info': {},
 'security_headers': [],
 'response_indicators': []
 }
 
 headers = response.get('headers', {})
 status_code = response.get('status_code', 0)
 
 # Server information
 server_header = headers.get('server', '').lower()
 if server_header:
 analysis['server_info']['server'] = server_header
 # Check for outdated servers
 for suspicious in self.threat_patterns['suspicious_responses']:
 if suspicious in server_header:
 analysis['response_indicators'].append({
 'type': 'outdated_server',
 'value': server_header,
 'risk': 'medium'
 })
 
 # Security headers analysis
 security_headers = [
 'strict-transport-security', 'x-content-type-options',
 'x-frame-options', 'x-xss-protection', 'content-security-policy'
 ]
 
 missing_headers = []
 for header in security_headers:
 if header not in headers:
 missing_headers.append(header)
 
 if missing_headers:
 analysis['security_headers'] = missing_headers
 analysis['response_indicators'].append({
 'type': 'missing_security_headers',
 'value': missing_headers,
 'risk': 'medium' if len(missing_headers) > 2 else 'low'
 })
 
 # Response code analysis
 if status_code in [403, 401]:
 analysis['response_indicators'].append({
 'type': 'authentication_required',
 'value': status_code,
 'risk': 'high'
 })
 elif status_code >= 500:
 analysis['response_indicators'].append({
 'type': 'server_error',
 'value': status_code,
 'risk': 'medium'
 })
 
 return analysis
 
 async def _detect_technologies(self, target_url: str) -> Dict[str, Any]:
 """Detect web technologies and assess associated risks"""
 tech_analysis = {
 'technologies': [],
 'risk_indicators': []
 }
 
 try:
 # Simple technology detection - can be enhanced
 import aiohttp
 async with aiohttp.ClientSession() as session:
 async with session.get(target_url, timeout=10) as response:
 headers = response.headers
 content = await response.text()
 
 # Header-based detection
 x_powered_by = headers.get('x-powered-by', '').lower()
 if x_powered_by:
 if 'php' in x_powered_by:
 tech_analysis['technologies'].append('PHP')
 if 'asp.net' in x_powered_by:
 tech_analysis['technologies'].append('ASP.NET')
 
 # Content-based detection
 content_lower = content.lower()
 
 # WordPress detection
 if 'wp-content' in content_lower or 'wp-includes' in content_lower:
 tech_analysis['technologies'].append('WordPress')
 tech_analysis['risk_indicators'].append({
 'type': 'cms_detected',
 'technology': 'WordPress',
 'risk': 'medium'
 })
 
 # Other CMS detection
 cms_indicators = {
 'joomla': ['joomla', 'com_content', 'index.php?option=com'],
 'drupal': ['drupal', 'sites/all/', 'misc/drupal.js'],
 'magento': ['magento', 'skin/frontend', 'mage/cookies']
 }
 
 for cms, indicators in cms_indicators.items():
 if any(indicator in content_lower for indicator in indicators):
 tech_analysis['technologies'].append(cms.title())
 tech_analysis['risk_indicators'].append({
 'type': 'cms_detected',
 'technology': cms.title(),
 'risk': 'medium'
 })
 
 # Framework detection
 if 'django' in content_lower or 'csrfmiddlewaretoken' in content_lower:
 tech_analysis['technologies'].append('Django')
 
 if 'laravel' in content_lower or 'laravel_session' in str(headers):
 tech_analysis['technologies'].append('Laravel')
 
 except Exception as e:
 logger.debug("tech_detection.failed", error=str(e))
 
 return tech_analysis
 
 def _calculate_threat_level(self, risk_indicators: List[Dict]) -> ThreatLevel:
 """Calculate overall threat level based on risk indicators"""
 if not risk_indicators:
 return ThreatLevel.LOW
 
 risk_scores = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
 total_score = sum(risk_scores.get(indicator.get('risk', 'low'), 1) 
 for indicator in risk_indicators)
 
 if total_score >= 20:
 return ThreatLevel.CRITICAL
 elif total_score >= 15:
 return ThreatLevel.HIGH
 elif total_score >= 8:
 return ThreatLevel.MEDIUM
 else:
 return ThreatLevel.LOW
 
 def _choose_scan_strategy(self, analysis: Dict[str, Any]) -> ScanStrategy:
 """Choose optimal scanning strategy based on analysis"""
 threat_level = analysis['threat_level']
 technologies = analysis.get('technologies', [])
 
 # High-value targets get aggressive scanning
 if threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
 return ScanStrategy.AGGRESSIVE
 
 # CMS targets get balanced approach
 if any('wordpress' in tech.lower() or 'joomla' in tech.lower() 
 for tech in technologies):
 return ScanStrategy.BALANCED
 
 # Default to stealth for unknown targets
 return ScanStrategy.STEALTH
 
 def _identify_priority_areas(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
 """Identify priority areas for focused scanning"""
 priorities = []
 
 technologies = analysis.get('technologies', [])
 threat_level = analysis['threat_level']
 
 # WordPress priorities
 if any('wordpress' in tech.lower() for tech in technologies):
 priorities.extend([
 {'area': 'wp_admin', 'priority': 9, 'paths': ['/wp-admin/', '/wp-login.php']},
 {'area': 'wp_content', 'priority': 7, 'paths': ['/wp-content/', '/wp-includes/']},
 {'area': 'wp_config', 'priority': 10, 'paths': ['/wp-config.php', '/wp-config.php.bak']}
 ])
 
 # Admin panels (always high priority)
 priorities.append({
 'area': 'admin_panels',
 'priority': 8,
 'paths': ['/admin/', '/administrator/', '/panel/', '/dashboard/']
 })
 
 # Configuration files
 priorities.append({
 'area': 'config_files',
 'priority': 9,
 'paths': ['/.env', '/config.php', '/configuration.php', '/config.json']
 })
 
 # Backup files
 priorities.append({
 'area': 'backups',
 'priority': 7,
 'paths': ['/backup/', '/backups/', '/db_backup/', '/.git/']
 })
 
 # API endpoints
 priorities.append({
 'area': 'api_endpoints',
 'priority': 6,
 'paths': ['/api/', '/v1/', '/v2/', '/rest/', '/graphql']
 })
 
 # Sort by priority
 priorities.sort(key=lambda x: x['priority'], reverse=True)
 
 return priorities
 
 def _estimate_scan_time(self, analysis: Dict[str, Any]) -> float:
 """Estimate scan time based on analysis complexity"""
 base_time = 180.0 # 3 minutes base
 
 # Adjust based on threat level
 threat_multipliers = {
 ThreatLevel.CRITICAL: 2.5,
 ThreatLevel.HIGH: 2.0,
 ThreatLevel.MEDIUM: 1.5,
 ThreatLevel.LOW: 1.0
 }
 
 multiplier = threat_multipliers.get(analysis['threat_level'], 1.0)
 
 # Adjust based on technologies
 tech_count = len(analysis.get('technologies', []))
 tech_multiplier = 1.0 + (tech_count * 0.2)
 
 # Adjust based on priority areas
 priority_count = len(analysis.get('priority_areas', []))
 priority_multiplier = 1.0 + (priority_count * 0.1)
 
 estimated_time = base_time * multiplier * tech_multiplier * priority_multiplier
 
 return min(estimated_time, 1800.0) # Cap at 30 minutes
 
 async def make_scan_decisions(self, analysis: Dict[str, Any]) -> List[ScanDecision]:
 """Make autonomous scanning decisions based on analysis"""
 decisions = []
 
 strategy = analysis['recommended_strategy']
 priority_areas = analysis.get('priority_areas', [])
 
 # Decision 1: Initial reconnaissance
 decisions.append(ScanDecision(
 action="initial_recon",
 strategy=strategy,
 priority=10,
 reasoning="Gather basic information about target",
 parameters={'depth': 2 if strategy == ScanStrategy.AGGRESSIVE else 1},
 estimated_time=60.0,
 risk_level="low"
 ))
 
 # Decision 2: Priority area scanning
 for area in priority_areas[:3]: # Top 3 priorities
 decisions.append(ScanDecision(
 action="priority_scan",
 strategy=strategy,
 priority=area['priority'],
 reasoning=f"High-priority area: {area['area']}",
 parameters={
 'area': area['area'],
 'paths': area['paths'],
 'depth': 3 if strategy == ScanStrategy.AGGRESSIVE else 2
 },
 estimated_time=120.0,
 risk_level="medium"
 ))
 
 # Decision 3: Vulnerability scanning
 if analysis['threat_level'] in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
 decisions.append(ScanDecision(
 action="vulnerability_scan",
 strategy=strategy,
 priority=8,
 reasoning="High threat level detected, comprehensive vulnerability scan needed",
 parameters={
 'templates': 'all' if strategy == ScanStrategy.AGGRESSIVE else 'high-medium',
 'rate_limit': 100 if strategy == ScanStrategy.AGGRESSIVE else 50
 },
 estimated_time=300.0,
 risk_level="high"
 ))
 
 # Decision 4: Technology-specific scans
 technologies = analysis.get('technologies', [])
 if technologies:
 decisions.append(ScanDecision(
 action="tech_specific_scan",
 strategy=strategy,
 priority=7,
 reasoning=f"Technology-specific scanning for: {', '.join(technologies)}",
 parameters={
 'technologies': technologies,
 'cms_scan': any('wordpress' in tech.lower() for tech in technologies)
 },
 estimated_time=180.0,
 risk_level="medium"
 ))
 
 # Sort decisions by priority
 decisions.sort(key=lambda x: x.priority, reverse=True)
 
 logger.info("autonomous.decisions_made", 
 count=len(decisions),
 total_estimated_time=sum(d.estimated_time for d in decisions))
 
 return decisions
 
 async def adaptive_throttling(self, target_responses: List[Dict]) -> Dict[str, Any]:
 """Implement adaptive request throttling based on target responses"""
 
 # Analyze recent responses
 error_rate = sum(1 for r in target_responses[-50:] 
 if r.get('status_code', 0) >= 400) / max(len(target_responses[-50:]), 1)
 
 avg_response_time = sum(r.get('response_time', 0) for r in target_responses[-20:]) / max(len(target_responses[-20:]), 1)
 
 # Determine throttling parameters
 if error_rate > 0.3: # High error rate
 throttling = {
 'delay': 2.0,
 'concurrent_requests': 5,
 'reason': 'high_error_rate',
 'adaptive': True
 }
 elif avg_response_time > 5000: # Slow responses (5s+)
 throttling = {
 'delay': 1.0,
 'concurrent_requests': 10,
 'reason': 'slow_responses',
 'adaptive': True
 }
 else: # Normal operation
 throttling = {
 'delay': 0.1,
 'concurrent_requests': 20,
 'reason': 'normal',
 'adaptive': False
 }
 
 logger.debug("autonomous.throttling_adjusted", 
 error_rate=error_rate,
 avg_response_time=avg_response_time,
 **throttling)
 
 return throttling
 
 def update_threat_intelligence(self, findings: List[Dict]):
 """Update threat intelligence based on new findings"""
 for finding in findings:
 url = finding.get('url', '')
 severity = finding.get('severity', 'low')
 
 # Update threat patterns
 if severity in ['critical', 'high']:
 domain = url.split('/')[2] if '://' in url else url
 if domain not in self.threat_intelligence:
 self.threat_intelligence[domain] = {
 'first_seen': time.time(),
 'threat_score': 0,
 'vulnerabilities': []
 }
 
 self.threat_intelligence[domain]['threat_score'] += 1
 self.threat_intelligence[domain]['vulnerabilities'].append({
 'type': finding.get('name', 'unknown'),
 'severity': severity,
 'timestamp': time.time()
 })
 
 logger.debug("autonomous.threat_intel_updated", 
 domains=len(self.threat_intelligence),
 new_findings=len(findings))

# Global autonomous engine instance
autonomous_engine = AutonomousDecisionEngine()