"""
OpenClaw Shield - Core Security Implementation

Provides three layers of defense for OpenClaw agentic AI:
1. Input validation (Azure Prompt Shield)
2. Tool execution validation (command, file, network shields)
3. Output sanitization
"""

import re
import os
import json
import logging
import urllib.parse
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

# Azure SDK imports
from azure.ai.contentsafety import ContentSafetyClient
from azure.ai.contentsafety.models import AnalyzeTextOptions, TextCategory
from azure.core.credentials import AzureKeyCredential
from azure.monitor.opentelemetry import configure_azure_monitor

logger = logging.getLogger(__name__)


class SecurityException(Exception):
    """Raised when a security policy is violated"""
    pass


class AzureShieldClient:
    """
    Azure AI Content Safety client wrapper
    Handles prompt shield and PII detection
    """
    def __init__(self, endpoint: str, key: str):
        self.client = ContentSafetyClient(
            endpoint=endpoint,
            credential=AzureKeyCredential(key)
        )
    
    async def detect_jailbreak(self, text: str) -> Dict[str, Any]:
        """
        Detect jailbreak and indirect prompt injection attacks
        """
        try:
            response = self.client.analyze_text(
                AnalyzeTextOptions(
                    text=text,
                    categories=[],  # Prompt Shield doesn't use categories
                    halt_on_blocklist_hit=False,
                    output_type="FourSeverityLevels"
                )
            )
            
            # Check for attacks in additional fields
            jailbreak_detected = getattr(response, 'jailbreak_analysis', None)
            indirect_attack = getattr(response, 'indirect_attack_analysis', None)
            
            return {
                'jailbreak_detected': jailbreak_detected is not None and jailbreak_detected.detected,
                'indirect_attack_detected': indirect_attack is not None and indirect_attack.detected,
                'attack_type': self._get_attack_type(jailbreak_detected, indirect_attack),
                'details': {
                    'jailbreak': jailbreak_detected.__dict__ if jailbreak_detected else None,
                    'indirect_attack': indirect_attack.__dict__ if indirect_attack else None
                }
            }
        except Exception as e:
            logger.error(f"Jailbreak detection failed: {e}")
            # Fail open or closed based on configuration
            return {'jailbreak_detected': False, 'error': str(e)}
    
    async def detect_pii(self, text: str, severity_threshold: int = 2) -> Dict[str, Any]:
        """
        Detect PII in text using Azure Content Safety
        Returns detected entities and severity
        """
        try:
            # Note: PII detection might require additional Azure Cognitive Services
            # This is a placeholder for the integration
            response = self.client.analyze_text(
                AnalyzeTextOptions(
                    text=text,
                    categories=[TextCategory.HATE, TextCategory.VIOLENCE],  # Placeholder
                    output_type="EightSeverityLevels"
                )
            )
            
            # In production, integrate with Azure PII detection service
            contains_pii = False
            entities = []
            severity_level = 0
            
            return {
                'contains_pii': contains_pii,
                'entities': entities,
                'severity_level': severity_level
            }
        except Exception as e:
            logger.error(f"PII detection failed: {e}")
            return {'contains_pii': False, 'error': str(e)}
    
    def _get_attack_type(self, jailbreak, indirect_attack) -> Optional[str]:
        """Determine the type of attack detected"""
        if jailbreak and jailbreak.detected:
            return 'jailbreak'
        if indirect_attack and indirect_attack.detected:
            return 'indirect_attack'
        return None


class BashCommandShield:
    """
    Validates bash_tool commands before execution
    Prevents command injection, privilege escalation, and data destruction
    """
    def __init__(self, azure_client: AzureShieldClient, config: Dict[str, Any]):
        self.azure = azure_client
        self.config = config
        
        # Dangerous command patterns
        self.blocked_patterns = [
            r'rm\s+-rf\s+/',          # Recursive delete from root
            r':(){ :|:& };:',         # Fork bomb
            r'mv\s+.*\s+/dev/null',   # Data destruction
            r'chmod\s+777',           # Security weakening
            r'curl.*\|\s*bash',       # Remote code execution
            r'wget.*\|\s*(sh|bash)',  # Remote code execution
            r'nc\s+-l',               # Reverse shell
            r'eval\s+\$\(',           # Command injection
            r'sudo\s+',               # Privilege escalation
            r'dd\s+if=',              # Low-level disk operations
            r'mkfs\.',                # Filesystem formatting
            r'\>\s*/dev/sd[a-z]',     # Direct disk write
        ]
        
        # Allowed commands (whitelist)
        self.allowed_commands = config.get('allowed_bash_commands', [
            'ls', 'cat', 'grep', 'find', 'echo', 'pwd', 'whoami',
            'git', 'npm', 'pip', 'python', 'python3', 'node',
            'mkdir', 'cd', 'cp', 'mv', 'touch', 'wc', 'head', 'tail',
            'sed', 'awk', 'sort', 'uniq', 'diff'
        ])
    
    async def validate(self, command: str, description: str = "") -> Dict[str, Any]:
        """
        Validate a bash command before execution
        
        Returns:
            dict: {'allowed': bool, 'reason': str, 'severity': str}
        """
        # 1. Azure Prompt Shield - detect injection in command
        shield_result = await self.azure.detect_jailbreak(command)
        
        if shield_result.get('jailbreak_detected') or shield_result.get('indirect_attack_detected'):
            await self._alert_security_team({
                'type': 'prompt_injection_in_command',
                'command': command,
                'attack_type': shield_result.get('attack_type'),
                'timestamp': datetime.utcnow().isoformat()
            })
            return {
                'allowed': False,
                'reason': 'Prompt injection detected in bash command',
                'severity': 'HIGH',
                'details': shield_result
            }
        
        # 2. Pattern matching for dangerous commands
        for pattern in self.blocked_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                await self._alert_security_team({
                    'type': 'dangerous_command_blocked',
                    'command': command,
                    'pattern': pattern,
                    'timestamp': datetime.utcnow().isoformat()
                })
                return {
                    'allowed': False,
                    'reason': f'Dangerous command pattern detected: {pattern}',
                    'severity': 'CRITICAL'
                }
        
        # 3. Whitelist validation
        first_command = command.strip().split()[0] if command.strip() else ''
        
        if first_command not in self.allowed_commands:
            logger.warning(f"Command not in allowlist: {first_command}")
            return {
                'allowed': False,
                'reason': f'Command not in allowlist: {first_command}',
                'severity': 'MEDIUM',
                'requires_approval': True  # Human in the loop option
            }
        
        # 4. Check for PII in command (e.g., API keys as arguments)
        pii_result = await self.azure.detect_pii(command)
        
        if pii_result.get('contains_pii'):
            return {
                'allowed': False,
                'reason': 'PII detected in command parameters',
                'severity': 'HIGH',
                'entities': pii_result.get('entities', [])
            }
        
        # 5. Log approved command
        await self._log_command_execution(command, description)
        
        return {'allowed': True, 'severity': 'LOW'}
    
    async def _alert_security_team(self, alert_data: Dict[str, Any]):
        """Send security alert"""
        logger.critical(f"SECURITY ALERT: {json.dumps(alert_data)}")
        # In production: integrate with Azure Sentinel, PagerDuty, etc.
    
    async def _log_command_execution(self, command: str, description: str):
        """Log command execution for audit trail"""
        logger.info(f"Command executed: {command} | Description: {description}")


class FileOperationShield:
    """
    Validates file operations (create_file, str_replace, view)
    Prevents path traversal, credential leakage, and unauthorized access
    """
    def __init__(self, azure_client: AzureShieldClient, config: Dict[str, Any]):
        self.azure = azure_client
        self.config = config
        
        # Safe paths within the container
        self.safe_paths = config.get('safe_file_paths', [
            '/home/claude/workspace',
            '/tmp/openclaw-sandbox'
        ])
        
        # Forbidden paths
        self.forbidden_paths = [
            '/etc', '/.ssh', '/.aws', '/.env', '/.config',
            '/root', '/home/claude/.bashrc', '/home/claude/.bash_history',
            '/proc', '/sys'
        ]
        
        # Credential patterns
        self.credential_patterns = [
            (r'aws_access_key_id\s*=', 'AWS credentials'),
            (r'AKIA[0-9A-Z]{16}', 'AWS access key'),
            (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API key'),
            (r'ghp_[a-zA-Z0-9]{36}', 'GitHub token'),
            (r'glpat-[a-zA-Z0-9\-]{20}', 'GitLab token'),
            (r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', 'Private key'),
            (r'Bearer [a-zA-Z0-9\-\._~\+\/]+=*', 'Bearer token'),
        ]
    
    def _is_safe_path(self, path: str) -> bool:
        """Check if path is within safe zones"""
        normalized = os.path.abspath(path)
        
        # Check forbidden paths
        for forbidden in self.forbidden_paths:
            if normalized.startswith(forbidden):
                return False
        
        # Check safe paths
        for safe in self.safe_paths:
            if normalized.startswith(safe):
                return True
        
        return False
    
    async def validate_file_write(self, path: str, content: str) -> Dict[str, Any]:
        """
        Validate file write operations (create_file, str_replace)
        """
        # 1. Path validation
        if not self._is_safe_path(path):
            return {
                'allowed': False,
                'reason': f'Path outside safe zone: {path}',
                'severity': 'HIGH'
            }
        
        # 2. Scan content for credentials
        for pattern, credential_type in self.credential_patterns:
            if re.search(pattern, content):
                logger.critical(f"Credential detected in file: {credential_type}")
                return {
                    'allowed': False,
                    'reason': f'Credential detected in file content: {credential_type}',
                    'severity': 'CRITICAL'
                }
        
        # 3. PII detection using Azure Content Safety
        # Sample first 10k chars for performance
        sample = content[:10000] if len(content) > 10000 else content
        pii_scan = await self.azure.detect_pii(sample)
        
        if pii_scan.get('contains_pii') and pii_scan.get('severity_level', 0) >= 4:
            logger.warning(f"PII detected in file write: {path}")
            # In production: integrate with Purview DLP
            return {
                'allowed': False,
                'reason': 'PII detected in file content',
                'severity': 'MEDIUM',
                'detected_entities': pii_scan.get('entities', []),
                'action_required': 'apply_sensitivity_label'
            }
        
        return {'allowed': True, 'severity': 'LOW'}
    
    async def validate_file_read(self, path: str) -> Dict[str, Any]:
        """
        Validate file read operations (view tool)
        """
        if not self._is_safe_path(path):
            return {
                'allowed': False,
                'reason': f'Path outside safe zone: {path}',
                'severity': 'HIGH'
            }
        
        # In production: check Purview sensitivity labels
        # For now, log the access
        logger.info(f"File read: {path}")
        
        return {'allowed': True, 'severity': 'LOW'}


class NetworkShield:
    """
    Validates network requests (web_fetch, external API calls)
    Prevents data exfiltration and indirect prompt injection
    """
    def __init__(self, azure_client: AzureShieldClient, config: Dict[str, Any]):
        self.azure = azure_client
        self.config = config
        
        # Approved domains
        self.allowlist = config.get('allowed_domains', [
            'github.com',
            'api.github.com',
            'docs.python.org',
            'pypi.org',
            'npmjs.com',
            'stackoverflow.com',
        ])
        
        # Blocked domains (data exfiltration risks)
        self.blocklist = [
            'pastebin.com',
            'transfer.sh',
            'file.io',
            'discord.com/api/webhooks',
            'ipinfo.io',
            'ipify.org',
        ]
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc
    
    async def validate_request(self, url: str) -> Dict[str, Any]:
        """
        Validate outbound network request
        """
        domain = self._extract_domain(url)
        
        # 1. Blocklist check
        if any(blocked in domain for blocked in self.blocklist):
            logger.warning(f"Blocked domain access: {domain}")
            return {
                'allowed': False,
                'reason': f'Blocked domain: {domain}',
                'severity': 'HIGH',
                'risk': 'data_exfiltration'
            }
        
        # 2. Allowlist check
        if not any(allowed in domain for allowed in self.allowlist):
            logger.warning(f"Domain not in allowlist: {domain}")
            return {
                'allowed': False,
                'reason': f'Domain not in allowlist: {domain}',
                'severity': 'MEDIUM',
                'requires_approval': True
            }
        
        # 3. Check URL for injection
        decoded_url = urllib.parse.unquote(url)
        shield_check = await self.azure.detect_jailbreak(decoded_url)
        
        if shield_check.get('jailbreak_detected') or shield_check.get('indirect_attack_detected'):
            return {
                'allowed': False,
                'reason': 'Injection detected in URL parameters',
                'severity': 'HIGH'
            }
        
        return {'allowed': True, 'severity': 'LOW'}
    
    async def sanitize_response(self, response_content: str) -> str:
        """
        Sanitize fetched content for indirect prompt injections
        Critical: Attackers can embed instructions in websites
        """
        injection_check = await self.azure.detect_jailbreak(response_content)
        
        if injection_check.get('indirect_attack_detected'):
            logger.critical("Indirect prompt injection detected in web response")
            await self._alert_security_team({
                'type': 'indirect_prompt_injection',
                'source': 'web_fetch',
                'attack_type': injection_check.get('attack_type'),
                'timestamp': datetime.utcnow().isoformat()
            })
            return "[CONTENT BLOCKED: Prompt injection detected in external response]"
        
        return response_content
    
    async def _alert_security_team(self, alert_data: Dict[str, Any]):
        """Send security alert"""
        logger.critical(f"SECURITY ALERT: {json.dumps(alert_data)}")


class SecureToolExecutor:
    """
    Main orchestrator for OpenClaw tool execution with security shields
    Intercepts every tool call and applies appropriate validation
    """
    def __init__(
        self,
        azure_content_safety_endpoint: str,
        azure_content_safety_key: str,
        config: Optional[Dict[str, Any]] = None
    ):
        self.config = config or {}
        
        # Initialize Azure client
        self.azure_client = AzureShieldClient(
            endpoint=azure_content_safety_endpoint,
            key=azure_content_safety_key
        )
        
        # Initialize shields
        self.bash_shield = BashCommandShield(self.azure_client, self.config)
        self.file_shield = FileOperationShield(self.azure_client, self.config)
        self.network_shield = NetworkShield(self.azure_client, self.config)
        
        # Shield mode: 'enforcing' or 'monitoring'
        self.mode = self.config.get('shield_mode', 'enforcing')
    
    async def execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Any:
        """
        Execute OpenClaw tool with security validation
        
        Args:
            tool_name: Name of the tool (bash_tool, create_file, etc.)
            parameters: Tool parameters
            
        Returns:
            Tool execution result
            
        Raises:
            SecurityException: If security policy is violated (in enforcing mode)
        """
        validation_result = None
        
        # Route to appropriate shield
        if tool_name == "bash_tool":
            validation_result = await self.bash_shield.validate(
                command=parameters.get('command', ''),
                description=parameters.get('description', '')
            )
        
        elif tool_name == "create_file":
            validation_result = await self.file_shield.validate_file_write(
                path=parameters.get('path', ''),
                content=parameters.get('file_text', '')
            )
        
        elif tool_name == "str_replace":
            validation_result = await self.file_shield.validate_file_write(
                path=parameters.get('path', ''),
                content=parameters.get('new_str', '')
            )
        
        elif tool_name == "view":
            validation_result = await self.file_shield.validate_file_read(
                path=parameters.get('path', '')
            )
        
        elif tool_name == "web_fetch":
            validation_result = await self.network_shield.validate_request(
                url=parameters.get('url', '')
            )
        
        else:
            # Unknown tool - block by default in enforcing mode
            validation_result = {
                'allowed': False,
                'reason': f'Unknown tool: {tool_name}',
                'severity': 'MEDIUM'
            }
        
        # Handle validation result
        if not validation_result.get('allowed'):
            await self._log_blocked_action(tool_name, parameters, validation_result)
            
            if self.mode == 'enforcing':
                raise SecurityException(
                    f"Tool execution blocked: {validation_result.get('reason')}"
                )
            else:
                logger.warning(
                    f"Tool execution would be blocked (monitoring mode): "
                    f"{validation_result.get('reason')}"
                )
        
        # Execute tool (placeholder - integrate with actual OpenClaw execution)
        result = await self._execute_openclaw_tool(tool_name, parameters)
        
        # Post-execution sanitization for web_fetch
        if tool_name == "web_fetch" and result:
            result = await self.network_shield.sanitize_response(str(result))
        
        return result
    
    async def _execute_openclaw_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Any:
        """
        Execute the actual OpenClaw tool
        This should integrate with your OpenClaw deployment
        """
        # Placeholder - implement actual tool execution
        logger.info(f"Executing tool: {tool_name} with parameters: {parameters}")
        return {"status": "simulated_execution"}
    
    async def _log_blocked_action(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        validation_result: Dict[str, Any]
    ):
        """Log blocked action for audit and monitoring"""
        log_entry = {
            'event': 'tool_execution_blocked',
            'tool_name': tool_name,
            'parameters': parameters,
            'reason': validation_result.get('reason'),
            'severity': validation_result.get('severity'),
            'timestamp': datetime.utcnow().isoformat()
        }
        logger.warning(f"BLOCKED: {json.dumps(log_entry)}")
        
        # In production: send to Azure Monitor
