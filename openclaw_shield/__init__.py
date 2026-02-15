"""
OpenClaw Shield - AI Security Posture Management for OpenClaw

A comprehensive security framework that integrates Azure AI Content Safety,
Prompt Shields, and Microsoft Purview to protect OpenClaw (Claude Computer Use)
deployments from prompt injections, data leakage, and rogue agent behavior.
"""

__version__ = "0.1.0"
__author__ = "Bit Pulse AI AS"
__license__ = "MIT"

from openclaw_shield.shields import (
    SecureToolExecutor,
    BashCommandShield,
    FileOperationShield,
    NetworkShield,
    AzureShieldClient,
    SecurityException,
)

__all__ = [
    "SecureToolExecutor",
    "BashCommandShield",
    "FileOperationShield",
    "NetworkShield",
    "AzureShieldClient",
    "SecurityException",
]
