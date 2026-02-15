# OpenClaw Shield

**AI Security Posture Management for OpenClaw Agentic Workflows**

A comprehensive security framework that integrates Azure AI Content Safety, Prompt Shields, and Microsoft Purview to protect OpenClaw (Claude Computer Use) deployments from prompt injections, data leakage, and rogue agent behavior.

## 🎯 Overview

OpenClaw Shield provides three layers of defense for AI agents:

1. **Input Shield**: Validates user prompts and detects jailbreak attempts before they reach the LLM
2. **Tool Execution Shield**: Intercepts and validates every tool call (bash, file operations, network requests)
3. **Output Shield**: Sanitizes responses to prevent credential leakage and PII exposure

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    User Request                             │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              LAYER 1: Input Shield                          │
│  • Azure Prompt Shield (jailbreak detection)                │
│  • PII Detection (Azure Content Safety)                     │
│  • DLP Policy Enforcement (Microsoft Purview)               │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              OpenClaw Agent (Claude)                        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│         LAYER 2: Tool Execution Shield                      │
│  • BashCommandShield      (validates shell commands)        │
│  • FileOperationShield    (validates file read/write)       │
│  • NetworkShield          (validates web requests)          │
│  • Policy enforcement on every tool call                    │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│         Sandboxed Execution Environment                     │
│  • Docker container with restricted access                  │
│  • Network egress filtering                                 │
│  • Resource limits                                          │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│         LAYER 3: Output Shield                              │
│  • Response sanitization                                    │
│  • Credential detection                                     │
│  • PII redaction                                            │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Azure subscription with:
  - Azure AI Content Safety resource
  - Microsoft Purview (optional but recommended)
  - Azure Monitor / Application Insights
- OpenClaw setup

### Installation

```bash
# Clone the repository
git clone https://github.com/junhao-bitpulse/openclaw-shield.git
cd openclaw-shield

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your Azure credentials
```

### Configuration

```bash
# .env file
AZURE_CONTENT_SAFETY_ENDPOINT=https://your-instance.cognitiveservices.azure.com/
AZURE_CONTENT_SAFETY_KEY=your-key-here
PURVIEW_ENDPOINT=https://your-purview.purview.azure.com/
SHIELD_MODE=enforcing  # or 'monitoring' for testing

# Customize policies
ALLOWED_BASH_COMMANDS=ls,cat,grep,git,npm,pip,python,node
SAFE_FILE_PATHS=/home/claude/workspace,/tmp/openclaw-sandbox
ALLOWED_DOMAINS=github.com,docs.python.org,stackoverflow.com
```

### Running with Docker Compose

```bash
docker-compose up -d
```

## 📚 Documentation

- [Architecture Deep Dive](./docs/architecture.md)
- [Shield Configuration Guide](./docs/configuration.md)
- [Purview DLP Integration](./docs/purview-integration.md)
- [Incident Response Playbook](./docs/incident-response.md)
- [API Reference](./docs/api-reference.md)

## 🛡️ Security Features

### Bash Command Shield
- Pattern-based blocking of dangerous commands (rm -rf, sudo, curl|bash)
- Command allowlisting
- Prompt injection detection in command parameters
- PII detection in arguments

### File Operation Shield
- Path validation (safe zones enforcement)
- Credential scanning in file content
- PII detection with Purview DLP integration
- Sensitivity label enforcement

### Network Shield
- Domain allowlisting/blocklisting
- URL parameter injection detection
- Response sanitization (indirect prompt injection)
- Data exfiltration prevention

### Output Shield
- Credential leak detection
- PII redaction
- Sensitive path removal
- Azure Content Safety filtering

## 📊 Monitoring & Compliance

### Azure Monitor Integration

```kusto
// Query blocked actions
customEvents
| where name == "ToolExecutionBlocked"
| extend tool = tostring(customDimensions.tool_name),
         reason = tostring(customDimensions.block_reason)
| summarize count() by tool, reason, bin(timestamp, 1h)
```

### Compliance Reporting

- All tool executions logged to Azure Monitor
- PII handling tracked for GDPR compliance
- DLP policy violations reported to Microsoft Purview
- Integration with Azure Sentinel for SOC workflows

## 🔧 Advanced Usage

### Custom Shield Policies

```python
from openclaw_shield import SecureToolExecutor, BashCommandShield

# Extend with custom rules
class CustomBashShield(BashCommandShield):
    async def validate(self, command: str, description: str):
        # Your custom validation logic
        if "production" in command and not self.user_has_permission():
            return {'allowed': False, 'reason': 'Production access denied'}
        
        return await super().validate(command, description)

executor = SecureToolExecutor(bash_shield=CustomBashShield())
```

### Integrating with Existing OpenClaw Deployment

```python
# Wrap your existing OpenClaw setup
from openclaw_shield import SecureToolExecutor

executor = SecureToolExecutor(
    azure_content_safety_endpoint=os.getenv("AZURE_CONTENT_SAFETY_ENDPOINT"),
    azure_content_safety_key=os.getenv("AZURE_CONTENT_SAFETY_KEY"),
    purview_endpoint=os.getenv("PURVIEW_ENDPOINT")
)

# Intercept tool calls
async def execute_tool(tool_name: str, parameters: dict):
    return await executor.execute_tool(tool_name, parameters)
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for details.

## 📄 License

MIT License - see [LICENSE](./LICENSE) file for details

## 🆘 Support

- **Documentation**: [docs/](./docs/)
- **Issues**: [GitHub Issues](https://github.com/junhao-bitpulse/openclaw-shield/issues)
- **Security**: Report vulnerabilities to security@bitpulse.ai

## 🔗 Related Projects

- [OpenClaw](https://github.com/openclaw/openclaw) - The underlying Claude Computer Use framework
- [Prompt Shields](https://github.com/junhao-bitpulse/prompt-shields) - Our commercial AI Security Posture Management platform
- [Azure AI Content Safety](https://azure.microsoft.com/en-us/products/ai-services/ai-content-safety)

## 📈 Roadmap

- [ ] Multi-agent coordination safeguards
- [ ] Real-time policy updates via Purview API
- [ ] ML-based anomaly detection
- [ ] Integration with additional LLM providers
- [ ] Kubernetes deployment support

---

Built with ❤️ by [Bit Pulse AI](https://bitpulse.ai) | Securing AI Agents at Scale
