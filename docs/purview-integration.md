# Microsoft Purview DLP Integration

## Overview

This guide explains how to integrate OpenClaw Shield with Microsoft Purview for comprehensive Data Loss Prevention (DLP) and information protection.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│              OpenClaw Shield                             │
│  ┌────────────────────────────────────────────────────┐  │
│  │ File Operation Shield                              │  │
│  │ - Detects PII in file operations                   │  │
│  │ - Checks sensitivity labels                        │  │
│  └──────────────────┬─────────────────────────────────┘  │
│                     │                                     │
│                     ▼                                     │
│  ┌────────────────────────────────────────────────────┐  │
│  │ Purview Integration Layer                          │  │
│  │ - DLP Policy Evaluation                            │  │
│  │ - Sensitivity Label Application                    │  │
│  │ - Compliance Reporting                             │  │
│  └──────────────────┬─────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────┐
│         Microsoft Purview                                │
│  ┌────────────────┬────────────────┬──────────────────┐  │
│  │ DLP Policies   │ Sensitivity    │ Compliance       │  │
│  │                │ Labels         │ Manager          │  │
│  └────────────────┴────────────────┴──────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

## Prerequisites

1. **Microsoft Purview Setup**
   - Active Microsoft 365 E5 or Purview subscription
   - Purview DLP policies configured
   - Information Protection labels defined

2. **Azure Permissions**
   ```
   - InformationProtection.Read.All
   - InformationProtection.Write.All
   - Policy.Read.All
   ```

3. **Environment Variables**
   ```bash
   PURVIEW_TENANT_ID=your-tenant-id
   PURVIEW_CLIENT_ID=your-app-client-id
   PURVIEW_CLIENT_SECRET=your-client-secret
   PURVIEW_ENDPOINT=https://your-org.purview.azure.com/
   ```

## Configuration

### 1. Register Azure AD Application

```bash
# Using Azure CLI
az ad app create --display-name "OpenClaw Shield Purview Integration"

# Grant API permissions
az ad app permission add \
  --id <app-id> \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions \
    4e46008b-f24c-477d-8fff-7bb4ec7aafe0=Scope
```

### 2. Define DLP Policies in Purview

Navigate to **Microsoft Purview Compliance Portal** → **Data Loss Prevention**

#### Example Policy: Block High-Value PII in AI Operations

```yaml
Policy Name: "AI Agent PII Protection"
Description: "Prevent AI agents from processing or transmitting sensitive PII"

Conditions:
  - Content contains:
      - Credit card numbers (5+ instances)
      - Social Security Numbers
      - Passport numbers
  
  - Location:
      - Any file created by OpenClaw
      - Any bash command output
      - Any web_fetch response

Actions:
  - Block the operation
  - Send incident report to security team
  - Require business justification

Exceptions:
  - User is in "AI Admin" security group
  - Content has "Public" sensitivity label
```

### 3. Configure Sensitivity Labels

Define labels that OpenClaw Shield will apply:

| Label | Protection | When Applied |
|-------|-----------|--------------|
| Public | None | No PII detected |
| Internal | Encryption at rest | Low-risk PII (emails, names) |
| Confidential | Encryption + Access control | Credit cards, SSNs detected |
| Highly Confidential | Full DLP + Watermarking | Multiple high-risk PII types |

## Implementation

### Purview Client Integration

```python
# openclaw_shield/purview_client.py

from azure.identity import ClientSecretCredential
from azure.core.credentials import AccessToken
import requests
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class PurviewDLPClient:
    """
    Microsoft Purview DLP integration for OpenClaw Shield
    """
    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        purview_endpoint: str
    ):
        self.endpoint = purview_endpoint
        self.credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )
        self.token = None
    
    async def _get_access_token(self) -> str:
        """Get Azure AD access token for Purview API"""
        if not self.token or self._is_token_expired():
            self.token = self.credential.get_token(
                "https://purview.azure.net/.default"
            )
        return self.token.token
    
    async def evaluate_dlp_policy(
        self,
        content: str,
        file_path: str,
        detected_pii: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Evaluate content against Purview DLP policies
        
        Args:
            content: File content or command output
            file_path: Path to file (for context)
            detected_pii: PII entities detected by Azure Content Safety
        
        Returns:
            DLP decision: ALLOW, BLOCK, ENCRYPT, or AUDIT
        """
        token = await self._get_access_token()
        
        # Build DLP evaluation request
        payload = {
            "content": content[:50000],  # Limit size
            "metadata": {
                "file_path": file_path,
                "source": "openclaw_agent",
                "detected_entities": detected_pii
            }
        }
        
        # Call Purview DLP API
        response = requests.post(
            f"{self.endpoint}/dataLossPrevention/evaluate",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            },
            json=payload
        )
        
        if response.status_code != 200:
            logger.error(f"Purview DLP evaluation failed: {response.text}")
            # Fail closed - block if DLP check fails
            return {
                'action': 'BLOCK',
                'reason': 'DLP evaluation failed',
                'policy_name': 'Default Deny'
            }
        
        result = response.json()
        return self._parse_dlp_response(result)
    
    def _parse_dlp_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Purview DLP response into action
        """
        # Determine action based on policy matches
        matched_policies = response.get('matched_policies', [])
        
        if not matched_policies:
            return {'action': 'ALLOW', 'policy_name': None}
        
        # Take most restrictive action
        actions = [policy.get('action') for policy in matched_policies]
        
        if 'BLOCK' in actions:
            blocking_policy = next(p for p in matched_policies if p['action'] == 'BLOCK')
            return {
                'action': 'BLOCK',
                'policy_name': blocking_policy.get('name'),
                'reason': blocking_policy.get('reason'),
                'detected_types': blocking_policy.get('sensitive_info_types', [])
            }
        
        if 'ENCRYPT' in actions:
            encryption_policy = next(p for p in matched_policies if p['action'] == 'ENCRYPT')
            return {
                'action': 'ENCRYPT',
                'policy_name': encryption_policy.get('name'),
                'label': encryption_policy.get('sensitivity_label'),
                'encryption_method': 'AES256'
            }
        
        return {'action': 'AUDIT', 'policy_name': matched_policies[0].get('name')}
    
    async def apply_sensitivity_label(
        self,
        file_path: str,
        label: str,
        justification: Optional[str] = None
    ) -> bool:
        """
        Apply Microsoft Information Protection label to file
        
        Args:
            file_path: Path to file
            label: Label name (e.g., "Confidential")
            justification: Business justification for the label
        
        Returns:
            Success status
        """
        token = await self._get_access_token()
        
        payload = {
            "file_path": file_path,
            "label": label,
            "justification": justification or "Applied by OpenClaw Shield",
            "method": "automatic"
        }
        
        response = requests.post(
            f"{self.endpoint}/informationProtection/applyLabel",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            },
            json=payload
        )
        
        if response.status_code == 200:
            logger.info(f"Sensitivity label '{label}' applied to {file_path}")
            return True
        else:
            logger.error(f"Failed to apply label: {response.text}")
            return False
    
    async def get_file_label(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve current sensitivity label for a file
        
        Returns:
            Label metadata including sensitivity level
        """
        token = await self._get_access_token()
        
        response = requests.get(
            f"{self.endpoint}/informationProtection/getLabel",
            headers={"Authorization": f"Bearer {token}"},
            params={"file_path": file_path}
        )
        
        if response.status_code == 200:
            label_data = response.json()
            return {
                'label_name': label_data.get('name'),
                'sensitivity': label_data.get('sensitivity_level'),
                'requires_approval': label_data.get('requires_justification', False),
                'encryption_enabled': label_data.get('encryption', {}).get('enabled', False)
            }
        
        return None
    
    async def report_dlp_incident(
        self,
        incident_type: str,
        details: Dict[str, Any]
    ) -> str:
        """
        Report DLP incident to Purview Compliance Manager
        
        Args:
            incident_type: Type of incident (e.g., "pii_exposure", "policy_violation")
            details: Incident details
        
        Returns:
            Incident ID
        """
        token = await self._get_access_token()
        
        payload = {
            "incident_type": incident_type,
            "severity": details.get('severity', 'MEDIUM'),
            "source": "openclaw_shield",
            "details": details,
            "timestamp": details.get('timestamp')
        }
        
        response = requests.post(
            f"{self.endpoint}/compliance/incidents",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            },
            json=payload
        )
        
        if response.status_code == 201:
            incident_id = response.json().get('incident_id')
            logger.info(f"DLP incident reported: {incident_id}")
            return incident_id
        else:
            logger.error(f"Failed to report incident: {response.text}")
            return None
```

### Integration with File Shield

```python
# Modify openclaw_shield/shields.py FileOperationShield

class FileOperationShield:
    def __init__(self, azure_client, purview_client, config):
        self.azure = azure_client
        self.purview = purview_client  # Add Purview client
        self.config = config
    
    async def validate_file_write(self, path: str, content: str) -> Dict[str, Any]:
        # ... existing validation ...
        
        # PII detection
        pii_scan = await self.azure.detect_pii(content)
        
        if pii_scan.get('contains_pii'):
            # Evaluate against Purview DLP policies
            dlp_decision = await self.purview.evaluate_dlp_policy(
                content=content,
                file_path=path,
                detected_pii=pii_scan.get('entities', [])
            )
            
            if dlp_decision['action'] == 'BLOCK':
                # Report incident
                await self.purview.report_dlp_incident(
                    incident_type='pii_in_file_write',
                    details={
                        'file_path': path,
                        'policy': dlp_decision['policy_name'],
                        'detected_types': dlp_decision['detected_types'],
                        'severity': 'HIGH',
                        'timestamp': datetime.utcnow().isoformat()
                    }
                )
                
                return {
                    'allowed': False,
                    'reason': f"DLP policy violation: {dlp_decision['policy_name']}",
                    'severity': 'HIGH'
                }
            
            elif dlp_decision['action'] == 'ENCRYPT':
                # Apply sensitivity label
                await self.purview.apply_sensitivity_label(
                    file_path=path,
                    label=dlp_decision['label']
                )
                logger.info(f"Sensitivity label applied: {dlp_decision['label']}")
        
        return {'allowed': True}
```

## Compliance Reporting

### Query DLP Incidents in Azure Monitor

```kusto
// Purview DLP incidents from OpenClaw Shield
customEvents
| where name == "DLPIncident"
| extend 
    incident_type = tostring(customDimensions.incident_type),
    policy = tostring(customDimensions.policy_name),
    severity = tostring(customDimensions.severity),
    file_path = tostring(customDimensions.file_path)
| summarize count() by incident_type, policy, bin(timestamp, 1d)
| render timechart
```

### Export to Purview Compliance Manager

```python
# Automated compliance report generation
async def generate_compliance_report(start_date, end_date):
    """
    Generate compliance report for auditors
    """
    incidents = await purview_client.query_incidents(
        start_date=start_date,
        end_date=end_date,
        source="openclaw_shield"
    )
    
    report = {
        'period': f"{start_date} to {end_date}",
        'total_incidents': len(incidents),
        'by_severity': {},
        'by_policy': {},
        'remediation_actions': []
    }
    
    for incident in incidents:
        severity = incident['severity']
        policy = incident['policy_name']
        
        report['by_severity'][severity] = report['by_severity'].get(severity, 0) + 1
        report['by_policy'][policy] = report['by_policy'].get(policy, 0) + 1
    
    return report
```

## Best Practices

### 1. Policy Design
- **Start permissive**: Begin with AUDIT-only policies to understand patterns
- **Gradual enforcement**: Move to BLOCK only after testing
- **Exception handling**: Define clear exception processes

### 2. Label Taxonomy
```
Public
  └─ Internal
      └─ Confidential
          └─ Highly Confidential
              └─ Restricted
```

### 3. Monitoring
- Set up alerts for policy violations
- Regular review of DLP incidents
- Monitor false positive rate

### 4. Performance
- Cache DLP policy evaluations where possible
- Batch label applications
- Use async operations for API calls

## Troubleshooting

### Common Issues

**Issue**: DLP evaluation timeout
```python
# Solution: Increase timeout and add retry logic
response = requests.post(
    url,
    timeout=30,  # Increase from default 10s
    json=payload
)
```

**Issue**: Label application fails
```python
# Solution: Check file permissions and label compatibility
label_info = await purview_client.get_file_label(path)
if label_info and label_info['encryption_enabled']:
    # File may already have incompatible label
    logger.warning("File already labeled, cannot override")
```

**Issue**: High false positive rate
```python
# Solution: Fine-tune PII detection sensitivity
pii_scan = await azure.detect_pii(
    content,
    severity_threshold=4  # Increase from 2 to reduce false positives
)
```

## References

- [Microsoft Purview DLP Documentation](https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp)
- [Information Protection SDK](https://learn.microsoft.com/en-us/information-protection/)
- [Azure Content Safety Integration](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/)
