"""
Regex patterns for detecting various types of secrets and credentials.

This module defines patterns for common secret types including API keys,
tokens, passwords, and cloud provider credentials.
"""

import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class SecretPattern:
    """Represents a pattern for detecting a specific type of secret."""

    name: str
    pattern: re.Pattern
    severity: str
    description: str

    def match(self, text: str) -> List[re.Match]:
        """Find all matches of this pattern in the given text."""
        return list(self.pattern.finditer(text))


class PatternRegistry:
    """Registry of all secret detection patterns."""

    def __init__(self):
        self._patterns: List[SecretPattern] = []
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load all predefined secret patterns."""
        # AWS Access Key ID
        self._patterns.append(SecretPattern(
            name="AWS Access Key ID",
            pattern=re.compile(r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'),
            severity="high",
            description="AWS Access Key Identifier"
        ))

        # AWS Secret Access Key
        self._patterns.append(SecretPattern(
            name="AWS Secret Access Key",
            pattern=re.compile(r'(?i)(?:aws_secret_access_key|aws_secret_key)\s*[=:]\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?'),
            severity="high",
            description="AWS Secret Access Key"
        ))

        # Generic API Key patterns
        self._patterns.append(SecretPattern(
            name="Generic API Key",
            pattern=re.compile(r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?'),
            severity="medium",
            description="Generic API key assignment"
        ))

        # Private Key headers
        self._patterns.append(SecretPattern(
            name="Private Key",
            pattern=re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'),
            severity="critical",
            description="Private key file header"
        ))

        # GitHub Personal Access Token
        self._patterns.append(SecretPattern(
            name="GitHub Token",
            pattern=re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
            severity="high",
            description="GitHub Personal Access Token"
        ))

        # GitHub OAuth Token
        self._patterns.append(SecretPattern(
            name="GitHub OAuth",
            pattern=re.compile(r'gho_[A-Za-z0-9]{36}'),
            severity="high",
            description="GitHub OAuth Access Token"
        ))

        # GitLab Personal Access Token
        self._patterns.append(SecretPattern(
            name="GitLab Token",
            pattern=re.compile(r'glpat-[A-Za-z0-9\-]{20,}'),
            severity="high",
            description="GitLab Personal Access Token"
        ))

        # Slack Bot Token
        self._patterns.append(SecretPattern(
            name="Slack Bot Token",
            pattern=re.compile(r'xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*'),
            severity="high",
            description="Slack Bot User OAuth Token"
        ))

        # Slack User Token
        self._patterns.append(SecretPattern(
            name="Slack User Token",
            pattern=re.compile(r'xoxp-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*'),
            severity="high",
            description="Slack User OAuth Token"
        ))

        # Slack Webhook URL
        self._patterns.append(SecretPattern(
            name="Slack Webhook",
            pattern=re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[a-zA-Z0-9]{24}'),
            severity="medium",
            description="Slack Incoming Webhook URL"
        ))

        # Google API Key
        self._patterns.append(SecretPattern(
            name="Google API Key",
            pattern=re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
            severity="high",
            description="Google Cloud API Key"
        ))

        # Google OAuth Client Secret
        self._patterns.append(SecretPattern(
            name="Google OAuth Secret",
            pattern=re.compile(r'(?i)google.*[\'"]?[a-zA-Z0-9_\-]{24}[\'"]?'),
            severity="medium",
            description="Potential Google OAuth credential"
        ))

        # Stripe API Key
        self._patterns.append(SecretPattern(
            name="Stripe API Key",
            pattern=re.compile(r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}'),
            severity="high",
            description="Stripe API Key"
        ))

        # Stripe Restricted Key
        self._patterns.append(SecretPattern(
            name="Stripe Restricted Key",
            pattern=re.compile(r'rk_(?:test|live)_[0-9a-zA-Z]{24,}'),
            severity="high",
            description="Stripe Restricted API Key"
        ))

        # Square Access Token
        self._patterns.append(SecretPattern(
            name="Square Token",
            pattern=re.compile(r'sq0atp-[0-9A-Za-z\-_]{22}'),
            severity="high",
            description="Square Access Token"
        ))

        # Square OAuth Secret
        self._patterns.append(SecretPattern(
            name="Square OAuth",
            pattern=re.compile(r'sq0csp-[0-9A-Za-z\-_]{43}'),
            severity="high",
            description="Square OAuth Secret"
        ))

        # Twilio API Key
        self._patterns.append(SecretPattern(
            name="Twilio API Key",
            pattern=re.compile(r'SK[0-9a-fA-F]{32}'),
            severity="high",
            description="Twilio API Key"
        ))

        # Twilio Account SID
        self._patterns.append(SecretPattern(
            name="Twilio SID",
            pattern=re.compile(r'AC[0-9a-fA-F]{32}'),
            severity="medium",
            description="Twilio Account SID"
        ))

        # SendGrid API Key
        self._patterns.append(SecretPattern(
            name="SendGrid Key",
            pattern=re.compile(r'SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}'),
            severity="high",
            description="SendGrid API Key"
        ))

        # Mailgun API Key
        self._patterns.append(SecretPattern(
            name="Mailgun Key",
            pattern=re.compile(r'key-[0-9a-zA-Z]{32}'),
            severity="high",
            description="Mailgun API Key"
        ))

        # Mailchimp API Key
        self._patterns.append(SecretPattern(
            name="Mailchimp Key",
            pattern=re.compile(r'[0-9a-f]{32}-us[0-9]{1,2}'),
            severity="medium",
            description="Mailchimp API Key"
        ))

        # NPM Token
        self._patterns.append(SecretPattern(
            name="NPM Token",
            pattern=re.compile(r'//registry\.npmjs\.org/:_authToken=[a-zA-Z0-9\-]{36,}'),
            severity="high",
            description="NPM Authentication Token"
        ))

        # PyPI Token
        self._patterns.append(SecretPattern(
            name="PyPI Token",
            pattern=re.compile(r'pypi-[A-Za-z0-9\-_]{50,}'),
            severity="high",
            description="PyPI API Token"
        ))

        # Docker Hub Token
        self._patterns.append(SecretPattern(
            name="Docker Token",
            pattern=re.compile(r'dckr_pat_[A-Za-z0-9\-_]{56}'),
            severity="high",
            description="Docker Hub Personal Access Token"
        ))

        # Heroku API Key
        self._patterns.append(SecretPattern(
            name="Heroku Key",
            pattern=re.compile(r'(?i)heroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
            severity="high",
            description="Heroku API Key"
        ))

        # Azure Storage Account Key
        self._patterns.append(SecretPattern(
            name="Azure Storage Key",
            pattern=re.compile(r'(?i)(?:accountkey|storagekey)\s*[=:]\s*[a-zA-Z0-9+/=]{88}'),
            severity="high",
            description="Azure Storage Account Key"
        ))

        # Azure Connection String
        self._patterns.append(SecretPattern(
            name="Azure Connection",
            pattern=re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+'),
            severity="high",
            description="Azure Storage Connection String"
        ))

        # Database connection strings
        self._patterns.append(SecretPattern(
            name="Database URL",
            pattern=re.compile(r'(?i)(?:mysql|postgres|postgresql|mongodb|redis)://[^:]+:[^@]+@'),
            severity="high",
            description="Database connection string with credentials"
        ))

        # Generic password patterns
        self._patterns.append(SecretPattern(
            name="Hardcoded Password",
            pattern=re.compile(r'(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*[\'"][^\'"]{8,}[\'"]'),
            severity="medium",
            description="Potential hardcoded password"
        ))

        # JWT Token
        self._patterns.append(SecretPattern(
            name="JWT Token",
            pattern=re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
            severity="medium",
            description="JSON Web Token"
        ))

        # Basic Auth in URL
        self._patterns.append(SecretPattern(
            name="Basic Auth URL",
            pattern=re.compile(r'https?://[^:]+:[^@]+@'),
            severity="medium",
            description="URL with embedded credentials"
        ))

        # SSH Private Key Path
        self._patterns.append(SecretPattern(
            name="SSH Key Reference",
            pattern=re.compile(r'(?i)identityfile\s+["\']?~?/?\.ssh/id_[a-z]+["\']?'),
            severity="low",
            description="Reference to SSH private key file"
        ))

        # Generic secret/credential keywords with values
        self._patterns.append(SecretPattern(
            name="Generic Secret",
            pattern=re.compile(r'(?i)(?:secret|credential|token|auth)\s*[=:]\s*[\'"]?[a-zA-Z0-9_\-]{16,}[\'"]?'),
            severity="low",
            description="Potential generic secret value"
        ))

    @property
    def patterns(self) -> List[SecretPattern]:
        """Return all registered patterns."""
        return self._patterns

    def get_by_severity(self, severity: str) -> List[SecretPattern]:
        """Get patterns filtered by severity level."""
        return [p for p in self._patterns if p.severity == severity]

    def get_by_name(self, name: str) -> Optional[SecretPattern]:
        """Get a pattern by its name."""
        for pattern in self._patterns:
            if pattern.name.lower() == name.lower():
                return pattern
        return None


# Global registry instance
registry = PatternRegistry()


def get_all_patterns() -> List[SecretPattern]:
    """Get all registered secret patterns."""
    return registry.patterns


def get_patterns_by_severity(severity: str) -> List[SecretPattern]:
    """Get patterns filtered by severity."""
    return registry.get_by_severity(severity)
