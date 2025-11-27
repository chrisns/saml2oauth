"""
Shared pytest fixtures for saml2oauth tests.
"""
import os
import sys
import json
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Set required environment variables BEFORE importing app modules
os.environ.setdefault("OAUTH_CLIENT_ID", "test-client-id")
os.environ.setdefault("OAUTH_CLIENT_SECRET", "test-client-secret")
os.environ.setdefault("SP_ACS_URL", "https://sp.example.com/acs")
os.environ.setdefault("SP_ENTITY_ID", "https://sp.example.com")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("FLASK_SECRET_KEY", "test-secret-key-for-testing-only")
os.environ.setdefault("SAML_KEYPAIR_SECRET_NAME", "test-saml-keypair")


@pytest.fixture(scope="session")
def test_keypair():
    """Generate a test RSA keypair and self-signed certificate for SAML signing."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    # Generate RSA key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("ascii")

    # Self-signed cert
    now = datetime.utcnow()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    return {
        "private_key": private_key_pem,
        "certificate": cert_pem
    }


@pytest.fixture
def mock_secrets_manager(test_keypair):
    """Mock boto3 Secrets Manager client to return test keypair."""
    with patch("shim_saml.boto3") as mock_boto3:
        mock_sm = MagicMock()
        mock_boto3.client.return_value = mock_sm

        # Configure exception classes
        mock_sm.exceptions.ResourceNotFoundException = type('ResourceNotFoundException', (Exception,), {})
        mock_sm.exceptions.ResourceExistsException = type('ResourceExistsException', (Exception,), {})

        # Return test keypair on get_secret_value
        mock_sm.get_secret_value.return_value = {
            "SecretString": json.dumps({
                "private_key_pem": test_keypair["private_key"],
                "cert_pem": test_keypair["certificate"]
            })
        }
        yield mock_sm


@pytest.fixture
def app_client(mock_secrets_manager):
    """Create Flask test client with mocked dependencies."""
    from app import app
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        yield client


@pytest.fixture
def app_instance():
    """Get the Flask app instance."""
    from app import app
    return app


@pytest.fixture
def mock_oauth_provider():
    """Mock Authlib OAuth client."""
    with patch("app.oauth") as mock_oauth:
        mock_sso = MagicMock()
        mock_oauth.sso = mock_sso
        yield mock_sso


@pytest.fixture
def mock_scim_requests():
    """Mock requests for SCIM API calls."""
    with patch("shim_scim.requests") as mock_requests:
        yield mock_requests


@pytest.fixture
def sample_user_claims():
    """Standard user claims for testing."""
    return {
        "sub": "user-12345",
        "email": "test@example.gov.uk",
        "display_name": "Test User",
        "given_name": "Test",
        "family_name": "User",
        "groups": ["admin", "developers"],
        "picture": "https://example.com/avatar.png"
    }


@pytest.fixture
def sample_oauth_token(sample_user_claims):
    """Mock OAuth token response with userinfo."""
    return {
        "access_token": "mock-access-token",
        "token_type": "Bearer",
        "sub": sample_user_claims["sub"],
        "userinfo": {
            "sub": sample_user_claims["sub"],
            "email": sample_user_claims["email"],
            "email_verified": True,
            "display_name": sample_user_claims["display_name"],
            "given_name": sample_user_claims["given_name"],
            "family_name": sample_user_claims["family_name"],
            "groups": sample_user_claims["groups"],
            "picture": sample_user_claims["picture"]
        }
    }


@pytest.fixture
def sample_saml_request():
    """Base64-encoded sample SAML AuthnRequest."""
    import base64
    saml_request_xml = '''<samlp:AuthnRequest
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        ID="_test-request-id-12345"
        Version="2.0"
        IssueInstant="2024-01-01T00:00:00Z"
        AssertionConsumerServiceURL="https://sp.example.com/acs">
        <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            https://sp.example.com
        </saml:Issuer>
    </samlp:AuthnRequest>'''
    return base64.b64encode(saml_request_xml.encode()).decode()


@pytest.fixture
def minimal_claims():
    """Minimal claims with only email."""
    return {
        "sub": "minimal-user",
        "email": "minimal@example.com"
    }


@pytest.fixture
def claims_with_special_chars():
    """Claims with special characters that need escaping."""
    return {
        "sub": "special-user",
        "email": "user@example.com",
        "display_name": '<script>alert("xss")</script>',
        "given_name": "Test & User",
        "family_name": "O'Brien",
        "groups": ['admin"injection', "<group>"]
    }
