"""
Unit tests for SAML response generation and cryptographic operations.
These tests are CRITICAL as they cover security-sensitive signing operations.
"""
import pytest
import base64
import json
from lxml import etree
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from freezegun import freeze_time


class TestFetchCertAndKey:
    """Test certificate/key retrieval from AWS Secrets Manager."""

    def test_returns_existing_keypair_from_secrets_manager(self, mock_secrets_manager, test_keypair):
        """Should return existing keypair when secret exists."""
        from shim_saml import fetch_cert_and_key

        key, cert = fetch_cert_and_key("test-secret", "test.example.com")

        assert key == test_keypair["private_key"]
        assert cert == test_keypair["certificate"]
        mock_secrets_manager.get_secret_value.assert_called_once()

    def test_generates_new_keypair_when_secret_not_found(self):
        """Should generate and store new keypair when ResourceNotFoundException."""
        with patch("shim_saml.boto3") as mock_boto3:
            mock_sm = MagicMock()
            mock_boto3.client.return_value = mock_sm

            # Create proper exception class
            class ResourceNotFoundException(Exception):
                pass

            class ResourceExistsException(Exception):
                pass

            mock_sm.exceptions.ResourceNotFoundException = ResourceNotFoundException
            mock_sm.exceptions.ResourceExistsException = ResourceExistsException
            mock_sm.get_secret_value.side_effect = ResourceNotFoundException("Not found")

            from shim_saml import fetch_cert_and_key
            key, cert = fetch_cert_and_key("new-secret", "test.example.com")

            # Should have created secret
            assert mock_sm.create_secret.called or mock_sm.put_secret_value.called
            assert "BEGIN" in key and "PRIVATE KEY" in key
            assert "BEGIN CERTIFICATE" in cert

    def test_handles_corrupted_secret_gracefully(self):
        """Should regenerate when secret JSON is malformed."""
        with patch("shim_saml.boto3") as mock_boto3:
            mock_sm = MagicMock()
            mock_boto3.client.return_value = mock_sm

            class ResourceNotFoundException(Exception):
                pass

            class ResourceExistsException(Exception):
                pass

            mock_sm.exceptions.ResourceNotFoundException = ResourceNotFoundException
            mock_sm.exceptions.ResourceExistsException = ResourceExistsException
            mock_sm.get_secret_value.return_value = {
                "SecretString": "not-valid-json"
            }

            from shim_saml import fetch_cert_and_key
            key, cert = fetch_cert_and_key("bad-secret", "localhost")

            # Should regenerate valid keypair
            assert key is not None
            assert cert is not None
            assert "BEGIN" in key


class TestBuildSamlResponse:
    """Test SAML response XML generation and signing."""

    @freeze_time("2024-06-15 12:00:00")
    def test_generates_valid_signed_saml_response(self, test_keypair, sample_user_claims):
        """Should generate properly signed SAML response."""
        from shim_saml import build_saml_response

        result_b64 = build_saml_response(
            idp_cert=test_keypair["certificate"],
            idp_key=test_keypair["private_key"],
            SP_ACS_URL="https://sp.example.com/acs",
            SP_ENTITY_ID="https://sp.example.com",
            NAMEID_FORMAT="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            claims=sample_user_claims,
            issuer="https://idp.example.com/",
        )

        # Decode and parse
        result_xml = base64.b64decode(result_b64).decode()
        root = etree.fromstring(result_xml.encode())

        # Verify structure
        assert root.tag.endswith("Response")
        assert root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion") is not None
        assert root.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature") is not None

    def test_includes_in_response_to_when_saml_request_provided(
        self, test_keypair, sample_user_claims, sample_saml_request
    ):
        """Should extract and include InResponseTo from SAML request."""
        from shim_saml import build_saml_response

        result_b64 = build_saml_response(
            idp_cert=test_keypair["certificate"],
            idp_key=test_keypair["private_key"],
            SP_ACS_URL="https://sp.example.com/acs",
            SP_ENTITY_ID="https://sp.example.com",
            NAMEID_FORMAT="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            claims=sample_user_claims,
            issuer="https://idp.example.com/",
            saml_request_b64=sample_saml_request
        )

        result_xml = base64.b64decode(result_b64).decode()
        assert 'InResponseTo="_test-request-id-12345"' in result_xml

    def test_includes_all_user_attributes(self, test_keypair, sample_user_claims):
        """Should include email, name, groups in AttributeStatement."""
        from shim_saml import build_saml_response

        result_b64 = build_saml_response(
            idp_cert=test_keypair["certificate"],
            idp_key=test_keypair["private_key"],
            SP_ACS_URL="https://sp.example.com/acs",
            SP_ENTITY_ID="https://sp.example.com",
            NAMEID_FORMAT="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            claims=sample_user_claims,
            issuer="https://idp.example.com/",
        )

        result_xml = base64.b64decode(result_b64).decode()

        assert sample_user_claims["email"] in result_xml
        assert sample_user_claims["display_name"] in result_xml
        assert "admin" in result_xml  # group
        assert "developers" in result_xml  # group

    def test_handles_minimal_claims(self, test_keypair, minimal_claims):
        """Should work with only email claim."""
        from shim_saml import build_saml_response

        result_b64 = build_saml_response(
            idp_cert=test_keypair["certificate"],
            idp_key=test_keypair["private_key"],
            SP_ACS_URL="https://sp.example.com/acs",
            SP_ENTITY_ID="https://sp.example.com",
            NAMEID_FORMAT="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            claims=minimal_claims,
            issuer="https://idp.example.com/",
        )

        assert result_b64 is not None
        result_xml = base64.b64decode(result_b64).decode()
        assert "minimal@example.com" in result_xml

    def test_escapes_special_characters_in_claims(self, test_keypair, claims_with_special_chars):
        """Should escape special characters to prevent XML injection."""
        from shim_saml import build_saml_response

        result_b64 = build_saml_response(
            idp_cert=test_keypair["certificate"],
            idp_key=test_keypair["private_key"],
            SP_ACS_URL="https://sp.example.com/acs",
            SP_ENTITY_ID="https://sp.example.com",
            NAMEID_FORMAT="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            claims=claims_with_special_chars,
            issuer="https://idp.example.com/",
        )

        result_xml = base64.b64decode(result_b64).decode()

        # Should NOT contain raw script tags (should be escaped)
        assert '<script>' not in result_xml
        # Should contain escaped version
        assert '&lt;script&gt;' in result_xml or '&lt;' in result_xml

        # XML should be valid and parseable
        root = etree.fromstring(result_xml.encode())
        assert root is not None

    def test_uses_cryptographically_random_ids(self, test_keypair, sample_user_claims):
        """Should use random IDs, not predictable timestamps."""
        from shim_saml import build_saml_response

        result1_b64 = build_saml_response(
            idp_cert=test_keypair["certificate"],
            idp_key=test_keypair["private_key"],
            SP_ACS_URL="https://sp.example.com/acs",
            SP_ENTITY_ID="https://sp.example.com",
            NAMEID_FORMAT="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            claims=sample_user_claims,
            issuer="https://idp.example.com/",
        )

        result2_b64 = build_saml_response(
            idp_cert=test_keypair["certificate"],
            idp_key=test_keypair["private_key"],
            SP_ACS_URL="https://sp.example.com/acs",
            SP_ENTITY_ID="https://sp.example.com",
            NAMEID_FORMAT="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            claims=sample_user_claims,
            issuer="https://idp.example.com/",
        )

        result1_xml = base64.b64decode(result1_b64).decode()
        result2_xml = base64.b64decode(result2_b64).decode()

        # Extract IDs - they should be different (random)
        import re
        ids1 = re.findall(r'ID="([^"]+)"', result1_xml)
        ids2 = re.findall(r'ID="([^"]+)"', result2_xml)

        # Each response should have unique IDs
        assert ids1 != ids2, "IDs should be random, not identical"


class TestGetSamlMetadata:
    """Test SAML IdP metadata generation."""

    def test_generates_valid_metadata_xml(self, mock_secrets_manager):
        """Should generate valid IdP metadata XML."""
        from shim_saml import get_saml_metadata

        xml = get_saml_metadata(
            login_url="https://idp.example.com/login",
            logout_url="https://idp.example.com/logout",
            idp_entity_id="https://idp.example.com/",
            NAMEID_FORMAT="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            secret_name="test-secret",
            host="idp.example.com"
        )

        assert "EntityDescriptor" in xml
        assert "IDPSSODescriptor" in xml
        assert "SingleSignOnService" in xml
        assert "X509Certificate" in xml

    def test_includes_correct_endpoints(self, mock_secrets_manager):
        """Should include login/logout URLs in metadata."""
        from shim_saml import get_saml_metadata

        xml = get_saml_metadata(
            login_url="https://idp.example.com/login",
            logout_url="https://idp.example.com/logout",
            idp_entity_id="https://idp.example.com/",
            NAMEID_FORMAT="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            secret_name="test-secret",
            host="idp.example.com"
        )

        assert "https://idp.example.com/login" in xml
        assert "https://idp.example.com/logout" in xml
