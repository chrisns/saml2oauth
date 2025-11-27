"""
Integration tests for Flask routes and OAuth authentication flow.
"""
import pytest
from unittest.mock import patch, MagicMock


class TestHealthRoutes:
    """Test health check endpoints."""

    def test_health_returns_ok(self, app_client):
        """Should return OK for basic health check."""
        response = app_client.get("/health")
        assert response.status_code == 200
        assert response.data == b"OK"

    def test_health_cert_returns_ok_when_cert_available(self, app_client, mock_secrets_manager):
        """Should return OK when certificate is accessible."""
        response = app_client.get("/health/cert")
        assert response.status_code == 200
        assert response.data == b"OK"


class TestRootRoute:
    """Test root/home page."""

    def test_root_returns_html_page(self, app_client):
        """Should return HTML page with links."""
        response = app_client.get("/")
        assert response.status_code == 200
        assert b"SAML2OAuth" in response.data
        assert b"IDP Entity ID" in response.data


class TestLoginRoute:
    """Test /login endpoint."""

    def test_stores_saml_request_in_session(self, app_client, sample_saml_request):
        """Should store SAMLRequest in session for later use."""
        with patch("app.oauth.sso") as mock_sso:
            mock_sso.authorize_redirect.return_value = MagicMock(
                status_code=302,
                headers={"Location": "https://sso.example.com/authorize"}
            )

            response = app_client.get(
                f"/login?SAMLRequest={sample_saml_request}&RelayState=test-relay"
            )

            with app_client.session_transaction() as sess:
                assert sess.get("saml_request") == sample_saml_request
                assert sess.get("relay_state") == "test-relay"

    def test_redirects_to_saml_response_when_already_signed_in(self, app_client):
        """Should skip OAuth when user already has valid session."""
        with app_client.session_transaction() as sess:
            sess["signed_in"] = True
            sess["user"] = {"email": "test@example.com"}

        response = app_client.get("/login")

        assert response.status_code == 302
        assert "/saml/response" in response.headers["Location"]


class TestCallbackRoute:
    """Test /callback endpoint (OAuth return)."""

    def test_successful_callback_creates_session(
        self, app_client, mock_secrets_manager, sample_oauth_token
    ):
        """Should create session and redirect to SAML response on success."""
        with patch("app.oauth.sso") as mock_sso:
            mock_sso.authorize_access_token.return_value = sample_oauth_token

            with patch("app.push_user_info_to_scim"):
                response = app_client.get("/callback")

            with app_client.session_transaction() as sess:
                assert sess["signed_in"] is True
                assert sess["user"]["email"] == "test@example.gov.uk"

    def test_callback_extracts_all_user_claims(
        self, app_client, mock_secrets_manager, sample_oauth_token
    ):
        """Should extract sub, email, display_name, groups from token."""
        with patch("app.oauth.sso") as mock_sso:
            mock_sso.authorize_access_token.return_value = sample_oauth_token

            with patch("app.push_user_info_to_scim"):
                response = app_client.get("/callback")

            with app_client.session_transaction() as sess:
                user = sess["user"]
                assert user["sub"] == "user-12345"
                assert user["email"] == "test@example.gov.uk"
                assert user["display_name"] == "Test User"
                assert "admin" in user["groups"]

    def test_callback_rejects_unverified_email(self, app_client, mock_secrets_manager):
        """Should reject tokens where email is not verified."""
        unverified_token = {
            "userinfo": {
                "email": "unverified@example.com",
                "email_verified": False
            }
        }

        with patch("app.oauth.sso") as mock_sso:
            mock_sso.authorize_access_token.return_value = unverified_token

            response = app_client.get("/callback")

            assert response.status_code == 302
            # Should redirect to error or saml response, not create session
            with app_client.session_transaction() as sess:
                assert sess.get("signed_in") is not True


class TestLogoutRoute:
    """Test /logout endpoint."""

    def test_clears_session_and_redirects(self, app_client):
        """Should clear session and redirect to external logout URL."""
        with app_client.session_transaction() as sess:
            sess["signed_in"] = True
            sess["user"] = {"email": "test@example.com"}

        response = app_client.get("/logout")

        assert response.status_code == 302
        with app_client.session_transaction() as sess:
            assert "signed_in" not in sess
            assert "user" not in sess


class TestSamlResponseRoute:
    """Test /saml/response endpoint."""

    def test_generates_saml_response_for_signed_in_user(
        self, app_client, sample_user_claims, mock_secrets_manager
    ):
        """Should return auto-post form with SAML response."""
        with app_client.session_transaction() as sess:
            sess["signed_in"] = True
            sess["user"] = sample_user_claims
            sess["saml_request"] = None
            sess["relay_state"] = None

        response = app_client.get("/saml/response")

        assert response.status_code == 200
        html = response.data.decode()
        assert "SAMLResponse" in html
        assert "document.forms[0].submit()" in html

    def test_includes_relay_state_when_provided(
        self, app_client, sample_user_claims, mock_secrets_manager
    ):
        """Should include RelayState in auto-post form."""
        with app_client.session_transaction() as sess:
            sess["signed_in"] = True
            sess["user"] = sample_user_claims
            sess["relay_state"] = "https://app.example.com/dashboard"

        response = app_client.get("/saml/response")
        html = response.data.decode()

        assert "RelayState" in html

    def test_escapes_relay_state_to_prevent_xss(
        self, app_client, sample_user_claims, mock_secrets_manager
    ):
        """Should escape RelayState to prevent XSS attacks."""
        with app_client.session_transaction() as sess:
            sess["signed_in"] = True
            sess["user"] = sample_user_claims
            sess["relay_state"] = '"><script>alert("xss")</script>'

        response = app_client.get("/saml/response")
        html = response.data.decode()

        # Should not contain raw script tag
        assert '<script>alert("xss")</script>' not in html
        # Should contain escaped version
        assert '&lt;script&gt;' in html or '&#' in html or '&quot;' in html

    def test_redirects_to_error_when_not_signed_in(self, app_client):
        """Should redirect to error page for unauthenticated request."""
        response = app_client.get("/saml/response")

        assert response.status_code == 302
        assert "error" in response.headers["Location"]


class TestSamlCertRoute:
    """Test /saml/cert endpoint."""

    def test_returns_certificate_pem(self, app_client, mock_secrets_manager):
        """Should return certificate with correct content type."""
        response = app_client.get("/saml/cert")

        assert response.status_code == 200
        assert b"BEGIN CERTIFICATE" in response.data


class TestSamlMetadataRoute:
    """Test /saml/metadata endpoint."""

    def test_returns_metadata_xml(self, app_client, mock_secrets_manager):
        """Should return valid SAML metadata XML."""
        response = app_client.get("/saml/metadata")

        assert response.status_code == 200
        assert b"EntityDescriptor" in response.data

    def test_view_mode_returns_html_escaped(self, app_client, mock_secrets_manager):
        """Should return HTML page when view=true."""
        response = app_client.get("/saml/metadata?view=true")

        assert response.status_code == 200
        html = response.data.decode()
        assert "<pre>" in html
        assert "&lt;" in html  # Escaped XML


class TestBuildAutoPostHtml:
    """Test the auto-post HTML generation helper."""

    def test_generates_form_with_saml_response(self):
        """Should generate form with SAMLResponse input."""
        from app import build_auto_post_html

        html = build_auto_post_html(
            "https://sp.example.com/acs",
            "base64encodedsamlresponse",
            relay_state=None
        )

        assert 'action="https://sp.example.com/acs"' in html
        assert 'name="SAMLResponse"' in html
        assert 'value="base64encodedsamlresponse"' in html
        assert "document.forms[0].submit()" in html

    def test_includes_relay_state_when_provided(self):
        """Should include RelayState input when provided."""
        from app import build_auto_post_html

        html = build_auto_post_html(
            "https://sp.example.com/acs",
            "base64encodedsamlresponse",
            relay_state="https://return.url"
        )

        assert 'name="RelayState"' in html

    def test_escapes_relay_state_special_chars(self):
        """Should escape special characters in relay state."""
        from app import build_auto_post_html

        html = build_auto_post_html(
            "https://sp.example.com/acs",
            "base64encodedsamlresponse",
            relay_state='"><img src=x onerror=alert(1)>'
        )

        # Should not contain raw HTML injection
        assert 'onerror=alert(1)' not in html or '&' in html
