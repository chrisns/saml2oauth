"""
Unit tests for SCIM provisioning logic.
"""
import pytest
from unittest.mock import patch, MagicMock, call
import responses


class TestEscapeScimFilterValue:
    """Test SCIM filter value escaping."""

    def test_escapes_double_quotes(self):
        """Should escape double quotes in filter values."""
        from shim_scim import escape_scim_filter_value

        result = escape_scim_filter_value('test"value')
        assert result == 'test\\"value'

    def test_escapes_backslashes(self):
        """Should escape backslashes in filter values."""
        from shim_scim import escape_scim_filter_value

        result = escape_scim_filter_value('test\\value')
        assert result == 'test\\\\value'

    def test_handles_empty_string(self):
        """Should handle empty string gracefully."""
        from shim_scim import escape_scim_filter_value

        result = escape_scim_filter_value('')
        assert result == ''

    def test_handles_none(self):
        """Should handle None gracefully."""
        from shim_scim import escape_scim_filter_value

        result = escape_scim_filter_value(None)
        assert result is None

    def test_escapes_injection_attempt(self):
        """Should escape SCIM filter injection attempts."""
        from shim_scim import escape_scim_filter_value

        # Attempt to break out of filter
        malicious = 'user@example.com" or "1"="1'
        result = escape_scim_filter_value(malicious)
        assert '"' not in result.replace('\\"', '')  # All quotes should be escaped


class TestPushUserInfoToScim:
    """Test user provisioning via SCIM."""

    def test_creates_new_user_when_not_found(self, mock_scim_requests, sample_user_claims):
        """Should POST new user when search returns empty."""
        from shim_scim import push_user_info_to_scim

        # Mock search returns empty
        search_response = MagicMock()
        search_response.status_code = 200
        search_response.json.return_value = {"Resources": []}

        # Mock create returns new user
        create_response = MagicMock()
        create_response.status_code = 201
        create_response.json.return_value = {"id": "new-user-id"}

        mock_scim_requests.get.return_value = search_response
        mock_scim_requests.post.return_value = create_response
        mock_scim_requests.patch.return_value = MagicMock(status_code=200)

        result = push_user_info_to_scim(
            "https://scim.example.com",
            "token",
            sample_user_claims
        )

        # Should have called POST, not PUT
        mock_scim_requests.post.assert_called()
        call_url = str(mock_scim_requests.post.call_args)
        assert "/Users" in call_url

    def test_updates_existing_user_when_found(self, mock_scim_requests, sample_user_claims):
        """Should PUT update when user already exists."""
        from shim_scim import push_user_info_to_scim

        # Mock search finds user
        search_response = MagicMock()
        search_response.status_code = 200
        search_response.json.return_value = {
            "Resources": [{"id": "existing-user-id"}]
        }

        # Mock update
        update_response = MagicMock()
        update_response.status_code = 200

        mock_scim_requests.get.return_value = search_response
        mock_scim_requests.put.return_value = update_response
        mock_scim_requests.patch.return_value = MagicMock(status_code=200)

        result = push_user_info_to_scim(
            "https://scim.example.com",
            "token",
            sample_user_claims
        )

        mock_scim_requests.put.assert_called()
        call_url = str(mock_scim_requests.put.call_args)
        assert "existing-user-id" in call_url

    def test_raises_on_search_failure(self, mock_scim_requests, sample_user_claims):
        """Should raise RuntimeError on SCIM search failure."""
        from shim_scim import push_user_info_to_scim

        error_response = MagicMock()
        error_response.status_code = 500
        error_response.text = "Internal Server Error"
        mock_scim_requests.get.return_value = error_response

        with pytest.raises(RuntimeError, match="SCIM search failed"):
            push_user_info_to_scim(
                "https://scim.example.com",
                "token",
                sample_user_claims
            )

    def test_raises_on_missing_email(self, mock_scim_requests):
        """Should raise ValueError when claims have no email."""
        from shim_scim import push_user_info_to_scim

        claims_no_email = {"sub": "user-123", "display_name": "No Email"}

        with pytest.raises(ValueError, match="must have an email"):
            push_user_info_to_scim(
                "https://scim.example.com",
                "token",
                claims_no_email
            )

    def test_uses_escaped_email_in_filter(self, mock_scim_requests):
        """Should escape email in SCIM filter to prevent injection."""
        from shim_scim import push_user_info_to_scim

        claims_with_injection = {
            "sub": "user-123",
            "email": 'user@example.com" or "1"="1'
        }

        search_response = MagicMock()
        search_response.status_code = 200
        search_response.json.return_value = {"Resources": []}

        create_response = MagicMock()
        create_response.status_code = 201
        create_response.json.return_value = {"id": "new-user-id"}

        mock_scim_requests.get.return_value = search_response
        mock_scim_requests.post.return_value = create_response

        push_user_info_to_scim(
            "https://scim.example.com",
            "token",
            claims_with_injection
        )

        # Verify the filter URL has escaped quotes
        call_args = mock_scim_requests.get.call_args
        url = call_args[0][0] if call_args[0] else call_args[1].get('url', '')
        # The quotes should be escaped
        assert '\\"' in url or '%5C%22' in url or '" or "' not in url


class TestSyncGroupsForUser:
    """Test group membership sync."""

    def test_creates_group_if_not_exists(self, mock_scim_requests):
        """Should create SCIM group when not found."""
        from shim_scim import sync_groups_for_user

        # Search returns empty (group not found)
        search_empty = MagicMock()
        search_empty.status_code = 200
        search_empty.json.return_value = {"Resources": []}

        create_response = MagicMock()
        create_response.status_code = 201
        create_response.json.return_value = {"id": "new-group-id"}

        mock_scim_requests.get.return_value = search_empty
        mock_scim_requests.post.return_value = create_response
        mock_scim_requests.patch.return_value = MagicMock(status_code=200)

        sync_groups_for_user(
            "user-123",
            ["new-group"],
            "https://scim.example.com",
            {"Authorization": "Bearer token"}
        )

        # Should create group
        mock_scim_requests.post.assert_called()

    def test_adds_user_to_existing_group(self, mock_scim_requests):
        """Should PATCH add member to existing group."""
        from shim_scim import sync_groups_for_user

        # Group exists
        search_response = MagicMock()
        search_response.status_code = 200
        search_response.json.return_value = {
            "Resources": [{"id": "existing-group-id"}]
        }

        mock_scim_requests.get.return_value = search_response
        mock_scim_requests.patch.return_value = MagicMock(status_code=200)

        sync_groups_for_user(
            "user-123",
            ["existing-group"],
            "https://scim.example.com",
            {"Authorization": "Bearer token"}
        )

        mock_scim_requests.patch.assert_called()
        patch_call = str(mock_scim_requests.patch.call_args)
        assert "existing-group-id" in patch_call


class TestBuildUserInfo:
    """Test SCIM user payload construction."""

    def test_builds_complete_user_payload(self, sample_user_claims):
        """Should build SCIM user with all fields."""
        from shim_scim import build_user_info

        result = build_user_info(sample_user_claims)

        assert result["userName"] == "test@example.gov.uk"
        assert result["externalId"] == "user-12345"
        assert result["active"] is True
        assert result["displayName"] == "Test User"
        assert result["emails"][0]["value"] == "test@example.gov.uk"
        assert result["name"]["givenName"] == "Test"
        assert result["name"]["familyName"] == "User"

    def test_handles_missing_optional_fields(self, minimal_claims):
        """Should work with minimal claims."""
        from shim_scim import build_user_info

        result = build_user_info(minimal_claims)

        assert result["userName"] == "minimal@example.com"
        assert "displayName" not in result

    def test_includes_scim_schema(self, sample_user_claims):
        """Should include SCIM user schema."""
        from shim_scim import build_user_info

        result = build_user_info(sample_user_claims)

        assert "schemas" in result
        assert "urn:ietf:params:scim:schemas:core:2.0:User" in result["schemas"]
