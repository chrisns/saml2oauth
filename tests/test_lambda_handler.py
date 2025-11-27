"""
Integration tests for Lambda handler entry point.
"""

from unittest.mock import MagicMock, patch


class TestLambdaHandler:
    """Test Lambda handler function."""

    def test_handles_health_check_event(self, mock_secrets_manager):
        """Should handle API Gateway/ALB event for health check."""
        # Create a minimal ALB-style event
        event = {
            "requestContext": {"elb": {"targetGroupArn": "arn:aws:..."}},
            "httpMethod": "GET",
            "path": "/health",
            "headers": {"host": "example.com"},
            "queryStringParameters": None,
            "body": None,
            "isBase64Encoded": False,
        }

        from lambda_function import lambda_handler

        result = lambda_handler(event, {})

        assert result["statusCode"] == 200
        assert result["body"] == "OK"

    def test_returns_500_on_exception(self):
        """Should return 500 error on unhandled exception."""
        event = {
            "requestContext": {"elb": {"targetGroupArn": "arn:aws:..."}},
            "httpMethod": "GET",
            "path": "/crash",
            "headers": {"host": "example.com"},
            "queryStringParameters": None,
            "body": None,
            "isBase64Encoded": False,
        }

        with patch("lambda_function.make_lambda_handler") as mock_handler:
            mock_handler.return_value = MagicMock(side_effect=Exception("Boom"))

            from lambda_function import lambda_handler

            result = lambda_handler(event, {})

        assert result["statusCode"] == 500
        assert "Error" in result["body"]

    def test_logs_request_and_response(self, mock_secrets_manager, capsys):
        """Should log request and response for monitoring."""
        event = {
            "requestContext": {"elb": {"targetGroupArn": "arn:aws:..."}},
            "httpMethod": "GET",
            "path": "/health",
            "headers": {"host": "example.com"},
            "queryStringParameters": None,
            "body": None,
            "isBase64Encoded": False,
        }

        from lambda_function import lambda_handler

        lambda_handler(event, {})

        captured = capsys.readouterr()
        # Should have logged something
        assert "Request" in captured.out or "Response" in captured.out
