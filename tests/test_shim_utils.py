"""
Unit tests for utility functions.
"""
import pytest
import json
from freezegun import freeze_time


class TestJprint:
    """Test JSON logging utility."""

    @freeze_time("2024-06-15 12:00:00")
    def test_outputs_json_with_timestamp(self, capsys):
        """Should output JSON with _datetime field."""
        from shim_utils import jprint

        jprint({"message": "test"})

        captured = capsys.readouterr()
        output = json.loads(captured.out.strip())

        assert output["_datetime"] == "2024-06-15T12:00:00.000000Z"
        assert output["message"] == "test"

    def test_converts_string_to_message_dict(self, capsys):
        """Should wrap string in message dict."""
        from shim_utils import jprint

        jprint("simple message")

        captured = capsys.readouterr()
        output = json.loads(captured.out.strip())

        assert output["message"] == "simple message"

    def test_handles_additional_dict_arguments(self, capsys):
        """Should merge additional dict args."""
        from shim_utils import jprint

        jprint("base message", {"extra": "data"})

        captured = capsys.readouterr()
        output = json.loads(captured.out.strip())

        assert output["extra"] == "data"
        assert "base" in output["message"]

    def test_handles_multiple_string_arguments(self, capsys):
        """Should concatenate multiple string arguments."""
        from shim_utils import jprint

        jprint("first", "second", "third")

        captured = capsys.readouterr()
        output = json.loads(captured.out.strip())

        assert "first" in output["message"]
        assert "second" in output["message"]
        assert "third" in output["message"]

    def test_handles_empty_call(self, capsys):
        """Should handle call with no arguments."""
        from shim_utils import jprint

        jprint()

        captured = capsys.readouterr()
        output = json.loads(captured.out.strip())

        assert "_datetime" in output

    def test_handles_none_argument(self, capsys):
        """Should handle None as argument."""
        from shim_utils import jprint

        jprint(None)

        captured = capsys.readouterr()
        output = json.loads(captured.out.strip())

        assert "_datetime" in output
        assert output["message"] == "None"
