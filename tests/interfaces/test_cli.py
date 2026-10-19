"""The CLI renders data returned by the shared engine."""

import contextlib
import io
import json
import unittest
from unittest.mock import patch

from interfaces.cli import main


class CliTests(unittest.TestCase):
    def test_local_json_uses_shared_port_reader(self):
        rows = [{"pid": 7, "process": "demo", "address": "127.0.0.1:8080", "port": 8080}]
        output = io.StringIO()
        with patch("core.local_ports.get_local_ports", return_value=rows), contextlib.redirect_stdout(output):
            self.assertEqual(main(["--local", "--json"]), 0)
        self.assertEqual(json.loads(output.getvalue()), rows)


if __name__ == "__main__":
    unittest.main()
