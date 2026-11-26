"""Local-only regression checks for the private Railway health service."""
import json
import threading
import unittest
from http.server import HTTPServer
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import urlopen

import railway_health


class CloudRuntimeTests(unittest.TestCase):
    def test_full_runtime_selfcheck(self):
        result = railway_health.run_checks()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["tests"], 3)

    def test_broken_engine_is_not_marked_healthy(self):
        with patch("railway_health.load_engine", side_effect=RuntimeError("injected missing engine")):
            with self.assertRaisesRegex(RuntimeError, "missing engine"):
                railway_health.run_checks()

    def test_health_endpoint_never_runs_crypto(self):
        server = HTTPServer(("127.0.0.1", 0), railway_health.HealthHandler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        root = "http://127.0.0.1:" + str(server.server_port)
        try:
            with urlopen(root + "/healthz", timeout=5) as res:
                self.assertEqual(res.status, 200)
                self.assertEqual(json.loads(res.read()), {"status": "ok"})
            with self.assertRaises(HTTPError) as result:
                urlopen(root + "/factor?modulus=3233", timeout=5)
            self.assertEqual(result.exception.code, 404)
        finally:
            server.shutdown()
            worker.join(timeout=5)
            server.server_close()


if __name__ == "__main__":
    unittest.main()
