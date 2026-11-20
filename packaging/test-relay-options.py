"""Exercise the production script's argument/TLS selection without system changes."""
import pathlib
import subprocess
import unittest

SCRIPT = pathlib.Path(__file__).with_name("shixpeer-ward-prepare-relay.sh").read_text()
PREFIX = SCRIPT.split('[[ $(uname -s) == Linux', 1)[0]
PRINT = '\nprintf "%s\\n" "$origin" "$address_type:$hostname" "${verify_name[*]}" "$listen_host"\n'

class RelayOptions(unittest.TestCase):
    def run_options(self, host, port="9443"):
        return subprocess.run(["bash", "-c", PREFIX + PRINT, "relay-options", "--hostname", host, "--port", port], capture_output=True, text=True)

    def test_ipv4(self):
        result = self.run_options("192.0.2.10")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["https://192.0.2.10:9443", "IP:192.0.2.10", "-verify_ip 192.0.2.10", "0.0.0.0"])

    def test_ipv6(self):
        result = self.run_options("[2001:db8::1]")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["https://[2001:db8::1]:9443", "IP:2001:db8::1", "-verify_ip 2001:db8::1", "[::]"])

    def test_dns(self):
        result = self.run_options("relay.example.com")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("DNS:relay.example.com", result.stdout)
        self.assertIn("-verify_hostname relay.example.com", result.stdout)

    def test_invalid(self):
        for host, port in [("999.2.3.4", "9443"), ("192.02.3.4", "9443"), ("192.0.2.10", "80"), ("bad;touch", "9443")]:
            with self.subTest(host=host, port=port):
                result = self.run_options(host, port)
                self.assertEqual(result.returncode, 2)
                self.assertIn("FAILED:", result.stderr)
                self.assertNotIn("Usage:", result.stderr)

    def test_missing_option_value(self):
        result = subprocess.run(["bash", "-c", PREFIX, "relay-options", "--port"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("FAILED: Missing value for --port.", result.stderr)

    def test_help(self):
        result = subprocess.run(["bash", "-c", PREFIX, "relay-options", "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Usage:", result.stdout)

if __name__ == "__main__":
    unittest.main()
