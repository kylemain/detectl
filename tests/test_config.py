import os
import tempfile
import unittest
from pathlib import Path

from detectl.config import load_config
from detectl.exceptions import ConfigError


class TestLoadConfig(unittest.TestCase):
    def setUp(self):
        self._env_backup = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env_backup)

    def test_unknown_platform(self):
        with self.assertRaises(ConfigError):
            load_config("not-a-platform")

    def test_missing_required_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yml"
            path.write_text("splunk:\n  base_url: https://splunk.example.com\n")
            with self.assertRaises(ConfigError) as ctx:
                load_config("splunk", config_path=path)
            self.assertIn("token", str(ctx.exception))

    def test_loads_from_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yml"
            path.write_text("splunk:\n  base_url: https://splunk.example.com\n  token: abc123\n")
            values = load_config("splunk", config_path=path)
            self.assertEqual(values["base_url"], "https://splunk.example.com")
            self.assertEqual(values["token"], "abc123")

    def test_env_var_substitution_in_yaml(self):
        os.environ["MY_SPLUNK_TOKEN"] = "secret-token"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yml"
            path.write_text("splunk:\n  base_url: https://splunk.example.com\n  token: ${MY_SPLUNK_TOKEN}\n")
            values = load_config("splunk", config_path=path)
            self.assertEqual(values["token"], "secret-token")

    def test_env_var_substitution_missing_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yml"
            path.write_text("splunk:\n  base_url: https://splunk.example.com\n  token: ${DOES_NOT_EXIST_VAR}\n")
            with self.assertRaises(ConfigError):
                load_config("splunk", config_path=path)

    def test_falls_back_to_platform_prefixed_env_vars(self):
        os.environ["SPLUNK_BASE_URL"] = "https://splunk.example.com"
        os.environ["SPLUNK_TOKEN"] = "envtoken"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yml"  # no file written -> falls through to env only
            values = load_config("splunk", config_path=path)
            self.assertEqual(values["token"], "envtoken")

    def test_verify_ssl_string_normalized_to_bool(self):
        os.environ["SPLUNK_BASE_URL"] = "https://splunk.example.com"
        os.environ["SPLUNK_TOKEN"] = "t"
        os.environ["SPLUNK_VERIFY_SSL"] = "false"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yml"
            values = load_config("splunk", config_path=path)
            self.assertIs(values["verify_ssl"], False)


if __name__ == "__main__":
    unittest.main()
