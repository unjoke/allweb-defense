"""Tests for waf.config integration with url_rules: --url-rules, url_rules_file, errors."""
import pytest

from waf.config import load_config


@pytest.fixture
def tmp_url_rules(tmp_path):
    def _write(name: str, body: str) -> str:
        p = tmp_path / name
        p.write_text(body, encoding="utf-8")
        return str(p)
    return _write


@pytest.fixture
def tmp_config(tmp_path):
    def _write(body: str) -> str:
        p = tmp_path / "waf-config.yaml"
        p.write_text(body, encoding="utf-8")
        return str(p)
    return _write


class TestConfigUrlRulesPlumbing:
    # Default: neither CLI nor YAML → url_rules is None
    def test_default_no_url_rules(self, tmp_config):
        cfg_path = tmp_config("listen_port: 8080\n")
        config = load_config(["--config", cfg_path])
        assert config["url_rules"] is None

    # I5: explicit --url-rules but file missing → SystemExit
    def test_i5_missing_file_exits(self, tmp_config):
        cfg_path = tmp_config("listen_port: 8080\n")
        with pytest.raises(SystemExit):
            load_config(["--config", cfg_path, "--url-rules", "/definitely/missing.yaml"])

    # I6: CLI overrides YAML
    def test_i6_cli_overrides_yaml(self, tmp_config, tmp_url_rules):
        cli_rules = tmp_url_rules("cli.yaml",
                                  "rules:\n  - url: /from-cli\n    detect: [SQL]\n")
        yaml_rules = tmp_url_rules("yaml.yaml",
                                   "rules:\n  - url: /from-yaml\n    detect: [XSS]\n")
        cfg_path = tmp_config(f"listen_port: 8080\nurl_rules_file: '{yaml_rules}'\n")
        config = load_config(["--config", cfg_path, "--url-rules", cli_rules])
        # The CLI file's first rule lists SQL on /from-cli
        ur = config["url_rules"]
        assert ur is not None
        assert ur.rules[0].pattern == "/from-cli"
        assert "sql_injection" in ur.rules[0].detect_keys

    def test_yaml_only(self, tmp_config, tmp_url_rules):
        rules_path = tmp_url_rules(
            "rules.yaml", "rules:\n  - url: /from-yaml\n    detect: [XSS]\n")
        cfg_path = tmp_config(f"listen_port: 8080\nurl_rules_file: '{rules_path}'\n")
        config = load_config(["--config", cfg_path])
        ur = config["url_rules"]
        assert ur is not None
        assert ur.rules[0].pattern == "/from-yaml"
        assert "xss" in ur.rules[0].detect_keys

    def test_strict_error_exits(self, tmp_config, tmp_url_rules):
        bad = tmp_url_rules("bad.yaml",
                            "rules:\n  - url: /foo\n    detect: [BOGUS]\n")
        cfg_path = tmp_config("listen_port: 8080\n")
        with pytest.raises(SystemExit):
            load_config(["--config", cfg_path, "--url-rules", bad])

    def test_warning_on_global_off(self, tmp_config, tmp_url_rules, capsys):
        rules_path = tmp_url_rules(
            "rules.yaml", "rules:\n  - url: /foo\n    detect: [XSS]\n")
        cfg_path = tmp_config(
            "listen_port: 8080\n"
            "rules:\n  xss: false\n"
        )
        load_config(["--config", cfg_path, "--url-rules", rules_path])
        captured = capsys.readouterr()
        assert "url_rules entry [0] lists xss" in captured.err
