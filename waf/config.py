import argparse
import copy
import sys

_UNSET = object()

try:
    import yaml
except ImportError:
    yaml = None

DEFAULTS = {
    "listen_port": 8080,
    "backend_url": "http://127.0.0.1:5000",
    "login_path": "/login",
    "rules": {
        "sql_injection": True,
        "xss": True,
        "path_traversal": True,
        "cmd_injection": True,
        "rate_limit": True,
        "file_upload": True,
        "security_headers": True,
    },
    "rate_limit": {
        "max_failures": 10,
        "window": 60,
        "lockout": 300,
    },
    "log_path": "security.log",
}


def _deep_merge(base: dict, override: dict) -> dict:
    result = base.copy()
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="WAF Reverse Proxy")
    parser.add_argument("--listen", type=int, default=None)
    parser.add_argument("--backend", type=str, default=None)
    parser.add_argument("--config", type=str, default=_UNSET)
    parser.add_argument("--disable", nargs="+", default=[])
    return parser


def load_config(argv=None) -> dict:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    config = copy.deepcopy(DEFAULTS)

    # Determine whether --config was explicitly provided or is the default
    config_explicitly_set = args.config is not _UNSET
    config_path = args.config if config_explicitly_set else "waf/config.yaml"

    if yaml is not None:
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                file_data = yaml.safe_load(f)
            if isinstance(file_data, dict):
                config = _deep_merge(config, file_data)
        except FileNotFoundError:
            if config_explicitly_set:
                print(f"Error: config file not found: {config_path}", file=sys.stderr)
                sys.exit(1)
            # default path missing — silently use defaults
    else:
        # yaml not available; if --config was explicitly set, warn and exit
        if config_explicitly_set:
            print("Error: PyYAML is not installed; cannot load config file.", file=sys.stderr)
            sys.exit(1)

    # Apply CLI overrides
    if args.listen is not None:
        config["listen_port"] = args.listen
    if args.backend is not None:
        config["backend_url"] = args.backend

    # Apply --disable rules
    for rule_name in (args.disable or []):
        if rule_name not in config["rules"]:
            print(f"Warning: unknown rule '{rule_name}', ignoring", file=sys.stderr)
            continue
        config["rules"][rule_name] = False

    return config
