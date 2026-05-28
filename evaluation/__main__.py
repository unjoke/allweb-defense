"""CLI entry point: python -m evaluation <mode>"""
import argparse
import sys
from collections import Counter

from .payload_loader import load_all
from .runner import run
from .report import generate


def main():
    parser = argparse.ArgumentParser(description="WAF Adversarial Evaluation")
    parser.add_argument("mode", choices=["baseline", "hardened"])
    parser.add_argument("--waf-url", default="http://127.0.0.1:8080")
    parser.add_argument("--payloads-dir", default="evaluation/payloads/")
    parser.add_argument("--results-dir", default="evaluation/results/")
    parser.add_argument("--category", help="Only run payloads of this category")
    parser.add_argument("--skip-rate-limit", action="store_true",
                        help="Skip rate_limit category (avoids long lockout)")
    args = parser.parse_args()

    payloads = load_all(
        args.payloads_dir,
        category=args.category,
        skip_rate_limit=args.skip_rate_limit,
    )
    if not payloads:
        print(f"No payloads loaded from {args.payloads_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(payloads)} payloads, targeting {args.waf_url}")
    try:
        results = run(payloads, args.waf_url)
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    path = generate(results, args.results_dir, label=args.mode)
    outcomes = Counter(r.outcome for r in results)
    print(f"Report written to {path}")
    print(f"  TP={outcomes['TP']}  FN={outcomes['FN']}  "
          f"FP={outcomes['FP']}  TN={outcomes['TN']}")


if __name__ == "__main__":
    main()
