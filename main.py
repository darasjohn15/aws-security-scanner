from scanner.formatter import print_findings, print_json
import argparse

from scanner.formatter import print_findings
from scanner.s3_checks import scan_s3_buckets
from scanner.sg_checks import scan_security_groups


def parse_args():
    parser = argparse.ArgumentParser(
        description="AWS Security Scanner CLI - scan AWS resources for common security misconfigurations."
    )

    parser.add_argument(
        "--check",
        choices=["all", "sg", "s3"],
        default="all",
        help="Choose which scan to run: all, sg (security groups), or s3 (S3 buckets). Default is all.",
    )

    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format: text (default) or json.",
    )

    return parser.parse_args()


def main():
    args = parse_args()
    findings = []

    print("\nAWS Security Scanner")
    print("=" * 25)
    print(f"Running check: {args.check}\n")

    if args.check in ("all", "sg"):
        print("Scanning security groups...")
        findings.extend(scan_security_groups())

    if args.check in ("all", "s3"):
        print("Scanning S3 buckets...")
        findings.extend(scan_s3_buckets())

    if args.output == "json":
        print_json(findings)
    else:
        print_findings(findings)


if __name__ == "__main__":
    main()