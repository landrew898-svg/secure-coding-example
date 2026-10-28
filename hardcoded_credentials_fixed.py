# Vulnerability: Hard-coded credentials
# Reference IDs: CWE-798 | OWASP A07:2021 Identification and Authentication Failures
# Author: Andrew Lopez (M-2)
# Fixed Code Snippet

import argparse
import hmac
import os


def fixed_example(password: str) -> bool:
    # Secure implementation: deployment supplies the secret outside the source.
    operator_password = os.environ.get("DEMO_OPERATOR_PASSWORD")
    if not operator_password:
        raise RuntimeError("Set DEMO_OPERATOR_PASSWORD before running this example")
    return hmac.compare_digest(password, operator_password)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fixed operator login demo")
    parser.add_argument("--password", required=True)
    args = parser.parse_args()
    try:
        allowed = fixed_example(args.password)
    except RuntimeError as exc:
        parser.error(str(exc))
    print("Access granted" if allowed else "Access denied")
