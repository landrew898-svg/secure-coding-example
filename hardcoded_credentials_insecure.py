# Vulnerability: Hard-coded credentials
# Reference IDs: CWE-798 | OWASP A07:2021 Identification and Authentication Failures
# Author: Andrew Lopez (M-2)
# Insecure Code Snippet

import argparse
import hmac


def insecure_example(password: str) -> bool:
    # Vulnerable implementation: the credential is exposed to anyone reading source.
    operator_password = "demo-password-123"
    return hmac.compare_digest(password, operator_password)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Insecure operator login demo")
    parser.add_argument("--password", required=True)
    args = parser.parse_args()
    print("Access granted" if insecure_example(args.password) else "Access denied")
