# Vulnerability: Plain-text password storage
# Reference IDs: CWE-256 | OWASP A02:2021 Cryptographic Failures
# Author: Andrew Lopez (M-2)
# Fixed Code Snippet

import argparse
import hashlib
import hmac
import os
import sqlite3


ITERATIONS = 600_000


def fixed_example(db_path: str, action: str, username: str, password: str) -> bool:
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, salt BLOB NOT NULL, password_hash BLOB NOT NULL)"
        )
        if action == "register":
            # Secure implementation: save a unique random salt and derived hash.
            salt = os.urandom(16)
            password_hash = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt, ITERATIONS
            )
            connection.execute(
                "INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)",
                (username, salt, password_hash),
            )
            return True
        row = connection.execute(
            "SELECT salt, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row is None:
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), row[0], ITERATIONS
        )
        return hmac.compare_digest(candidate, row[1])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fixed password storage demo")
    parser.add_argument("--db", default="fixed-users.db")
    parser.add_argument("action", choices=("register", "login"))
    parser.add_argument("username")
    parser.add_argument("password")
    args = parser.parse_args()
    try:
        result = fixed_example(args.db, args.action, args.username, args.password)
    except sqlite3.IntegrityError:
        parser.error("Username already exists")
    print("Registered" if args.action == "register" else ("Access granted" if result else "Access denied"))
