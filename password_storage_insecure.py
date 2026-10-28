# Vulnerability: Plain-text password storage
# Reference IDs: CWE-256 | OWASP A02:2021 Cryptographic Failures
# Author: Andrew Lopez (M-2)
# Insecure Code Snippet

import argparse
import hmac
import sqlite3


def insecure_example(db_path: str, action: str, username: str, password: str) -> bool:
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT NOT NULL)"
        )
        if action == "register":
            # Vulnerable implementation: the original readable password is saved.
            connection.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password),
            )
            return True
        row = connection.execute(
            "SELECT password FROM users WHERE username = ?", (username,)
        ).fetchone()
        return row is not None and hmac.compare_digest(password, row[0])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Insecure password storage demo")
    parser.add_argument("--db", default="insecure-users.db")
    parser.add_argument("action", choices=("register", "login"))
    parser.add_argument("username")
    parser.add_argument("password")
    args = parser.parse_args()
    try:
        result = insecure_example(args.db, args.action, args.username, args.password)
    except sqlite3.IntegrityError:
        parser.error("Username already exists")
    print("Registered" if args.action == "register" else ("Access granted" if result else "Access denied"))
