# Secure Coding Examples in Python

Four runnable Python examples compare insecure and safer ways to handle credentials and store passwords. Each pair performs the same task so you can see how the security change affects the implementation.

The examples use only the Python standard library. Run the commands below from this folder in PowerShell. Bandit is an optional dependency for scanning the code.

These are educational demonstrations with intentionally vulnerable versions, not a complete authentication system. Use disposable demo credentials only.

## Hard-coded credentials (CWE-798)

Both scripts authenticate a demo operator and print `Access granted` or `Access denied`. The insecure script contains its demo password in source. The fixed script requires an externally supplied secret.

```powershell
python hardcoded_credentials_insecure.py --password demo-password-123
$env:DEMO_OPERATOR_PASSWORD = 'demo-password-123'
python hardcoded_credentials_fixed.py --password demo-password-123
Remove-Item Env:DEMO_OPERATOR_PASSWORD
```

The fixed version stops with an error if `DEMO_OPERATOR_PASSWORD` is missing or empty. Keeping the secret outside the source allows it to change without editing the code; access to that external configuration still needs protection.

## Plain-text password storage (CWE-256)

Both scripts register a user in a local SQLite database and then authenticate the user. They use separate database files so their storage can be compared. The insecure database has a readable `password` column. The fixed database stores a random salt and a PBKDF2-HMAC-SHA256 hash.

```powershell
python password_storage_insecure.py register alice demo-password-123
python password_storage_insecure.py login alice demo-password-123
python password_storage_fixed.py register alice demo-password-123
python password_storage_fixed.py login alice demo-password-123
```

Pass `--db path/to/file.db` before the command to choose a database file. For example: `python password_storage_fixed.py --db fixed-demo.db register alice demo-password-123`.

Try a different password with `login` to see `Access denied`. If you register the same username twice, the script reports that it already exists. Use another username or a fresh database when repeating the demonstration.

The examples accept passwords as command-line arguments for repeatable runs. Real applications should use a protected input method, such as a non-echoing prompt or a secure form, to avoid exposing passwords in command history or process arguments. Generated databases are excluded by `.gitignore`.

## Bandit results and optional custom check

The standard Bandit 1.9.4 scan is saved in `bandit-results.json`. It reports B105 on the insecure hard-coded password and no findings on the other three files. It misses the plain-text password storage vulnerability.

To reproduce the standard scan:

```powershell
python -m pip install bandit==1.9.4
python -m bandit hardcoded_credentials_insecure.py hardcoded_credentials_fixed.py password_storage_insecure.py password_storage_fixed.py -f json -o bandit-results.json
```

`scan_with_custom_bandit.py` adds a custom rule, B901, for the direct password insert used in these examples. Run it with:

```powershell
python scan_with_custom_bandit.py hardcoded_credentials_insecure.py hardcoded_credentials_fixed.py password_storage_insecure.py password_storage_fixed.py -f json -o bandit-custom-results.json
```

The verified custom scan reports B105 on `hardcoded_credentials_insecure.py` and B901 (CWE-256) on `password_storage_insecure.py`. Neither fixed file has findings. Exit status 1 means findings were reported.

B901 is a custom heuristic, not a built-in Bandit rule. It checks explicit SQL INSERT column lists with question-mark placeholders for a directly supplied password-named variable in a password-named column. It does not trace values through aliases, dynamic SQL, other database operations, or earlier transformations. It can miss vulnerable code and can flag values hashed earlier under the same variable name.

The custom rule assigns high severity and medium confidence. Its implementation is in `scan_with_custom_bandit.py`; Bandit's automatically generated B901 documentation URL is not an official rule page. The launcher uses Bandit's internal extension registry and was tested with version 1.9.4.

Keep the standard and custom scan results distinct. A scan with no findings does not prove that code is secure, as the plain-text storage example demonstrates.
