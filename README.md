# Week 2: Andrew Lopez (M-2) snippet pairs

These four standalone Python 3 examples cover the two assigned vulnerabilities. They use only the standard library. Run them from this folder.

## Hard-coded credentials (CWE-798)

Both scripts authenticate a demo operator and print `Access granted` or `Access denied`. The insecure script contains its demo password in source. The fixed script requires an externally supplied secret.

```powershell
python hardcoded_credentials_insecure.py --password demo-password-123
$env:DEMO_OPERATOR_PASSWORD = 'demo-password-123'
python hardcoded_credentials_fixed.py --password demo-password-123
Remove-Item Env:DEMO_OPERATOR_PASSWORD
```

Use only a disposable demonstration password. The command-line argument is convenient for this classroom demo; a real application should avoid putting passwords in process arguments and use a protected secret source and input method.

## Plain-text password storage (CWE-256)

Both scripts register a user in a local SQLite database and then authenticate the user. They use separate database files so their storage can be compared. The insecure database has a readable `password` column. The fixed database stores a random salt and a PBKDF2-HMAC-SHA256 hash.

```powershell
python password_storage_insecure.py register alice demo-password-123
python password_storage_insecure.py login alice demo-password-123
python password_storage_fixed.py register alice demo-password-123
python password_storage_fixed.py login alice demo-password-123
```

Pass `--db path/to/file.db` before the command to choose a database file. For example: `python password_storage_fixed.py --db fixed-demo.db register alice demo-password-123`. The password argument is for a simple repeatable demo; production software should collect it through a non-echoing prompt or secure form. Do not use real passwords. Delete the demo databases after the demonstration.

The files are ready to hand to Jack Vega for the Week 2 merge. Cameron's final naming convention may require renaming them.

## Bandit results and optional custom check

The standard Bandit 1.9.4 scan is saved in `bandit-results.json`. It reports B105 on the insecure hard-coded password and no findings on the other three files. It misses the plain-text password storage vulnerability.

`scan_with_custom_bandit.py` adds project-specific rule B901 to Bandit for one invocation. Run it from this folder:

```powershell
python scan_with_custom_bandit.py hardcoded_credentials_insecure.py hardcoded_credentials_fixed.py password_storage_insecure.py password_storage_fixed.py -f json -o bandit-custom-results.json
```

The verified custom scan reports B105 on `hardcoded_credentials_insecure.py` and B901 (CWE-256) on `password_storage_insecure.py`. Neither fixed file has findings. Exit status 1 means findings were reported.

B901 is a custom heuristic, NOT a built-in Bandit rule. It checks explicit SQL INSERT column lists with question-mark placeholders for a directly supplied password-named variable in a password-named column. It does not trace values through aliases, dynamic SQL, other database operations, or earlier transformations. It can miss vulnerable code and can flag values hashed earlier under the same variable name. High severity and medium confidence are assigned by this project rule. Its implementation is in `scan_with_custom_bandit.py`; Bandit's automatically generated B901 documentation URL is not an official rule page. The launcher uses Bandit's internal extension registry and was tested with version 1.9.4.
