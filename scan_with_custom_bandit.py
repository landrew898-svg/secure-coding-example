"""Run Bandit with project-specific B901 (tested with Bandit 1.9.4).

This is a narrow name-based heuristic, not password data-flow analysis.
It detects direct password variables inserted into explicit password columns
using SQL question-mark placeholders. Aliases, dynamic SQL, other SQL forms,
and values hashed earlier under the same variable name are not resolved.
"""

import ast
import re
import sys
from types import SimpleNamespace

import bandit
from bandit.cli.main import main
from bandit.core import extension_loader, test_properties


PASSWORD_NAMES = {"password", "passwd", "pwd", "user_password", "plain_password"}


@test_properties.checks("Call")
@test_properties.test_id("B901")
def custom_plaintext_password_insert(context):
    node = context.node
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "execute":
        return
    if len(node.args) < 2:
        return
    sql, values = node.args[:2]
    if not isinstance(sql, ast.Constant) or not isinstance(sql.value, str):
        return
    if not isinstance(values, (ast.Tuple, ast.List)):
        return
    match = re.fullmatch(
        r"\s*INSERT\s+INTO\s+\w+\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)\s*;?\s*",
        sql.value,
        re.IGNORECASE,
    )
    if not match:
        return
    columns = [column.strip().lower() for column in match[1].split(",")]
    placeholders = [value.strip() for value in match[2].split(",")]
    if len(columns) != len(values.elts) or len(columns) != len(placeholders):
        return
    if any(value != "?" for value in placeholders):
        return
    for column, value in zip(columns, values.elts):
        if column in PASSWORD_NAMES and isinstance(value, ast.Name):
            if value.id.lower() in PASSWORD_NAMES:
                return bandit.Issue(
                    severity=bandit.HIGH,
                    confidence=bandit.MEDIUM,
                    cwe=256,
                    text=(
                        "CUSTOM PROJECT RULE: Possible plain-text password storage. "
                        "A password variable is inserted directly into a password column; "
                        "verify that it is hashed before storage."
                    ),
                )


if __name__ == "__main__":
    manager = extension_loader.MANAGER
    if "B901" in manager.plugins_by_id:
        raise RuntimeError("B901 is already registered; choose another custom rule ID")
    plugin = SimpleNamespace(
        name="custom_plaintext_password_insert",
        plugin=custom_plaintext_password_insert,
    )
    # Register for this invocation only; the standard Bandit command is unchanged.
    manager.plugins.append(plugin)
    manager.plugin_names.append(plugin.name)
    manager.plugins_by_id["B901"] = plugin
    manager.plugins_by_name[plugin.name] = plugin
    print("Running Bandit with CUSTOM project rule B901 (CWE-256).", file=sys.stderr)
    main()
