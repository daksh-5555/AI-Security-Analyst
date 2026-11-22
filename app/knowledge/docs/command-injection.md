# Preventing OS command injection

## Why it happens
Command injection occurs when request text is passed to a shell. Shell metacharacters let an attacker append or replace commands and run them with the application's privileges.

## Fix: avoid the shell
Prefer a library function over an external program. If a program must run, call it with an argument list and the shell disabled, for example `subprocess.run([...], shell=False)`, so each value is a single argument.

## Constrain arguments
Validate arguments against an allowlist of expected values or a strict pattern, and place a `--` separator before user-supplied operands so they cannot be read as options.

## Defense in depth
Run the process with minimal operating-system privileges, a fixed working directory, a restricted environment, and a timeout.
