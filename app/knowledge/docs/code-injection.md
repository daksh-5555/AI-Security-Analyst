# Preventing dynamic code execution of untrusted input

## Why it happens
Functions that evaluate text as code, such as `eval`, `exec`, or dynamic imports driven by request values, run whatever the text contains with the application's privileges.

## Fix: remove the evaluation
Replace evaluation with explicit logic: a dictionary that maps allowed names to functions, a parser for the specific expression language that is needed, or `ast.literal_eval` for literal values only.

## If evaluation must remain
Restrict inputs to a small allowlist that is checked before evaluation. Sandboxing interpreter features is not a reliable defense.
