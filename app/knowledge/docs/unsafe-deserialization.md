# Avoiding unsafe deserialization

## Why it happens
Some serialization formats can create arbitrary objects while loading. Loading attacker-controlled data with such a format, for example Python pickle or unsafe YAML loaders, can execute code.

## Fix: use a data-only format
Exchange untrusted data as JSON or another format that only produces plain data, and validate it against a schema. For YAML, use the safe loader.

## When object serialization is unavoidable
Only load data produced by the application itself, protect it with an integrity check such as an HMAC verified before loading, and keep the key out of the data path.

## Defense in depth
Run deserialization in a process with minimal privileges and monitor for unexpected failures.
