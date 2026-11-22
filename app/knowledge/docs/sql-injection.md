# Preventing SQL injection

## Why it happens
SQL injection occurs when text from a request becomes part of the SQL statement itself instead of being passed as data. Building a query with string concatenation, f-strings, or format calls lets an attacker change the query's logic, read other rows, or modify data.

## Fix: parameterized queries
Pass request values as bound parameters through the database driver or ORM. In Python DB-API drivers use placeholders such as `?` or `%s` and a separate parameter tuple; in SQLAlchemy use bound parameters or ORM filters. Never build the statement text from request values, even after escaping by hand.

## When identifiers must vary
Table names, column names, and sort directions cannot be bound parameters. Map the requested value to a fixed allowlist of known identifiers in code and reject anything else.

## Defense in depth
Run the application with a database account that has only the privileges it needs. Return generic errors to clients so database error messages do not reveal schema details. Validate the type and range of numeric identifiers before use.
