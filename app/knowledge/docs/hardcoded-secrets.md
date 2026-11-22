# Removing credentials from source code

## Why it matters
Credentials committed to a repository are exposed to everyone who can read it, including forks, backups, and build logs. Removing the line in a later commit does not remove it from history.

## Fix: rotate first, then remove
Treat any committed credential as compromised. Revoke or rotate it with the issuing service first, then remove it from the code. Check the service's access logs for use of the old value.

## Load secrets at runtime
Read credentials from the environment or a secrets manager at startup, and keep local development values in an untracked file that is listed in the ignore file. Provide a template file with placeholders only.

## Prevent recurrence
Run secret scanning in pre-commit hooks and in continuous integration. If the value must be purged from history, rewrite history with a dedicated tool and coordinate with everyone who has a clone; rotation is still required.
