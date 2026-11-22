# Fixing vulnerable dependencies

## Why it matters
A known vulnerability in a third-party package can affect the application whenever the vulnerable code path is reachable. Advisories list the affected versions and, when available, the first fixed version.

## Fix: upgrade to a fixed version
Upgrade the package to a version outside every affected range, update the lock file, and run the test suite. Prefer the smallest upgrade that fixes the advisory when a major-version change is risky.

## When no fix exists
Check whether the vulnerable feature is used. If it is, consider replacing the package, disabling the feature, or adding a compensating control, and record the decision with a review date.

## Keep it current
Pin exact versions in lock files so results are reproducible, re-run the audit regularly because new advisories appear for old versions, and treat advisory data that could not be fetched as unknown rather than clean.
