# Verifying fixes and retesting findings

## Confirm the fix
After changing the code, re-run the same analysis that produced the finding. A fixed issue is reported as not reproduced only when the check that found it completed; a skipped or failed check is not evidence of a fix.

## Add a regression test
Write a test that exercises the vulnerable input path with a harmless probe value and asserts the safe behaviour, so the issue cannot silently return.

## Static versus runtime evidence
Static findings show a possible data flow and have not been exploited. Confirm exploitability with an authorized runtime check where one exists, and keep the static finding until the flow itself is removed or proven safe.
