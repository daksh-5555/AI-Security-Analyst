# Preventing cross-site scripting

## Why it happens
Cross-site scripting (XSS) occurs when a page includes request-controlled text without encoding it for the place where it appears. The browser then interprets the text as markup or script and runs it with the site's privileges.

## Fix: context-aware output encoding
Encode data for its output context: HTML-escape text placed in element content, attribute-encode values placed in quoted attributes, and use JSON serialization rather than string building for values placed in scripts. Prefer a template engine with automatic escaping enabled and do not mark untrusted text as safe.

## Avoid dangerous sinks
Do not insert untrusted text into inline event handlers, `javascript:` URLs, or script blocks. In client code, set `textContent` instead of `innerHTML`. If rich HTML is required, sanitize it with a maintained allowlist sanitizer.

## Defense in depth
Send a restrictive Content-Security-Policy that disallows inline script, set cookies HttpOnly where possible, and validate input formats early. These reduce impact but do not replace encoding.
