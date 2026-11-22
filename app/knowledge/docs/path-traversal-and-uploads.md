# Preventing path traversal and unsafe file handling

## Why it happens
Path traversal occurs when request text is used to build a file path. Sequences such as `../`, absolute paths, or symbolic links can escape the intended directory and read, overwrite, or delete other files.

## Fix: resolve and contain
Map user input to a server-chosen identifier when possible. Otherwise join it to a fixed base directory, resolve the result to a canonical path, and verify it is still inside the base directory before opening it. Reject absolute paths and null bytes.

## Uploads
Generate stored file names on the server, store uploads outside the web root, enforce size limits, and validate the content type by inspecting the file rather than trusting the client-supplied name or header.

## Defense in depth
Run the application with file-system permissions limited to the directories it needs.
