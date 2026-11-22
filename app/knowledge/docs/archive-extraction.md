# Extracting archives safely

## Why it matters
Archive entries can contain paths with `../` or absolute paths that write outside the destination ("zip slip"), symbolic links that redirect later writes, and highly compressed content that exhausts disk or memory.

## Fix: validate every entry
Before extracting an entry, resolve its destination path and confirm it is inside the target directory. Reject absolute paths, links, and device files. In Python 3.12 and later, use the tarfile `data` extraction filter.

## Bound resource use
Limit the number of entries, the total uncompressed size, and the compression ratio, and stop extraction when a limit is reached.
