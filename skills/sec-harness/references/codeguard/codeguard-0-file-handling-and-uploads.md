---
rule_id: codeguard-0-file-handling-and-uploads
description: File handling & uploads
languages: [python, javascript, typescript, php, go, java]
always_apply: false
---
## File handling & uploads

- Canonicalize paths and confine to a base dir; reject ../ and absolute paths from input.
- Validate upload type/size; store outside the web root; never execute uploads.
- Stream large files; enforce quotas to avoid resource exhaustion.
