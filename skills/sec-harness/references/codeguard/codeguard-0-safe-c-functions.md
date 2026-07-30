---
rule_id: codeguard-0-safe-c-functions
description: Safe C/C++ functions
languages: [c, cpp]
always_apply: false
---
## Safe C/C++ functions

- Avoid strcpy/strcat/sprintf/gets/scanf; use bounded variants (strncpy/snprintf) with correct sizes.
- Check all lengths; beware off-by-one and integer/precedence errors in size math.
- Validate lengths from the wire before copying into fixed buffers.
