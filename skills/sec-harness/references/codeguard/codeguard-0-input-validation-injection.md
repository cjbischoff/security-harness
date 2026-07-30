---
rule_id: codeguard-0-input-validation-injection
description: Input validation & injection defense
languages: [python, javascript, typescript, php, go, java, ruby, sql]
always_apply: false
---
## Input validation & injection defense

- Use parameterized queries / prepared statements; never concatenate input into SQL/NoSQL/LDAP/SOQL.
- Run OS commands via an argument vector; never pass a shell string. Allowlist any command/arg from input.
- Validate at the trust boundary: type, length, format, range; reject by default.
