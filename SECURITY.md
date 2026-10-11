# Security policy

sentinel runs with elevated privileges (it reads `/etc/shadow` and other root-only files), so security reports matter.

## Reporting a vulnerability
Please **do not open a public issue**. Use GitHub's private vulnerability reporting ("Security" tab -> "Report a
vulnerability") or e-mail `TODO-add-security-contact@example.org`. Expect an acknowledgement within a few days.

## Scope and design decisions
- Audit checks only **read**; nothing on the audited system is modified (package checks use a simulated upgrade).
- The Docker setup mounts the host read-only. Root inside the container is required to read root-only files.
- Model files are NumPy arrays + JSON and are loaded with `allow_pickle=False` - no pickle, no code execution from a model file.
- The database may contain sensitive details (usernames, IPs, hashes' *types* - never hashes themselves). Protect it like a log.

## Authorized use only
Run sentinel only on systems you own or are explicitly authorized to assess.
