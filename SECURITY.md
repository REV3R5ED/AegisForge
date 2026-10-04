# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

AegisForge is a defensive-security tool; its safety posture matters.
If you find a security issue, please report it privately rather than
opening a public issue:

- Email the author directly (see GitHub profile REV3R5ED) with a
  description, reproduction steps, and the version affected.
- Allow a reasonable time for a fix before any public disclosure.

## Security-relevant design (v0.1)

- No `shell=True` anywhere; all subprocess calls use argument lists.
- All CLI targets are validated before use (no metacharacters, length
  caps); CIDR expansion is hard-capped at 65,536 addresses.
- Concurrency is bounded (ThreadPoolExecutor, default 20, max 50).
- Ping/traceroute timeouts are bounded; DNS lookups honor caller
  timeouts via worker threads.
- Every invocation writes an audit record (`~/.aegisforge/audit.log`),
  best effort.
- The tool never exfiltrates data: all output goes to stdout/files the
  operator chooses.

## License

AegisForge is open source under the MIT license (see LICENSE).
