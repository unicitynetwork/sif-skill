# Guard review fixes implementation plan

**Goal:** Address all fourteen comments on PR #1 while retaining a dependency-free, fail-safe example.

**Architecture:** Keep the one-message helper. Make exceptional forwarding explicit through callbacks and preserve sanitized transport metadata.

**Tech Stack:** Python 3.9+, unittest, Markdown.

**Spec:** https://github.com/unicitynetwork/sif-skill/pull/1 (MastaP review and fourteen inline comments).

## Tasks

- [x] Add regression tests for modify exit 4, modification approval, monitor flags, degraded blocks and explicit degraded approval.
- [x] Fix transport defaults, prefix paths, key whitespace, TLS-context reuse, opt-in detections, bounded responses and sanitized HTTP status/error metadata.
- [x] Add a regular scripts package and strengthen HTTP/HTTPS selection tests.
- [x] Update SDK-first guidance, normalization warnings, callbacks, monitor rollout and CLI documentation.
- [x] Run offline tests, syntax and Markdown-link checks, and diff checks.

## Constraints and review focus

Never forward originals after modify; tool modifications require review and validation. No automatic retries or redirects. No sensitive response content in exceptions or CLI output. Check IPv6 default ports, malformed error bodies, callback rejection, and fail-closed precedence.
