# Runnable Python Guard example

For Python integrations, first consider SIF's
[Python SDK](https://github.com/unicitynetwork/sif/tree/335c8525c61b3f8a3276096907d87a83bf549b29/sdk-wrappers/python).
Apply the complete Guard verdict rather than relying on a convenience flag
predicate: the SDK's `is_flagged` also includes `modify`.
Use [scripts/guard.py](../scripts/guard.py) as the dependency-free fallback for a synchronous,
one-message screening point to a Python application. It uses Python 3.9+ and
only the standard library. It is an integration example, not an SDK or a
background interceptor. Async applications should adapt the transport or run
the blocking call outside their event loop.

## Run a synthetic check

Run commands from the installed skill folder or repository root. Supply secrets
through the process environment or an approved secret store; do not paste keys
into shell commands, chat, or tracked files.

| Variable | Example behavior |
|---|---|
| `SIF_API_KEY` | Required Guard secret; never a management session token |
| `SIF_BASE_URL` | Defaults to `https://sif.unicity.network`; optional proxy path prefix, no query/fragment/credentials |
| `SIF_KEY_MODE` | Client option: `caller-selected` (default) or `class-bound` |
| `SIF_POLICY_ID` | Required for caller-selected; unset for class-bound |
| `SIF_TIMEOUT_SECONDS` | Client socket timeout, default `10`; must be finite and positive |
| `SIF_MESSAGE_ROLE` | CLI role, default `user`; also accepts `assistant`, `system`, `tool` |
| `SIF_ALLOW_LOCAL_HTTP` | Client option: `1` permits literal-loopback HTTP only |

Set the timeout for the selected policy and application latency budget. This
is a socket-operation timeout, not an end-to-end application deadline. The
helper does not retry a POST or follow redirects. A missing policy ID never
silently changes the key mode. The helper checks the decision fields it uses
and tolerates additional response fields.

With the environment configured:

```sh
printf '%s' 'Synthetic onboarding sample' | python3 -B scripts/guard.py
```

The CLI sends a real Guard request. On `allow` or valid `modify`, stdout contains
only `request_id` and `action`; it never prints content, replacement text, or
credentials. Exit codes are `0` for unchanged allowed content, `4` for modified
content (the original must not be forwarded), `1` for configuration or
verification failure, `2` for blocked content, and `3` for a flag requiring
application review. No downstream action occurs in this CLI. A flag is a valid
Guard decision; exit `3` represents the example's lack of a review handler, not
a service outage or a block verdict. Audit verification remains a separate
management step described in the skill.

Do not gate forwarding the original text on exit `4`. Use the Python API to
approve and consume replacements. The CLI only reports that a valid replacement
exists; it performs no forwarding.

For a local semanticd instance, explicitly set `SIF_BASE_URL` to
`http://127.0.0.1:<configured-port>` or `http://[::1]:<configured-port>` and set
`SIF_ALLOW_LOCAL_HTTP=1`. Use development credentials and synthetic content.
The example rejects HTTP hostnames (including `localhost`) and remote HTTP;
use a literal loopback address. Remote deployments require HTTPS with normal
certificate verification. The example does not install or start semanticd.

## Put verification before the next handler

Copy/adapt the helper into the application's server-side code, or run this
import from the repository root:

```python
from scripts.guard import GuardClient

guard = GuardClient.from_env()

def send_user_message(text, model_handler):
    return guard.screen_then(text, model_handler, role="user")

def add_tool_result(text, context_handler):
    return guard.screen_then(text, context_handler, role="tool")

def display_model_output(text, output_handler):
    return guard.screen_then(text, output_handler, role="assistant")
```

Each next handler receives exactly one string: the original on `allow`, or
`modified_content` on `modify` (an empty replacement is valid). A block raises
`GuardBlocked`, including degraded fail-closed blocks; other degraded/malformed/non-2xx/network failures raise
`GuardUnavailable`. Catch these at the application boundary to show an error or
refusal, without invoking the original handler or falling back to unscreened
text. Errors raised by the next handler itself are not retried.

By default `modify` also raises `GuardReviewRequired`. Supply
`on_modify=your_replacement_validator`; it receives the verdict and must return
exactly `True` before the replacement is forwarded. For plain text, explicitly
approve redaction when appropriate. For tool calls, parse `modified_content`,
validate schema and permissions, and execute only those validated arguments.
Never approve arbitrary tool replacements unconditionally.

SIF replacements collapse whitespace runs (including newlines) to one space,
trim surrounding whitespace, and strip zero-width characters. A redacted YAML
document, Python program, or Markdown table may therefore lose its structure.
Do not consume replacements as whitespace-sensitive source or structured data
without validation.

To honor an explicitly authorized fail-open policy, supply `on_degraded`;
it receives the verdict and must return exactly `True`. Blocks are always
honored before this callback, and normal flag/modify approval is still required.
`GuardUnavailable.status` preserves HTTP status. `.error_code` retains recognized
`PolicyRequired` / `PolicyIsClassLed` codes, and `.retry_after` retains the
`Retry-After` header. No response body is included in the exception. Respect
rate limits without automatically replaying a POST.

Detections are off by default; set `return_detections=True` on `GuardClient`
only when required. Responses are limited to 1 MiB. The TLS context is reused,
but each request uses a fresh connection and handshake.

For `flag`, supply `on_flag=your_review_handler`. It receives the verdict,
must implement the application's agreed warning/review behavior, and must
return exactly `True` to continue. Omission, rejection, or any other return
value raises `GuardReviewRequired`. Do not add an unconditional `True` callback
just to make the example pass. Do not dump verdicts to logs: detections can
contain submitted content. `guard.screen(...)` exposes permitted `.content`,
`.request_id`, and `.action` when a callback-based next handler is inconvenient.

Monitor mode returns `flag` with `reason.escalation == "monitored"`. The helper
still requires an explicit handler. For an approved monitor rollout:

```python
def on_monitor_flag(verdict):
    reason = verdict.get("reason")
    if not isinstance(reason, dict) or reason.get("escalation") != "monitored":
        return False
    record_monitor_event(verdict["request_id"])  # Your metadata-only audit hook.
    return True

def send_monitored_message(text, model_handler):
    return guard.screen_then(text, model_handler, on_flag=on_monitor_flag)
```

Ordinary flags still pause; do not use a blanket approval callback.

One message per request avoids pretending that SIF's combined replacement is
a role-preserving list of messages. The helper does not parse modified tool
arguments or implement streaming. Follow the tool-call validation and buffering
guidance in [SKILL.md](../SKILL.md) before wiring those paths.

## Verify offline, then verify the actual application

```sh
python3 -B -m unittest discover -s tests -v
```

These tests use fake responses and a local HTTP stub, never a live SIF service
or real credentials. They check that permitted content reaches the next handler
and that blocked, degraded, malformed, unavailable, and unhandled flagged
results do not; they also cover policy selection, replacement content, timeouts,
redirect refusal, and local HTTP configuration.

This does not prove that an application's real model/tool/output handlers are
gated. Add equivalent tests at its actual screening points, including tool
side effects and streaming output where applicable. Then run the configured
policy's known positive/negative samples against the target deployment and
check live audit records when authorized.
