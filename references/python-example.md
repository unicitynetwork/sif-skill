# Runnable Python Guard example

Use [scripts/guard.py](../scripts/guard.py) when adding a synchronous,
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
| `SIF_BASE_URL` | Defaults to `https://sif.unicity.network`; origin only, no path/query/credentials |
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
credentials. Exit codes are `0` for permitted content, `1` for configuration or
verification failure, `2` for blocked content, and `3` for a flag requiring
application review. No downstream action occurs in this CLI. A flag is a valid
Guard decision; exit `3` represents the example's lack of a review handler, not
a service outage or a block verdict. Audit verification remains a separate
management step described in the skill.

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
`GuardBlocked`; degraded/malformed/non-2xx/network failures raise
`GuardUnavailable`. Catch these at the application boundary to show an error or
refusal, without invoking the original handler or falling back to unscreened
text. Errors raised by the next handler itself are not retried.

For `flag`, supply `on_flag=your_review_handler`. It receives the verdict,
must implement the application's agreed warning/review behavior, and must
return exactly `True` to continue. Omission, rejection, or any other return
value raises `GuardReviewRequired`. Do not add an unconditional `True` callback
just to make the example pass. Do not dump verdicts to logs: detections can
contain submitted content. `guard.screen(...)` exposes permitted `.content`,
`.request_id`, and `.action` when a callback-based next handler is inconvenient.

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
