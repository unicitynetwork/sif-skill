"""One-message Guard integration example. Python 3.9+, standard library only."""

import http.client
import ipaddress
import json
import math
import os
import ssl
import sys
from dataclasses import dataclass, field
from urllib.parse import urlsplit


class GuardUnavailable(Exception):
    """Verification failed; do not continue the protected operation."""

    def __init__(self, message, *, status=None, error_code=None, retry_after=None):
        super().__init__(message)
        self.status = status
        self.error_code = error_code
        self.retry_after = retry_after


class GuardBlocked(Exception):
    """SIF rejected the content."""


class GuardReviewRequired(Exception):
    """A flag needs the application's agreed review/warning behavior."""


@dataclass
class Screened:
    request_id: str
    action: str
    content: str = field(repr=False)


class GuardClient:
    def __init__(self, base_url, api_key, policy_id, *, timeout=10.0, allow_local_http=False,
                 return_detections=False):
        # policy_id=None deliberately selects class-bound operation.
        if isinstance(api_key, str):
            api_key = api_key.strip()
        if not isinstance(api_key, str) or not api_key or any(ord(c) < 32 for c in api_key):
            raise ValueError("A non-empty Guard API key is required")
        if policy_id is not None and (not isinstance(policy_id, str) or not policy_id.strip()):
            raise ValueError("A non-empty policy ID is required for caller-selected keys")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Guard timeout must be finite and positive")
        try:
            url = urlsplit(base_url)
            port = url.port
            valid_origin = (
                url.hostname and url.username is None and url.password is None
                and "?" not in base_url and "#" not in base_url
                and not any(ord(c) <= 32 for c in base_url)
            )
            local_http = False
            if url.scheme == "http" and allow_local_http:
                local_http = ipaddress.ip_address(url.hostname).is_loopback
            if not valid_origin or not (url.scheme == "https" or local_http):
                raise ValueError()
        except (ValueError, TypeError):
            raise ValueError("Use an HTTPS origin, or explicitly enabled literal-loopback HTTP") from None
        self.host = url.hostname
        self.port = port if port is not None else (443 if url.scheme == "https" else 80)
        self.secure = url.scheme == "https"
        self.endpoint = url.path.rstrip("/") + "/api/v1/guard"
        self.context = ssl.create_default_context() if self.secure else None
        self.return_detections = bool(return_detections)
        self.api_key = api_key
        self.policy_id = policy_id
        self.timeout = timeout

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        mode = env.get("SIF_KEY_MODE", "caller-selected")
        policy_id = env.get("SIF_POLICY_ID")
        if mode == "caller-selected":
            if not policy_id:
                raise ValueError("Set SIF_POLICY_ID for a caller-selected key")
        elif mode == "class-bound":
            if policy_id:
                raise ValueError("Unset SIF_POLICY_ID for a class-bound key")
            policy_id = None
        else:
            raise ValueError("SIF_KEY_MODE must be caller-selected or class-bound")
        try:
            timeout = float(env.get("SIF_TIMEOUT_SECONDS", "10"))
        except ValueError:
            raise ValueError("SIF_TIMEOUT_SECONDS must be a positive finite number") from None
        return cls(
            env.get("SIF_BASE_URL", "https://sif.unicity.network"),
            env.get("SIF_API_KEY", ""), policy_id, timeout=timeout,
            allow_local_http=env.get("SIF_ALLOW_LOCAL_HTTP") == "1",
        )

    def _request(self, text, role):
        payload = {"messages": [{"role": role, "content": text}],
                   "config": {"return_detections": self.return_detections}}
        if self.policy_id is not None:
            payload["policy_id"] = self.policy_id
        # http.client does not follow redirects or retry this POST. HTTPS uses
        # certificate and hostname verification; never disable either.
        if self.secure:
            connection = http.client.HTTPSConnection(
                self.host, self.port, timeout=self.timeout, context=self.context)
        else:
            connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            connection.request("POST", self.endpoint, body=json.dumps(payload).encode("utf-8"),
                               headers={"Content-Type": "application/json", "X-API-Key": self.api_key})
            response = connection.getresponse()
            body = response.read(1024 * 1024 + 1)
            if not 200 <= response.status < 300:
                code = None
                try:
                    error = json.loads(body) if len(body) <= 1024 * 1024 else {}
                    candidate = error.get("code") if isinstance(error, dict) else None
                    if isinstance(error, dict) and isinstance(error.get("error"), dict):
                        candidate = error["error"].get("code", candidate)
                    # Only retain recognized public codes, never arbitrary body text.
                    if candidate in ("PolicyRequired", "PolicyIsClassLed"):
                        code = candidate
                except (ValueError, UnicodeError):
                    pass
                retry_after = response.getheader("Retry-After")
                raise GuardUnavailable("Guard returned a non-2xx response; verification failed",
                                       status=response.status, error_code=code,
                                       retry_after=retry_after if isinstance(retry_after, str) else None)
            if len(body) > 1024 * 1024:
                raise GuardUnavailable("Guard response exceeds the 1 MiB limit")
            return json.loads(body.decode("utf-8"))
        except (OSError, http.client.HTTPException, ValueError):
            # Never echo response bodies, request text, URL credentials or raw errors.
            raise GuardUnavailable("Guard transport or JSON verification failed") from None
        finally:
            connection.close()

    def screen(self, text, *, role="user", on_flag=None, on_modify=None, on_degraded=None):
        """Return permitted text and decision metadata, or raise before any use.

        on_flag(verdict) must implement the agreed warning/review behavior and
        return exactly True to continue. An absent callback pauses flagged work.
        on_modify(verdict) must approve and validate replacement use; omission
        pauses modified work. on_degraded(verdict) explicitly authorizes degraded
        verification. Neither callback can override a block.
        """
        if role not in ("user", "assistant", "system", "tool") or not isinstance(text, str):
            raise ValueError("Screen one text message with a supported Guard role")
        result = self._request(text, role)
        if not isinstance(result, dict):
            raise GuardUnavailable("Guard response is not an object")
        action = result.get("action")
        request_id = result.get("request_id")
        if (action not in ("allow", "block", "modify", "flag")
                or not isinstance(request_id, str) or not request_id.strip()
                or type(result.get("blocked")) is not bool
                or ("degraded" in result and type(result["degraded"]) is not bool)):
            raise GuardUnavailable("Guard decision fields are missing or malformed")
        if result["blocked"] or action == "block":
            raise GuardBlocked("Guard blocked the protected operation")
        if result.get("degraded", False) and (on_degraded is None or on_degraded(result) is not True):
            raise GuardUnavailable("Guard reported degraded verification")
        if action == "modify":
            if not isinstance(result.get("modified_content"), str):
                raise GuardUnavailable("Guard did not return replacement text")
            if on_modify is None or on_modify(result) is not True:
                raise GuardReviewRequired("Guard modified content; application approval is required")
            text = result["modified_content"]
        if action == "flag" and (on_flag is None or on_flag(result) is not True):
            raise GuardReviewRequired("Guard flagged content; application review behavior is required")
        return Screened(request_id, action, text)

    def screen_then(self, text, next_handler, *, role="user", on_flag=None, on_modify=None,
                    on_degraded=None):
        """Call the next model/tool/output handler only after verification."""
        screened = self.screen(text, role=role, on_flag=on_flag, on_modify=on_modify,
                               on_degraded=on_degraded)
        return next_handler(screened.content)


def main():
    """Read text from stdin; print only decision metadata, never screened text."""
    try:
        client = GuardClient.from_env()
        screened = client.screen(sys.stdin.read(), role=os.environ.get("SIF_MESSAGE_ROLE", "user"),
                                 on_modify=lambda verdict: True)
        print(json.dumps({"request_id": screened.request_id, "action": screened.action}))
        return 4 if screened.action == "modify" else 0
    except GuardBlocked:
        print("Guard blocked the sample", file=sys.stderr)
        return 2
    except GuardReviewRequired:
        print("Guard sample requires application review", file=sys.stderr)
        return 3
    except (GuardUnavailable, ValueError):
        print("Guard verification failed; check configuration and service availability", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
