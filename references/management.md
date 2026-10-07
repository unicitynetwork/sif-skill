# Manage SIF rules, policies, and credentials

Read this reference only when the task needs management authentication, audit
verification, key metadata/provisioning, or rule/policy authoring. For content
screening with an existing Guard key, follow [SKILL.md](../SKILL.md) without
requesting a management password. Connection and secret-handling requirements
in that file apply here too.

Obtain `SIF_ORGANIZATION` (the tenant slug; never assume `default`) and a
dedicated Operator's `SIF_USERNAME`/`SIF_PASSWORD` from private configuration.
An existing authorized Operator session can replace password login. Read the
session's actual capabilities; a role name alone does not prove authorization.

### Management login

`POST /manage/auth/login`, JSON body:

```json
{"organization":"<tenant slug>","username":"<operator username>","password":"<private password>"}
```

The response contains `access_token`, `refresh_token`, and `expires_at`.
Use `Authorization: Bearer <access_token>` for management calls. Immediately
call `GET /manage/auth/me` and verify `organization` equals the requested tenant
and the session has the capabilities required for the task before any write.

Access tokens last 15 minutes. `POST /manage/auth/refresh` accepts
`{"refresh_token":"<private refresh token>"}` and returns a replacement pair;
replace the old refresh token, which is revoked. Refresh tokens last 30 days.
For a short task, logging in once is sufficient. On `401`, refresh or log in
again once; on `403`, stop and report the missing permission. If enforced SSO
refuses password login, request an approved authenticated session; do not use
an administrator's break-glass account as an automation workaround.

## Author and test a rule or policy

A rule defines a detection pattern and score. A ruleset is an ordered group of
rules. A policy selects ordered rulesets and determines the resulting verdict
through its detector settings, thresholds and rollout mode.

Server code defaults are flag at `0.6`, modify at `0.7`, and block at `0.9`.
Deployments and policies can override them; read the actual policy or set all
three explicitly. A block test must reach the effective block threshold in
enforce mode. Verify the complete verdict rather than assuming a rule's score
alone guarantees blocking.

Read the existing configuration before changing it. Creation of a separate
custom ruleset/non-default policy is the preferred starting point. Get explicit
user approval before editing shared/live rules, changing an existing live
policy, switching the tenant default, or changing production key bindings.
The user's request to create and test an isolated policy authorizes that work,
not a replacement of their default protection.

Important: SIF can auto-publish policy content changes. Rule edits can affect
attached live policies on reload without a separate publish. Do not promise
that every write is an inert draft. A policy-version rollback also does not
restore previous rule definitions or ruleset membership.

### Relevant management endpoints

All paths below are relative to `SIF_BASE_URL` and use the management token.
`{id}`, `{ruleset_uuid}`, and `{policy_uuid}` are response `id` UUIDs, not
the human-readable `rule_id`, `ruleset_id`, or `policy_id` strings.

| Method and path | Use |
|---|---|
| `GET /manage/rulesets` | List rulesets, including built-ins |
| `POST /manage/rulesets` | Create a custom ruleset |
| `GET /manage/rulesets/{ruleset_uuid}/rules` | Read rules held by a ruleset |
| `GET /manage/rulesets/{ruleset_uuid}/policies` | Identify policies affected by changing a ruleset or its rules |
| `POST /manage/rulesets/{ruleset_uuid}/rules` | Create a rule in a custom ruleset |
| `GET /manage/rules/{id}` / `PATCH /manage/rules/{id}` | Read or update a rule |
| `POST /manage/rules/{id}/test` | Test this rule's pattern with `{"content":"..."}`; check `evaluated` and `matched` |
| `POST /manage/policies/validate-pattern` | Validate `match_spec` and `score` before saving; HTTP 200 can contain `valid: false` |
| `GET /manage/policies` / `GET /manage/policies/{policy_uuid}` | Read policies and published/latest versions |
| `POST /manage/policies` / `PATCH /manage/policies/{policy_uuid}` | Create or edit policy configuration |
| `GET /manage/policies/{policy_uuid}/rulesets` | Read policy attachments |
| `PUT /manage/policies/{policy_uuid}/rulesets` | Replace attachments with `{"ruleset_ids":["<UUID>","..."]}` |
| `GET /manage/policies/{policy_uuid}/flattened` | Inspect resolved rules |
| `GET /manage/policies/{policy_uuid}/versions` | Read version history |
| `POST /manage/policies/{policy_uuid}/publish` | Publish an exact version with `{"version":2}` |
| `POST /manage/guard/preview` | Test an exact policy version without a Guard key |
| `GET /manage/detectors` | Discover supported detectors; distinguish loaded from publishable IDs |
| `GET /manage/api-keys` | Inspect key metadata/class bindings; existing secrets are not returned |
| `POST /manage/api-keys` | Mint a Guard key only when requested; save the returned `api_key` privately, shown once |
| `POST /manage/api-keys/{id}/revoke` | Revoke a disposable test key using its UUID; no request body |
| `GET /manage/audit/by-request/{request_id}` | Confirm the saved decision for a live Guard request |

Policies select rulesets explicitly. Membership `PUT` operations replace the
whole list; read and preserve existing entries unless removal was requested.
Built-in content is not editable: create your own ruleset and rules instead.
Rule IDs are tenant-unique, and a rule may be shared by several rulesets.
When adding protection to an existing application, preserve its current
policy settings and ordered ruleset selection in a new policy, then append
the custom ruleset. Read the existing settings/attachments rather than
assuming server defaults. The rule-only example below intentionally isolates
one matcher; do not use it as a replacement for the application's existing
protections. Preview the complete combined policy as well as the rule alone.
After an uncertain write result, read the resource/list to reconcile it before
retrying; do not create duplicates or guess that nothing was saved.

### Minimal isolated example

Use unique IDs, not the literal example IDs if they already exist. These
requests demonstrate one rule, not a replacement for the tenant's full policy.

1. Validate the intended pattern using `/manage/policies/validate-pattern`:

```json
{"match_spec":{"type":"regex","patterns":["ONBOARDING_BLOCK_MARKER"],"case_insensitive":false},"score":1.0}
```

2. Create a ruleset:

```json
{"ruleset_id":"onboarding-demo","version":"1.0.0","description":"Isolated SIF example","enabled":true}
```

3. Create a rule under the returned ruleset UUID:

```json
{
  "rule_id":"onboarding-marker",
  "name":"Detect onboarding marker",
  "category":"custom",
  "severity":"high",
  "enabled":true,
  "match_spec":{"type":"regex","patterns":["ONBOARDING_BLOCK_MARKER"],"case_insensitive":false},
  "score":1.0
}
```

Test both the marker and benign text with the rule-test endpoint. Keywords are
also supported, for example
`{"type":"keywords","keywords":["secret phrase"],"mode":"any","case_insensitive":true}`.
Regex patterns use Rust regex syntax, not PCRE: look-around and backreferences
are unsupported. JSON requires escaped backslashes. Do not create
`semantic_similarity` rules: the current engine rejects them because no
embedding evaluator is available. Use supported regex/keyword matching, or
inspect the registered models before choosing an `ml_model` rule.
A rule's score/category
feeds SIF policy decisions; configure the policy's thresholds rather than
assuming every matching rule automatically blocks content.

4. Create a non-default policy that runs only this ruleset's rule engine:

```json
{
  "policy_id":"onboarding-demo",
  "name":"Onboarding demo",
  "fail_mode":"closed",
  "mode":"monitor",
  "is_default":false,
  "ruleset_ids":["<returned ruleset UUID>"],
  "stages":[{"detectors":["rule_engine"]}],
  "flag_threshold":0.3,
  "modify_threshold":0.6,
  "block_threshold":0.9,
  "capture":"off"
}
```

`fail_mode` (`open`/`closed`) is error handling. `mode`
(`off`/`monitor`/`enforce`) is rollout behavior. Monitor mode is not evidence
that a matching request will be blocked: it permits traffic.
On the wire, monitored matches are `flag` with `reason.escalation: "monitored"`.
The Python helper pauses flags by default, so a monitor rollout must supply
an explicit `on_flag` handler that records a metadata-only event and returns
`True` for monitored flags. See [the wiring example](python-example.md).

5. PATCH this new policy with `{"mode":"enforce"}` to stage an enforcing
version. Read `latest_version`, then preview that exact version:

```json
{"policy_id":"onboarding-demo","policy_version":2,"content":"ONBOARDING_BLOCK_MARKER","message_role":"user"}
```

Use the actual returned version, not a guessed `2`. The preview response has
`policy` (including version, state, mode and hashes) and `verdict` (the Guard
decision). Check both. Preview the benign example too. Preview does not publish
the draft, and rules are evaluated against the current corpus, not historical
rule bodies frozen by that version. Respect `429`/`Retry-After`. If a recent
edit has not reached the runtime, retry read/preview checks for at most 30
seconds; report failure instead of accepting an unexpected result.

If preview is unavailable in the deployment, stop and report that limitation.
Do not publish to the default policy as a testing workaround.

6. When rollout of this isolated policy is requested, publish the verified
exact version. Re-read `published_version` and `effective_mode`. Do not make
it default or change existing key/class assignments without approval.

For an explicitly requested caller-selected test key, a minimal creation body
is `{"name":"onboarding-test","permissions":["guard"],"agent_class_ids":[],"rate_limit_rpm":60}`.
Set an appropriate `expires_at` RFC3339 timestamp for disposable testing. Store
the returned secret privately, then run the same positive/negative samples
through `/api/v1/guard` with this policy ID. Live Guard checks are real screened
requests, unlike preview.

## Finish the task

Report the organization, resource string IDs/UUIDs, policy version/mode,
positive and negative results, audit verification, and any integration files
changed. State whether you only previewed a draft or verified the live Guard
path. Never include secrets. Do not silently delete requested resources; offer cleanup
of disposable test resources, revoke disposable keys, and leave an actionable
error if any check failed. Do not claim success from HTTP status alone.
