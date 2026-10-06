# SIF agent skill

An agent skill for integrating with Semantic Firewall (SIF) and creating,
testing, and managing tenant rules and policies.

Start with [SKILL.md](SKILL.md). It covers content screening and links to
management instructions when needed. No plugin or SDK installation is required;
your agent needs HTTP access to an existing SIF deployment.

## Setup

1. Clone/download this repository and install the whole folder as `sif` in your
   agent's supported skills location, preserving `references/` and `scripts/`.
   Alternatively, ask the agent to read `SKILL.md` in the checkout. Installing
   only `SKILL.md` omits the linked management guide and runnable example.
2. Provide the credentials for your organization through a private configuration
   file, environment variables, or your agent's secret store:

   - `SIF_API_KEY`: a Guard key for screening content.
   - `SIF_POLICY_ID`: the policy string ID for a caller-selected Guard key.
     Omit it for a class-bound key.
   - Only for management tasks: `SIF_ORGANIZATION` (tenant slug), and
     `SIF_USERNAME`/`SIF_PASSWORD` for a dedicated Operator account or an
     existing authorized session.

3. Ask the agent to connect and test the requested screening points. Management
   tasks additionally verify tenant identity and capabilities before writes.

The default API base URL is `https://sif.unicity.network`. Set `SIF_BASE_URL`
to use another deployment. Credentials must match the selected deployment.

Management credentials and Guard keys serve different purposes; provide only
what the task needs. The skill explains how to obtain a Guard key when
authorized. Never put credentials in this repository or in the skill file.

## Runnable integration example

The [Python example guide](references/python-example.md) covers the
standard-library client, environment configuration, downstream handlers,
local development, and offline tests. Python 3.9+ is required only for the
example, not for using the skill's HTTP instructions in another language.

With the environment configured, run from this repository's root:

```sh
printf '%s' 'Synthetic onboarding sample' | python3 -B scripts/guard.py
python3 -B -m unittest discover -s tests -v
```

The first command makes a live Guard request; the second runs offline tests.
For class-bound keys, set the example's `SIF_KEY_MODE=class-bound` and unset
`SIF_POLICY_ID`. Remote deployments require HTTPS; local loopback HTTP requires
the explicit opt-in described in the example guide.

See [compatibility and prerequisites](SKILL.md#compatibility-and-deployment-prerequisites)
for the SIF source baseline and required deployment features. Source review and
offline example tests do not establish compatibility with a live deployment.

## Example requests

- "Use SIF to create and test an isolated policy that blocks mention of
  Project Falcon. Leave the existing default policy unchanged."
- "Add SIF screening to this application's user input and tool results, and
  verify that blocked content never reaches the model."
- "Check this text with the configured SIF policy and explain the verdict."

Loading the skill does not automatically intercept agent traffic. Screening
requires an explicit Guard call, and an application integration must apply the
returned decision.
