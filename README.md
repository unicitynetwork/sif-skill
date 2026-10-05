# SIF agent skill

An agent skill for integrating with Semantic Firewall (SIF) and creating,
testing, and managing tenant rules and policies.

The instructions are self-contained in [SKILL.md](SKILL.md). No plugin or SDK
installation is required. Your agent needs HTTP access to SIF.

## Setup

1. Download `SKILL.md` and install it in your agent's supported skills location,
   or explicitly ask the agent to read and follow the file.
2. Provide the credentials for your organization through a private configuration
   file, environment variables, or your agent's secret store:

   - `SIF_ORGANIZATION`: your organization slug.
   - `SIF_USERNAME` and `SIF_PASSWORD`: a dedicated Operator account for
     managing rules and policies.
   - `SIF_API_KEY`: a Guard key for screening content.
   - `SIF_POLICY_ID`: the policy string ID for a caller-selected Guard key.

3. Ask the agent to connect, verify its tenant, and perform the requested task.

The default API base URL is `https://sif.unicity.network`. Set `SIF_BASE_URL`
to use another deployment. Credentials must match the selected deployment.

Management credentials and Guard keys serve different purposes; provide only
what the task needs. The skill explains how to obtain a Guard key when
authorized. Never put credentials in this repository or in the skill file.

## Example requests

- "Use SIF to create and test an isolated policy that blocks mention of
  Project Falcon. Leave the existing default policy unchanged."
- "Add SIF screening to this application's user input and tool results, and
  verify that blocked content never reaches the model."
- "Check this text with the configured SIF policy and explain the verdict."

Loading the skill does not automatically intercept agent traffic. Screening
requires an explicit Guard call, and an application integration must apply the
returned decision.
