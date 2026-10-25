---
classification: OFFICIAL_SENSITIVE
owner: Head of Security Architecture
---

# TRA agent: Solution Design (summary for self-assessment)

**OFFICIAL: Sensitive.** Summary of docs/design.md, written as the input to the
agent's own pre-pilot TRA. The full design is the authority.

## 1. Purpose

Security practitioners use the agent to draft threat and risk assessments from
solution designs. People approve at three gates; the agent never accepts risk.

## 2. Components

| Component | Description | Hosting |
|---|---|---|
| Practitioner | Security staff member, signed in with Entra ID and MFA | Corporate |
| Risk owner | Business owner who accepts risk at G3, with step-up authentication | Corporate |
| Orchestrator | Runs the workflow, enforces gates, writes state and audit. AgentCore Runtime or Foundry hosted agent | AWS or Azure, Sydney / Australia East |
| Specialist agents | Six agents (intake, system modeller, threat analyst, control mapper, risk assessor, quality critic). Each calls an LLM and the MCP servers | AWS or Azure |
| Reference MCP server | Read-only threat library, control catalogue and risk matrix | AWS or Azure |
| Artefacts MCP server | Reads solution designs from Git and Confluence with read-only credentials | AWS or Azure |
| Model provider | Claude on Bedrock (AU inference profile) or GPT on Foundry | AWS or Azure |
| State store | TRA records. S3 or Blob, KMS / customer-managed key | AWS or Azure |
| Audit log | Hash-chained events in an Object Lock / immutable container | AWS or Azure |
| Risk register | CSV export and eramba | SaaS |
| Artefact sources | Git repositories and Confluence spaces written by delivery teams | SaaS |

## 3. Data flows

1. Practitioner calls the orchestrator with a user token.
2. Orchestrator exchanges it for a delegation token per specialist (user as subject, orchestrator as actor) and calls each specialist over A2A or Invocations.
3. Specialists call MCP servers with their own delegation tokens.
4. Artefacts MCP server reads design documents from Git and Confluence; the text is wrapped as untrusted and sent to the model.
5. Specialists send prompts to the model provider and receive structured output, which code validates; ratings are calculated in code.
6. Orchestrator writes TRA state and audit events; specialists' audit events are ingested and re-chained.
7. At G3 the approved risks are exported to the risk register.

## 4. Security notes

- Every hop re-validates the token; MCP servers accept only listed callers.
- Classification ceiling is OFFICIAL: Sensitive; artefacts above it are refused.
- Gates: G2 needs two practitioners for Tier 1; G3 needs the risk owner with recent step-up.
- Model output is untrusted: schemas, retries, and code-calculated ratings.
- Prompts are versioned; prompt and model changes must pass the golden set.
