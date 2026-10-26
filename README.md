# TRA agent: platform-neutral core

A multi-agent service that drafts threat and risk assessments (TRAs) from design artefacts, for security practitioners to review. It follows ISO/IEC 27005, uses STRIDE per element with MITRE ATT&CK techniques, plus MITRE ATLAS for AI components, rates risk on the [SAR 5x5 matrix](../docs/03-risk-methodology.md) with AUD thresholds, and maps controls to ISO 27001:2022, the ASD Essential Eight (ML2), the ISM and PCI DSS v4.0.1.

The agent drafts; people decide. Every TRA stops at three human gates, and only a human can pass them:

| Gate | After stage | Who | Policy enforced in code |
|---|---|---|---|
| G1 | Intake | Practitioner | Human identity, role, clearance at or above the TRA's classification; the practitioner confirms the tier factors, which replace the model's proposal |
| G2 | Evaluation | Practitioner | As G1; Tier 1 needs two different practitioners on the same TRA version; no blocker issues, and open major issues need `approve_with_changes` |
| G3 | Acceptance | Risk owner, plus CISO if any residual risk is High or Critical | As G1, plus phishing-resistant MFA within the last 10 minutes; each accepter is a different person |

The core (`tra_core`) runs on a workstation. The platform adapters (`tra_platform`) run the same code on Amazon Bedrock AgentCore in Sydney or Microsoft Foundry in Australia East: see the [build guide](docs/build-guide.md).

## Quick start (offline, no cloud account)

The repo includes a fictional design ([examples/artefacts/payments-portal-design.md](examples/artefacts/payments-portal-design.md)) and recorded model output, so you can run the whole lifecycle without credentials.

```bash
cd tra-agent
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q

R=tests/fixtures/replay_payments.json
tra-agent --replay $R new --title "Customer payments portal" \
  --artefact git:payments-portal-design.md --git-root examples/artefacts --user alice
tra-agent show TRA-2026-001   # the intake's proposed tier factors
tra-agent --replay $R gate TRA-2026-001 G1 approve --user alice --rationale "Scope confirmed" \
  --internet-facing yes --cardholder-data yes --shared-platform no
tra-agent --replay $R gate TRA-2026-001 G2 approve_with_changes --user alice --rationale "Reviewed; gateway flows to add"
tra-agent --replay $R gate TRA-2026-001 G2 approve_with_changes --user bob --rationale "Second review"
tra-agent --replay $R gate TRA-2026-001 G3 approve --user carol --role risk_owner --strong-auth \
  --rationale "Accept treatment plan"
tra-agent --replay $R gate TRA-2026-001 G3 approve --user dana --role ciso --strong-auth \
  --rationale "Concur: R-01 is Critical"
tra-agent report TRA-2026-001 --out out/
tra-agent verify-audit
```

`out/` then holds the TRA report (Markdown with a Mermaid DFD), the TRA as JSON, and the risk register in the SAR CSV format. The example design hides an instruction telling "automated reviewers" to rate everything Low; the quality critic flags it.

## Running with real models

Edit [config/models.yaml](config/models.yaml), then drop `--replay`:

- **Claude on Bedrock (default).** Uses the AU geographic inference profiles, which route only between Sydney and Melbourne. Needs `pip install -e ".[aws]"` and AWS credentials with `bedrock:InvokeModel` on those profiles.
- **GPT on Azure.** Set the Foundry endpoint and a regional deployment in Australia East. Needs `pip install -e ".[azure]"` and an Entra ID identity with the Cognitive Services User role. Claude on Foundry is Global or US Data Zone only, so don't route classified work to it.

Each agent can use a different model; for example, run the quality critic on GPT for model diversity.

## How it fits together

```
tra_core/
  schemas.py        TRA, system model, threats, controls, risks (Pydantic)
  risk.py           SAR 5x5 matrix, modifiers, AUD impact scale, tiering, acceptance authority
  classification.py PSPF labels: OFFICIAL: Sensitive max, label propagation, TRA floor
  stride.py         STRIDE-per-element applicability
  checks.py         deterministic checks run on every agent output and before each gate
  identity.py       Principal: human or workload acting for a human (built from validated tokens)
  gates.py          G1/G2/G3 policy
  workflow.py       stage machine
  audit.py          append-only, hash-chained audit log
  llm.py            ModelClient: Bedrock Converse, Azure OpenAI, replay; per-agent routing
  tools.py          read-only tools; local and MCP clients
  mcp_servers.py    MCP servers: reference (threats, controls) and artefacts (Git, Confluence)
  artefacts.py      Git and Confluence sources; refuse unlabelled or PROTECTED material
  agents/           six specialists and their prompts
  orchestrator.py   runs stages, calls specialists through an Invoker, stops at gates
  register.py       SAR CSV register (an Eramba writer can replace it)
  report.py         Markdown report and Mermaid DFD
  data/             threat library, control crosswalk and pinned ATT&CK, ATLAS and ISM indexes (versioned YAML)
```

Design choices worth knowing:

- **Models never choose tools.** Each specialist calls the tools it needs in code and passes the results to its model. A prompt injection can't make an agent call something it wasn't going to call, and every tool call is logged.
- **Models never produce ratings.** They propose likelihood and impact with a rationale and citations; code computes the rating, applies the classification impact floor and checks that residual is not above inherent.
- **Artefacts are untrusted.** Their text is wrapped in `<artefact>` tags with an instruction never to follow it, and must carry a PSPF label to be read at all.
- **Invalid output is retried, then fails.** Schema and domain errors go back to the model up to three times; after that the stage fails rather than passing on bad data.
- **Specialists are A2A-ready.** Each takes a JSON `SpecialistRequest` and returns JSON, so the platform adapters host them behind A2A (AgentCore) or Invocations (Foundry) endpoints without code changes.

## Deploying: AgentCore and Foundry

```
tra_platform/
  auth.py        token validation, claims to Principal, delegation tokens (RFC 8693, Entra OBO)
  host.py        SpecialistHost (in the specialist) and RemoteInvoker (in the orchestrator)
  a2a.py         A2A v1.0 JSON-RPC server per specialist, and the A2A client transport
  mcp.py         MCP servers over streamable HTTP with per-user clearance; routed MCP client
  service.py     the orchestrator as a JSON service: create, decide, get, report
  storage.py     S3, Azure Blob and local backends; write-once audit objects
  federation.py  AWS to Entra and Entra to AWS workload federation (no stored secrets)
  agentcore.py   AgentCore Runtime entrypoints (HTTP, A2A, MCP)
  foundry.py     Foundry hosted-agent entrypoints (Invocations) and transport
infra/aws/       CDK stack: VPC, KMS, S3 with Object Lock, nine AgentCore runtimes
infra/azure/     Bicep: VNet-injected Foundry, private storage, ACR, MCP in Container Apps; agent deploy script
```

Every service-to-service call carries a token for exactly one audience, naming the user as subject and the caller as actor, and every container checks it even where the platform already has. Specialists return their audit events with their results and the orchestrator appends them to the one hash chain, which lands in write-once storage. The [build guide](docs/build-guide.md) covers Entra setup, both deployments, and what to verify before production.

## Evaluation and assurance

Every change is gated in CI by the unit, platform and [red-team tests](tests/redteam/README.md), a golden set of five designs scored for threat, element, risk and critique recall, a dependency audit, IaC checks, and an image scan with an SBOM. Images built on main are signed with cosign. Run the golden set yourself with:

```bash
tra-eval --replay-dir eval/replays          # offline, recorded model output
tra-eval --models config/models.yaml --repeat 3   # live Bedrock models
```

[Build guide section 8](docs/build-guide.md#8-evaluation-red-team-tests-and-ci) explains the cases, thresholds and workflows.

## Reference data

- [threat_library.yaml](src/tra_core/data/threat_library.yaml): 40 threats across identity, data, application, delivery, supply chain, FOCI, post-quantum cryptography and AI/agents, each with a default risk category, with MITRE ATT&CK Enterprise v20.0 technique IDs, MITRE ATLAS v5.6.0 IDs for AI threats, and links to SAR delivery-lifecycle IDs.
- [controls.yaml](src/tra_core/data/controls.yaml): 39 common controls crosswalked to ISO 27001:2022, Essential Eight, the ISM (September 2026, OFFICIAL: Sensitive baseline), PCI DSS v4.0.1 and, where a direction applies, the PSPF. The ASD Essentials column is ready for the successor baseline (expected around Q2 2027). Have the control owner verify the mappings before relying on them.
- [risk_taxonomy.yaml](src/tra_core/data/risk_taxonomy.yaml): the two-level cyber risk taxonomy every risk is filed under ([risk methodology 3.7](../docs/03-risk-methodology.md#37-cyber-risk-taxonomy)). Software development, supply chain, FOCI and cryptography are always considered: the critic flags a TRA with no risk in one.
- `attack.yaml`, `atlas.yaml`, `ism.yaml`: the framework releases the checks validate IDs against. Regenerate them with `scripts/refresh_frameworks.py` ([build guide section 9](docs/build-guide.md#keeping-the-frameworks-current)).
- [Glossary](docs/glossary.md) of the terms and acronyms used in the design, the code and the reports.

## Not done yet

- Only the payments case has a recording. The other golden cases run against live models; their expectations still need a practitioner's review of a live run.
- The CI workflows have not yet run on GitHub.
- Nothing has been deployed to a live AgentCore or Foundry account from this repo yet; the [build guide](docs/build-guide.md#10-verify-before-production) lists what to confirm on first deployment.
- The Confluence source has not been run against a live site.
- The portal UI. The CLI stands in for it locally; identity flags on the CLI are for local development only.
