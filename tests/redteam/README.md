# Red-team tests

These tests attack the TRA agent the way a malicious design author, a
compromised component or a careless reviewer would. They run in CI on every
change with recorded model output, so they test the controls in code, not a
model's good behaviour. A model that obeys an injected instruction must still
fail to change a rating, skip a gate or forge evidence.

Run them on their own with:

```bash
pytest tests/redteam -q
```

## Coverage

OWASP Top 10 for LLM Applications (2025) and MITRE ATLAS 5.6.0. The checks
reject any ATT&CK or ATLAS ID that is not in the pinned release
(`src/tra_core/data/attack.yaml` and `atlas.yaml`).

| Risk | ATLAS | Where it is tested | What must hold |
|---|---|---|---|
| LLM01 Prompt injection | AML.T0051.001 | `test_untrusted_content.py` | Artefact text cannot close or forge its `<artefact>` block or inject attributes through the locator. A planted instruction reaches the model only inside the block, does not change code-calculated ratings, and the critic reports it. The golden set's `critique_recall` of 1.0 makes the last point a release gate. |
| LLM02 Sensitive information disclosure | AML.T0057 | `test_untrusted_content.py`, `tests/test_artefacts_and_tools.py` | Body markings above the label (PROTECTED, SECRET, TOP SECRET) are refused before any model call; prose such as "protected by TLS" is not. Unlabelled artefacts and paths outside the artefact root are refused. Reads check the caller's clearance. |
| LLM03 Supply chain | AML.T0010 | CI: `pip-audit`, Trivy, SBOM, cosign | Known-vulnerable dependencies and critical image findings fail the build; the image is signed with its SBOM attached. |
| LLM05 Improper output handling | AML.T0048 | `test_model_output.py`, `test_untrusted_content.py` | Model-supplied ratings are ignored. Out-of-range scores, unknown IDs, residual above inherent, impact below the data's floor, ATT&CK or ATLAS IDs that are malformed or not in the pinned release, risk categories not in the taxonomy, and prose instead of JSON are rejected, retried with the errors, and logged. Persistent bad output stops the pipeline. The report escapes HTML, links, images and table-breaking pipes. |
| LLM06 Excessive agency | AML.T0053, AML.T0012 | `test_gates.py`, `test_tokens.py` | No workload can decide a gate, even one acting for a practitioner. Tier 1 needs two different practitioners who approved the same content. G3 needs step-up within 10 minutes. Tokens: `alg: none`, HS256 signed with the public key, tampered payloads, unknown or rotated keys, wrong issuer or audience, expired tokens, user tokens replayed at a specialist, and callers not on the allow list are all refused. |
| LLM07 System prompt leakage | AML.T0056 | Not applicable | Prompts are in the repository and contain no secrets or access rules; access is enforced in code. |
| LLM08 Vector and embedding weaknesses | AML.T0020 | Not applicable | The agent has no retrieval index. The `rag-assistant` golden case checks the agent finds this class of threat in designs it assesses. |
| LLM09 Misinformation and over-reliance | — | `test_gates.py`, golden set | Gates need a rationale; the intake cannot lower the classification; recall thresholds catch a model that stops finding known threats. |
| LLM10 Unbounded consumption | AML.T0029 | `test_model_output.py` | Each specialist gives up after `max_attempts` (3). Runtime idle and lifetime limits are set in the IaC. |
| Audit integrity (ISO 27001 A.8.15, ISM, PCI DSS 10.3) | — | `test_audit_tamper.py` | Deleting, reordering or editing events breaks the chain. Specialists can only report their own model, tool and output events, so a compromised specialist cannot inject a gate decision. Truncating the newest events is not detectable by the chain alone; Object Lock and the no-delete policy are the control for that. |

## Adding a test

When a review, pen test or incident finds a new way to subvert the agent, add
the attack here first, watch it fail, then fix the code. Name the test after
what must hold, not after the attack.
