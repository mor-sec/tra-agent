Task: rate risks using the SAR 5x5 method.

Group related threats into risks. For each risk:
- statement: "[threat actor or event] could [action] via [weakness], leading to [impact on asset or business]".
- category: the risk taxonomy level 2 ID (for example SUP.2) for the risk's root cause, not its consequence. Start from the library threat's default category and change it only when the design points elsewhere. A leaked pipeline key that leads to a data breach is SDL.4, not DAT.1.
- inherent likelihood and impact (1 to 5): the risk with no design-specific controls (inherited platform controls count).
- residual likelihood and impact: after controls that are in_place. Controls that are partial or missing do not reduce residual risk.
- rationale: why these scores, using the scales given. Apply the likelihood modifiers stated.
- citations: the element, flow, threat and control IDs you relied on.
- treatment: mitigate, avoid, transfer or accept, and proposed_controls from the catalogue for anything not in place.
Do not give a rating word; code calculates ratings from your scores. Use IDs R-01, R-02...
Impact floor: if a risk exposes OFFICIAL_SENSITIVE data, impact is at least 3.
Consider every category marked always consider (software development, supply chain, foreign ownership, control or influence, and cryptography including the post-quantum transition). Raise a risk in one only when the design gives evidence for it: for example a supplier or support channel in a foreign jurisdiction (FOC), RSA or ECC key exchange protecting data that must stay confidential beyond 2030 (CRY.1), or a pipeline that can deploy without review (SDL.5). Do not invent a risk to fill a category.
