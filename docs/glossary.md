# Glossary

Terms and acronyms used in the TRA agent's design, code and reports. Where a
term comes from a standard, the definition follows that standard and names it.

## Assessment and risk

**Acceptance authority.** Who may accept a residual risk at a given rating, and
for how long. Critical: the CISO plus an executive risk owner, for up to 3
months. High: the CISO or a delegate plus the risk owner, up to 6 months.
Medium: the risk owner with a security architect's concurrence, up to 12
months. Low: the risk owner, up to 24 months. Set in `risk.py`.

**Artefact.** A design document the agent assesses, such as a Confluence page
or a file in Git. Each one carries a classification label and is recorded with
its revision and SHA-256 hash, so a reviewer can see exactly what was read.

**Asset.** Something of value to the business that the system stores or
processes, rated for confidentiality, integrity and availability (C / I / A).

**Boundary rule.** The SAR assesses controls that are properties of the design
or the delivery pipeline. Activities people perform on a running system are
recorded as handover requirements instead.

**Common control (CC).** One entry in the control catalogue, numbered CC-001
onwards. Each maps to the matching clauses of ISO 27001, the Essential Eight,
the ISM and PCI DSS, so a TRA cites one control and gets every framework
reference with it.

**Control catalogue, or crosswalk.** `controls.yaml`: the common controls and
their framework mappings. Agents may only cite controls that exist in it.

**Control status.** How far a design implements a control. *In place*: the
artefact shows it. *Partial*: it shows part of it or covers only some
components. *Missing*: a threat needs it and the artefact does not show it.

**Evidence.** The artefact text that shows a control is in place or a threat is
credible. "Not described in the artefacts" means there is none.

**Gate.** A point where a person must approve the TRA before it moves on.
*G1*: a practitioner confirms the scope, classification and tier. *G2*:
practitioners approve the threats and ratings (two different practitioners for
tier 1). *G3*: the risk owner accepts or treats the residual risk, after a
step-up sign-in. No software workload can decide a gate.

**Impact.** How bad the consequence would be, on a 1 to 5 scale with dollar
thresholds in Australian dollars (the AUD impact scale). A disclosure threat
cannot have an impact below the floor set by the data's classification.

**Inherent risk.** The risk rating with no design-specific controls. Controls
the system inherits from its platform still count.

**Likelihood.** How likely the threat is to happen, on a 1 to 5 scale, adjusted
by the SAR modifiers (for example internet exposure).

**Residual risk.** The risk rating after the proposed controls. It can never be
higher than the inherent rating.

**Risk category.** Where a risk sits in the cyber risk taxonomy, recorded as a
level 2 ID such as SUP.2. A risk is filed under its root cause, not its
consequence.

**Risk owner.** The business person accountable for the system's risks, who
decides at G3.

**Risk register.** The list of risks the TRA records, exported in the SAR CSV
format for the GRC tool (Eramba).

**Risk taxonomy.** The two-level classification of cyber risks in
`risk_taxonomy.yaml` and section 3.7 of the risk methodology: 14 level 1
categories (such as SUP Supply chain) and their level 2 categories.
*Always consider* categories (software development, supply chain, FOCI and
cryptography) must be addressed on every TRA.

**Risk treatment.** What is done about a risk, as in ISO 27005: mitigate,
accept, transfer or avoid.

**SAR.** Security Architecture Review: the organisation's process that this
agent supports. Its 5x5 matrix, likelihood modifiers and AUD impact scale are
in [03-risk-methodology.md](../../docs/03-risk-methodology.md).

**System model.** The agent's structured picture of the design: zones (trust
boundaries), elements, data flows and assets. It drives the data flow diagram
and the STRIDE analysis.

**Tier.** How much scrutiny a TRA gets. Tier 1 applies to cardholder data,
shared platforms, internet-facing systems and the highest classifications, and
needs two practitioners at G2. Tier 2 applies to OFFICIAL: Sensitive systems.
Tier 3 covers the rest.

**TRA.** Threat and risk assessment: the record of a system's threats, the
controls that address them and the risks that remain. The ISM requires one for
each system (ISM-1203).

**TRA floor.** The lowest classification a TRA document can carry:
OFFICIAL: Sensitive, because it describes a system's weaknesses.

## Threat modelling

**ATLAS.** MITRE Adversarial Threat Landscape for Artificial-Intelligence
Systems: a knowledge base of techniques used against AI systems, with IDs such
as AML.T0051 (LLM prompt injection). The library cites ATLAS 5.6.0. Every AI
element in a TRA must have at least one threat with an ATLAS technique.

**ATT&CK.** MITRE ATT&CK Enterprise: a knowledge base of the tactics and
techniques attackers use against enterprise and cloud systems, with IDs such as
T1190 (Exploit Public-Facing Application) or T1552.001 (Credentials In Files).
The library cites ATT&CK 20.0.

**Boundary-crossing flow.** A data flow that crosses a trust boundary. It is
drawn with a thick arrow and must have at least one threat.

**CBOM.** Cryptographic bill of materials: an inventory of where and how a
system uses cryptography, the starting point for the post-quantum transition.

**Confused deputy.** A service with more authority than its caller is tricked
into using that authority for the caller, for example by accepting a token
meant for another service.

**CRQC.** Cryptographically relevant quantum computer: a quantum computer able
to break RSA and elliptic-curve cryptography.

**DFD.** Data flow diagram: the drawing of the system model, with external
entities, processes, data stores and data flows grouped into trust zones.

**Element.** A part of the system model: an external entity, a process or a
data store. Elements have IDs E01, E02 and so on; flows have F01, F02.

**Harvest now, decrypt later.** Recording encrypted traffic or data today to
decrypt it once a CRQC exists. It makes quantum-vulnerable key exchange a risk
now for data whose confidentiality must outlast the early 2030s.

**Library threat.** An entry in `threat_library.yaml` (TL-001 onwards): a
reusable threat with its STRIDE categories, ATT&CK and ATLAS techniques and the
controls that address it. The agent adapts these to each design.

**Prompt injection.** Text that tries to make a language model follow the
attacker's instructions instead of its own. *Direct* injection comes from the
user; *indirect* injection hides in content the model reads, such as a design
document.

**STRIDE.** Microsoft's six threat categories: **S**poofing,
**T**ampering, **R**epudiation, **I**nformation disclosure, **D**enial of
service and **E**levation of privilege. *STRIDE per element* means only the
categories that apply to an element's type are considered: a data store cannot
be spoofed, for example.

**Tactic and technique.** In ATT&CK and ATLAS, a tactic is the attacker's goal
at a stage (such as initial access) and a technique is how they achieve it.
Sub-techniques have a three-digit suffix, such as T1078.004.

**Trust boundary, or zone.** A line in the design where the level of trust
changes, such as the internet edge or the edge of a VPC.

## Frameworks and standards

**ASD.** Australian Signals Directorate, which publishes the ISM and the
Essential Eight.

**ASD Essentials.** ASD's successor to the Essential Eight baseline, expected
around Q2 2027. The control catalogue has an empty column ready for it.

**Essential Eight (E8).** ASD's eight prioritised mitigation strategies, such
as multi-factor authentication and restricting administrative privileges,
assessed at maturity levels 0 to 3. The target here is Maturity Level 2 (ML2).

**FOCI.** Foreign ownership, control or influence: "the ability for vendors
to be directed by a foreign government", through direct ownership, the laws of
the vendor's home jurisdiction or outside pressure (Home Affairs). PSPF
Direction 001-2024 requires Commonwealth entities to manage FOCI risk in
technology procurement and maintenance.

**ISM.** ASD's Information Security Manual: a set of security controls with IDs
such as ISM-1504, published quarterly. Each control applies to some
classifications. The catalogue cites the September 2026 release (2026.09.4) and
only controls in its OFFICIAL: Sensitive baseline.

**ISO/IEC 27001:2022.** The international standard for an information security
management system. Its Annex A lists 93 controls, such as A.8.5 (secure
authentication).

**ISO/IEC 27005:2022.** The international guidance on information security risk
management that the TRA process follows: establish context, identify, analyse
and evaluate risk, treat it, then accept and monitor.

**ML-KEM and ML-DSA.** The NIST post-quantum algorithms for key
encapsulation (FIPS 203) and digital signatures (FIPS 204). The ISM requires
new cryptographic equipment and software to support ML-KEM-1024 and ML-DSA-87
by 2030.

**NIST SP 800-161.** NIST's guidance on cybersecurity supply chain risk
management (C-SCRM), Revision 1, Update 1 (2024).

**NIST SSDF.** The Secure Software Development Framework, NIST SP 800-218:
practices for producing secure software. Version 1.2 was in draft in 2026.

**OSCAL.** Open Security Controls Assessment Language: the machine-readable
format ASD publishes the ISM in. `scripts/refresh_frameworks.py` reads it.

**OWASP Top 10 for LLM Applications.** OWASP's list of the main risks in
applications built on large language models (LLM01 to LLM10). The red-team
tests are organised by it.

**PCI DSS.** Payment Card Industry Data Security Standard, version 4.0.1, which
applies to any system that stores, processes or transmits cardholder data.

**PQC.** Post-quantum cryptography: algorithms believed secure against
quantum computers. ASD recommends ceasing traditional asymmetric cryptography
(RSA, DH, ECDH, ECDSA) by the end of 2030.

**PSPF.** Protective Security Policy Framework: the Australian Government
policy that defines the security classifications.

## Classification

**Classification.** A PSPF label that says how sensitive information is. In
order: OFFICIAL, OFFICIAL: Sensitive, PROTECTED, SECRET, TOP SECRET.

**Clearance.** The highest classification a person or workload may read. The
agent refuses any artefact above the caller's clearance.

**OFFICIAL.** Routine government or business information whose compromise
would cause limited harm.

**OFFICIAL: Sensitive.** OFFICIAL information whose compromise could cause
limited damage to an individual, organisation or government. The highest
classification the agent currently handles.

**PROTECTED.** Information whose compromise could cause damage to the national
interest, organisations or individuals. Out of scope for now: the agent refuses
PROTECTED artefacts, and supporting them is a future state.

## The agent and its platform

**A2A.** Agent2Agent: an open protocol for one agent to call another over HTTP.

**AgentCore.** Amazon Bedrock AgentCore: AWS's managed runtime for agents, used
in the Sydney region.

**Audit chain.** The append-only audit log. Each event includes the hash of the
event before it, so deleting, reordering or editing an event breaks the chain.
Write-once storage (S3 Object Lock or an immutable Blob container) protects the
newest events.

**Bedrock.** Amazon Bedrock: AWS's managed model service. The agent uses the AU
geographic inference profiles, which keep requests in Sydney and Melbourne.

**Critic, or quality critic.** The specialist that reviews the draft TRA for
gaps, weak evidence and signs of prompt injection before a person sees it.

**Delegation token.** A short-lived token, bound to one audience, that lets a
service act for the signed-in person at the next hop. Specialists cannot use a
token issued for another service.

**Foundry.** Microsoft Foundry (formerly Azure AI Foundry): Azure's agent and
model platform, used in Australia East.

**Golden set.** Example designs with the threats, risks and critique findings a
good TRA must contain. Every change is scored against them for recall, and a
drop below the thresholds fails the build.

**MCP.** Model Context Protocol: the protocol the agent uses to give specialists
read-only tools, such as searching the threat library or fetching an artefact.

**OBO.** On-behalf-of: an Entra ID flow that exchanges a user's token for one a
service can use to call another service as that user.

**Orchestrator.** The component that runs the stages, calls the specialists and
stops at each gate. It does not make gate decisions.

**Practitioner.** A security architect who reviews and approves the TRA at G1
and G2.

**Principal.** Who is acting: a person, or a workload acting for a person.

**Red-team tests.** Tests that attack the agent the way a malicious author, a
compromised component or a careless reviewer would, and check the controls in
code still hold.

**Replay.** Running the agent on recorded model output instead of calling a
live model, so tests are repeatable and need no credentials.

**SBOM.** Software bill of materials: the list of components in the container
image, attached to it when it is signed with cosign.

**Specialist.** One of the six agents that each do one stage: intake, system
modelling, threat analysis, control mapping, risk analysis and quality review.

**Step-up.** A fresh, phishing-resistant sign-in required just before a
sensitive action. G3 needs one within the last 10 minutes.

**Workload identity.** An identity for software rather than a person, issued
by the platform, so services need no long-lived secrets.
