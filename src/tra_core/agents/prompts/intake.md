Task: intake for a TRA.

Read the artefacts and the request, then:
- Summarise in two or three sentences what is being assessed.
- Confirm the work type (new_system, design_change, new_control, finding_triage, incident). Use the requested type unless the artefacts clearly show another.
- Propose the classification of the material and the system's data. It can never be lower than the highest artefact label you were given.
- Set internet_facing true only for anonymous internet exposure. Set handles_cardholder_data true if card numbers or a cardholder data environment appear. Set shared_platform true for landing zones, identity providers, CI/CD platforms, shared networking or secrets platforms.
- List missing information a reviewer would need (for example: no data flow description, no authentication design, no hosting details).
- Name the risk owner only if an artefact names one.
Leave tier unset; code calculates it.
