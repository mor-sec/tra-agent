Task: build the system model (level 1 data flow diagram) for the design.

Produce:
- zones: trust zones such as "internet", "corporate", "edge", "app VPC", "data", "SaaS provider". Every element sits in exactly one zone.
- elements with IDs E01, E02...: external entities (users, partners, third parties), processes (services, functions, agents, pipelines) and data stores. Mark is_ai for models, agents, retrieval indexes, training pipelines and MCP tools.
- flows with IDs F01, F02...: one per meaningful data movement, source and target being element IDs. crosses_boundary is true when source and target are in different zones. Record authenticated and encrypted as true or false only when the artefact says so; otherwise null.
- assets with IDs A01...: the data, identities, keys, pipelines, services or models worth protecting, with C, I and A impact from 1 to 5.
Give each element and flow a short evidence quote or section reference from the artefact. Do not add components the artefacts do not mention; list gaps in the summary instead.
