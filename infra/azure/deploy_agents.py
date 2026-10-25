"""Create or update the TRA hosted agents in a Foundry project.

Hosted agents are data-plane resources (no Bicep type), so this runs after
main.bicep. Every agent uses the same image; TRA_ROLE picks the role. Each run
creates a new immutable version per agent, which then takes all traffic.

    python infra/azure/deploy_agents.py --config infra/azure/agents.json --image <acr>/tra-agent:foundry-<sha>

The config file holds the outputs of main.bicep and the Entra app registrations
(see agents.example.json). After the first run, grant each agent's Entra
identity its data access (printed at the end); identities exist only once the
agents do.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

SPECIALISTS = ["intake", "system_modeller", "threat_analyst", "control_mapper", "risk_assessor", "quality_critic"]


def agent_name(role: str) -> str:
    return "tra-" + role.replace("_", "-")


def environment(role: str, cfg: dict) -> dict[str, str]:
    env = {
        "TRA_ENTRY": "tra_platform.foundry",
        "TRA_ROLE": role,
        "TRA_IDP_ISSUER": cfg["idp_issuer"],
        "TRA_IDP_JWKS_URL": cfg["idp_jwks_url"],
        "TRA_AUDIENCE": cfg["audiences"][role],
        "TRA_TENANT_ID": cfg["tenant_id"],
        "TRA_CLIENT_ID": cfg["client_ids"][role],
        "TRA_EXCHANGE": "entra-obo",
        "TRA_MCP": json.dumps(cfg["mcp"]),
    }
    if role == "orchestrator":
        env.update({
            "TRA_SPECIALISTS": json.dumps({
                s: {"endpoint": agent_name(s), "audience": cfg["audiences"][s]} for s in SPECIALISTS
            }),
            "TRA_STATE_URI": cfg["state_uri"],
            "TRA_AUDIT_URI": cfg["audit_uri"],
        })
    else:
        env["TRA_ALLOWED_CALLERS"] = cfg["client_ids"]["orchestrator"]
        if arn := cfg.get("bedrock_role_arn"):
            env["TRA_BEDROCK_ROLE_ARN"] = arn
    return env


def main() -> None:
    from azure.ai.projects import AIProjectClient
    from azure.ai.projects.models import (
        AgentEndpointProtocol,
        ContainerConfiguration,
        HostedAgentDefinition,
        ProtocolVersionRecord,
    )
    from azure.identity import DefaultAzureCredential

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--only", nargs="*", help="deploy only these roles")
    args = parser.parse_args()
    cfg = json.loads(args.config.read_text())

    project = AIProjectClient(endpoint=cfg["project_endpoint"], credential=DefaultAzureCredential())
    roles = args.only or ["orchestrator", *SPECIALISTS]
    for role in roles:
        size = cfg.get("sizes", {}).get(role, {"cpu": "1", "memory": "2Gi"})
        agent = project.agents.create_version(
            agent_name=agent_name(role),
            definition=HostedAgentDefinition(
                protocol_versions=[ProtocolVersionRecord(protocol=AgentEndpointProtocol.INVOCATIONS, version="2.0.0")],
                cpu=size["cpu"],
                memory=size["memory"],
                container_configuration=ContainerConfiguration(image=args.image),
                environment_variables=environment(role, cfg),
            ),
        )
        print(f"{agent_name(role)}: version {agent.version}")

    print(
        "\nNext: give the orchestrator's agent identity 'Storage Blob Data Contributor' on the state account and on "
        "the audit container (the immutability policy still blocks deletes), and give each specialist's identity "
        "'Cognitive Services OpenAI User' on the Foundry account if it routes to GPT. Find identities in the "
        "Foundry portal or with project.agents.get(agent_name=...)."
    )


if __name__ == "__main__":
    main()
