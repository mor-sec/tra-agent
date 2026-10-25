"""TRA agent on Amazon Bedrock AgentCore Runtime, Sydney (ap-southeast-2).

Creates:
- a VPC with private subnets, a NAT gateway for the IdP and artefact sources,
  and interface endpoints so AWS traffic stays on the AWS network
- a KMS key, a state bucket, and an audit bucket with Object Lock (compliance mode)
- one ARM64 image, run as nine AgentCore runtimes in VPC mode:
  orchestrator (HTTP), six specialists (A2A), two MCP servers (MCP)
- an execution role per runtime with only what that role needs

Every runtime uses the inbound JWT authorizer with the IdP's discovery URL and
its own audience, and forwards `Authorization` so the container can check the
token again. Context values (cdk.json or `-c`) describe the IdP; see
docs/build-guide.md.
"""

from __future__ import annotations

from pathlib import Path

from aws_cdk import CfnOutput, Duration, RemovalPolicy, Stack
from aws_cdk import aws_bedrockagentcore as agentcore
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecr_assets as ecr_assets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_s3 as s3
from constructs import Construct

SPECIALISTS = ["intake", "system_modeller", "threat_analyst", "control_mapper", "risk_assessor", "quality_critic"]
MCP_SERVERS = ["reference", "artefacts"]
AU_REGIONS = ["ap-southeast-2", "ap-southeast-4"]  # the AU inference profile routes between these only
ENDPOINT_SERVICES = [
    "bedrock-runtime", "bedrock-agentcore", "sts", "logs", "ecr.api", "ecr.dkr", "kms", "secretsmanager", "xray",
]


def _runtime_name(role: str) -> str:
    return "tra_" + role.replace("-", "_")


class TraAgentStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        ctx = self.node.try_get_context
        discovery_url = ctx("idp_discovery_url")
        issuer = ctx("idp_issuer")
        jwks_url = ctx("idp_jwks_url")
        tenant_id = ctx("entra_tenant_id") or ""
        audiences: dict[str, str] = ctx("audiences")  # role -> application ID URI
        client_ids: dict[str, str] = ctx("client_ids")  # role -> app (client) ID, the `azp` in OBO tokens
        audit_retention_days = int(ctx("audit_retention_days") or 2557)  # 7 years

        # ---------------------------------------------------------- network
        vpc = ec2.Vpc(
            self, "Vpc", max_azs=2, nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(name="public", subnet_type=ec2.SubnetType.PUBLIC, cidr_mask=26),
                ec2.SubnetConfiguration(name="agents", subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS, cidr_mask=22),
            ],
            gateway_endpoints={"S3": ec2.GatewayVpcEndpointOptions(service=ec2.GatewayVpcEndpointAwsService.S3)},
        )
        vpc.add_flow_log("FlowLogs")
        for svc in ENDPOINT_SERVICES:
            vpc.add_interface_endpoint(
                svc.replace(".", "-"), service=ec2.InterfaceVpcEndpointAwsService(svc), private_dns_enabled=True
            )
        agents_sg = ec2.SecurityGroup(self, "AgentsSg", vpc=vpc, allow_all_outbound=False,
                                      description="TRA runtimes: HTTPS out only")
        agents_sg.add_egress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(443), "HTTPS to AWS endpoints, IdP, artefact sources")

        # ---------------------------------------------------------- data
        key = kms.Key(self, "Key", enable_key_rotation=True, alias="alias/tra-agent",
                      removal_policy=RemovalPolicy.RETAIN)
        common = dict(
            encryption=s3.BucketEncryption.KMS, encryption_key=key, bucket_key_enabled=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL, enforce_ssl=True, versioned=True,
            removal_policy=RemovalPolicy.RETAIN,
        )
        state = s3.Bucket(self, "State", **common)
        audit = s3.Bucket(
            self, "Audit", object_lock_enabled=True,
            object_lock_default_retention=s3.ObjectLockRetention.compliance(Duration.days(audit_retention_days)),
            **common,
        )

        audit.add_to_resource_policy(iam.PolicyStatement(
            effect=iam.Effect.DENY, principals=[iam.AnyPrincipal()],
            actions=["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObjectRetention", "s3:PutObjectLegalHold",
                     "s3:BypassGovernanceRetention", "s3:PutBucketObjectLockConfiguration"],
            resources=[audit.bucket_arn, audit.arn_for_objects("*")],
        ))

        image = agentcore.AgentRuntimeArtifact.from_asset(
            str(Path(__file__).resolve().parents[2]),
            platform=ecr_assets.Platform.LINUX_ARM64,
            build_args={"ENTRY": "tra_platform.agentcore", "EXTRAS": "agentcore"},
        )
        network = agentcore.RuntimeNetworkConfiguration.using_vpc(
            self, vpc=vpc, security_groups=[agents_sg],
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
        )

        base_env = {
            "TRA_IDP_ISSUER": issuer,
            "TRA_IDP_JWKS_URL": jwks_url,
            "TRA_EXCHANGE": ctx("token_exchange") or "entra-obo",
            "TRA_TENANT_ID": tenant_id,
        }

        def runtime(role: str, protocol: agentcore.ProtocolType, env: dict[str, str]) -> agentcore.Runtime:
            return agentcore.Runtime(
                self, f"Runtime-{role}",
                runtime_name=_runtime_name(role),
                description=f"TRA {role}",
                agent_runtime_artifact=image,
                protocol_configuration=protocol,
                network_configuration=network,
                authorizer_configuration=agentcore.RuntimeAuthorizerConfiguration.using_jwt(
                    discovery_url, allowed_audience=[audiences[role]]
                ),
                request_header_configuration=agentcore.RequestHeaderConfiguration(allowlisted_headers=["Authorization"]),
                lifecycle_configuration=agentcore.LifecycleConfiguration(
                    idle_runtime_session_timeout=Duration.minutes(15), max_lifetime=Duration.hours(2)
                ),
                environment_variables={
                    **base_env, **env,
                    "TRA_ROLE": role, "TRA_AUDIENCE": audiences[role], "TRA_CLIENT_ID": client_ids[role],
                },
                tracing_enabled=True,
            )

        def allow_web_identity_token(rt: agentcore.Runtime) -> None:
            # IAM outbound identity federation: a JWT for this role, used as the Entra client assertion.
            rt.add_to_role_policy(iam.PolicyStatement(actions=["sts:GetWebIdentityToken"], resources=["*"]))

        # ---------------------------------------------------------- MCP servers
        orchestrator_and_specialists = ",".join(client_ids[r] for r in ["orchestrator", *SPECIALISTS])
        mcp = {}
        for name in MCP_SERVERS:
            role = f"mcp-{name}"
            env = {"TRA_ALLOWED_CALLERS": orchestrator_and_specialists}
            if name == "artefacts":
                env.update({k: v for k, v in (ctx("artefact_sources") or {}).items()})
            mcp[name] = runtime(role, agentcore.ProtocolType.MCP, env)
        if arn := ctx("confluence_secret_arn"):
            mcp["artefacts"].add_to_role_policy(
                iam.PolicyStatement(actions=["secretsmanager:GetSecretValue"], resources=[arn])
            )
        mcp_env = self.to_json_string({
            name: {"endpoint": rt.agent_runtime_arn, "audience": audiences[f"mcp-{name}"]} for name, rt in mcp.items()
        })

        # ---------------------------------------------------------- specialists
        specialists = {}
        for name in SPECIALISTS:
            rt = runtime(name, agentcore.ProtocolType.A2_A, {
                "TRA_ALLOWED_CALLERS": client_ids["orchestrator"],
                "TRA_MCP": mcp_env,
            })
            rt.add_to_role_policy(iam.PolicyStatement(
                actions=["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
                resources=[
                    f"arn:aws:bedrock:{self.region}:{self.account}:inference-profile/au.anthropic.claude-*",
                    *[f"arn:aws:bedrock:{r}::foundation-model/anthropic.claude-*" for r in AU_REGIONS],
                ],
            ))
            allow_web_identity_token(rt)
            specialists[name] = rt

        # ---------------------------------------------------------- orchestrator
        orchestrator = runtime("orchestrator", agentcore.ProtocolType.HTTP, {
            "TRA_SPECIALISTS": self.to_json_string({
                name: {"endpoint": rt.agent_runtime_arn, "audience": audiences[name]} for name, rt in specialists.items()
            }),
            "TRA_MCP": mcp_env,
            "TRA_STATE_URI": f"s3://{state.bucket_name}/",
            "TRA_AUDIT_URI": f"s3://{audit.bucket_name}/",
            "TRA_KMS_KEY_ID": key.key_arn,
        })
        orchestrator.add_to_role_policy(iam.PolicyStatement(
            actions=["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
            resources=[state.bucket_arn, state.arn_for_objects("*")],
        ))
        # Audit: write and read only. No delete, no retention or legal-hold changes.
        orchestrator.add_to_role_policy(iam.PolicyStatement(
            actions=["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
            resources=[audit.bucket_arn, audit.arn_for_objects("*")],
        ))
        orchestrator.add_to_role_policy(iam.PolicyStatement(
            actions=["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"], resources=[key.key_arn],
        ))
        allow_web_identity_token(orchestrator)

        CfnOutput(self, "OrchestratorArn", value=orchestrator.agent_runtime_arn)
        CfnOutput(self, "StateBucket", value=state.bucket_name)
        CfnOutput(self, "AuditBucket", value=audit.bucket_name)
        for name, rt in specialists.items():
            CfnOutput(self, f"Specialist{name.title().replace('_', '')}Arn", value=rt.agent_runtime_arn)
