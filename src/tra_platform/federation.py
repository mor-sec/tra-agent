"""Cross-cloud workload credentials without stored secrets.

A host on one cloud sometimes needs the other: a Foundry-hosted agent calling
Claude on Bedrock (Claude on Foundry is not Australia-resident), or an
AgentCore-hosted orchestrator using Entra on-behalf-of. Both directions use
OIDC federation, so there is no long-lived key to rotate or leak.

- AWS to Entra: STS `GetWebIdentityToken` (IAM outbound identity federation)
  mints a short-lived JWT for the runtime's role. An Entra app registration
  trusts it through a federated identity credential (issuer: the account's
  outbound issuer URL; subject: the role ARN).
- Entra to AWS: the container's managed identity gets a token for
  `api://AzureADTokenExchange`; IAM trusts Entra as an OIDC provider and
  `AssumeRoleWithWebIdentity` returns role credentials.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

ENTRA_EXCHANGE_AUDIENCE = "api://AzureADTokenExchange"


def aws_web_identity_token(audience: str = ENTRA_EXCHANGE_AUDIENCE, sts: Any = None) -> str:
    """A JWT asserting this AWS role, for an external IdP. Requires outbound federation enabled on the account."""
    import boto3

    client = sts or boto3.client("sts")
    return client.get_web_identity_token(Audience=[audience], SigningAlgorithm="RS256")["WebIdentityToken"]


def entra_assertion_from_aws(sts: Any = None) -> Callable[[], Awaitable[str]]:
    """Client assertion for `EntraOboExchanger` when the orchestrator runs on AgentCore."""

    async def assertion() -> str:
        import asyncio

        return await asyncio.to_thread(aws_web_identity_token, ENTRA_EXCHANGE_AUDIENCE, sts)

    return assertion


def entra_credential_from_aws(tenant_id: str, client_id: str, sts: Any = None) -> Any:
    """An azure-identity credential for an AWS-hosted agent (for example to call GPT in Australia East)."""
    from azure.identity import ClientAssertionCredential

    return ClientAssertionCredential(tenant_id, client_id, lambda: aws_web_identity_token(sts=sts))


def entra_assertion_from_managed_identity(credential: Any = None) -> Callable[[], Awaitable[str]]:
    """Client assertion for `EntraOboExchanger` when the orchestrator runs on Foundry."""
    from azure.identity import DefaultAzureCredential

    cred = credential or DefaultAzureCredential()

    async def assertion() -> str:
        return cred.get_token(f"{ENTRA_EXCHANGE_AUDIENCE}/.default").token

    return assertion


def bedrock_client_from_entra(role_arn: str, region: str = "ap-southeast-2", credential: Any = None) -> Any:
    """A bedrock-runtime client for an Azure-hosted agent, with role credentials that refresh themselves."""
    import boto3
    import botocore.session
    from azure.identity import DefaultAzureCredential
    from botocore.credentials import RefreshableCredentials

    cred = credential or DefaultAzureCredential()
    sts = boto3.client("sts", region_name=region)

    def fetch() -> dict[str, str]:
        token = cred.get_token(f"{ENTRA_EXCHANGE_AUDIENCE}/.default").token
        c = sts.assume_role_with_web_identity(
            RoleArn=role_arn, RoleSessionName="tra-foundry", WebIdentityToken=token, DurationSeconds=3600
        )["Credentials"]
        return {
            "access_key": c["AccessKeyId"],
            "secret_key": c["SecretAccessKey"],
            "token": c["SessionToken"],
            "expiry_time": c["Expiration"].isoformat(),
        }

    session = botocore.session.get_session()
    session._credentials = RefreshableCredentials.create_from_metadata(  # noqa: SLF001 - documented botocore pattern
        metadata=fetch(), refresh_using=fetch, method="assume-role-with-web-identity"
    )
    return boto3.Session(botocore_session=session).client("bedrock-runtime", region_name=region)
