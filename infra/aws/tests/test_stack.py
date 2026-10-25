"""Synthesises the stack and checks the security-relevant settings. Run: pytest infra/aws/tests"""

import json
from pathlib import Path

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Match, Template
from tra_stack import SPECIALISTS, TraAgentStack

CONTEXT = json.loads((Path(__file__).parents[1] / "cdk.json").read_text())["context"]


@pytest.fixture(scope="module")
def template() -> Template:
    app = cdk.App(context=CONTEXT)
    stack = TraAgentStack(app, "TraAgent", env=cdk.Environment(account="123456789012", region="ap-southeast-2"))
    return Template.from_stack(stack)


def test_nine_runtimes_in_vpc_with_jwt_authorizer(template):
    runtimes = template.find_resources("AWS::BedrockAgentCore::Runtime")
    assert len(runtimes) == 9
    for r in runtimes.values():
        p = r["Properties"]
        assert p["NetworkConfiguration"]["NetworkMode"] == "VPC"
        assert p["AuthorizerConfiguration"]["CustomJWTAuthorizer"]["AllowedAudience"] == [p["EnvironmentVariables"]["TRA_AUDIENCE"]]
        assert p["RequestHeaderConfiguration"]["RequestHeaderAllowlist"] == ["Authorization"]
    protocols = sorted(r["Properties"]["ProtocolConfiguration"] for r in runtimes.values())
    assert protocols == ["A2A"] * len(SPECIALISTS) + ["HTTP"] + ["MCP"] * 2


def test_audit_bucket_is_write_once(template):
    template.has_resource_properties("AWS::S3::Bucket", {
        "ObjectLockEnabled": True,
        "ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled",
                                    "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 2557}}},
    })
    template.has_resource_properties("AWS::S3::BucketPolicy", {"PolicyDocument": {"Statement": Match.array_with([
        Match.object_like({"Effect": "Deny", "Action": Match.array_with(["s3:DeleteObject"])}),
    ])}})


def test_models_limited_to_au_profiles(template):
    policies = template.find_resources("AWS::IAM::Policy")
    model_resources = [
        res
        for p in policies.values()
        for s in p["Properties"]["PolicyDocument"]["Statement"]
        if "bedrock:InvokeModel" in (s["Action"] if isinstance(s["Action"], list) else [s["Action"]])
        for res in s["Resource"]
    ]
    assert model_resources
    flat = json.dumps(model_resources)
    assert "us-" not in flat and "global." not in flat and "au.anthropic" in flat
