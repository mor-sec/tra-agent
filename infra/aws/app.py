#!/usr/bin/env python3
import aws_cdk as cdk
from tra_stack import TraAgentStack

app = cdk.App()
TraAgentStack(
    app,
    "TraAgent",
    env=cdk.Environment(account=app.node.try_get_context("account"), region="ap-southeast-2"),
    description="TRA agent on Bedrock AgentCore Runtime (Sydney)",
)
cdk.Tags.of(app).add("project", "tra-agent")
cdk.Tags.of(app).add("data-classification", "OFFICIAL-Sensitive")
app.synth()
