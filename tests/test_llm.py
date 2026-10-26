import json

import pytest

from tra_core.agents.specialists import RiskList
from tra_core.llm import BedrockClient, ModelError, inline_refs


def test_inline_refs_removes_defs():
    schema = inline_refs(RiskList.model_json_schema(mode="validation"))
    assert "$defs" not in json.dumps(schema) and "$ref" not in json.dumps(schema)
    assert "inherent_rating" not in json.dumps(schema)  # computed by code, never asked of the model


class _StubBedrock:
    def __init__(self, stop_reason="tool_use"):
        self.kwargs = None
        self.stop_reason = stop_reason

    def converse(self, **kwargs):
        self.kwargs = kwargs
        content = [{"toolUse": {"name": "X", "input": {"ok": True}}}]
        return {"output": {"message": {"content": content}}, "stopReason": self.stop_reason}


async def test_bedrock_truncation_fails_fast():
    client = BedrockClient("au.anthropic.claude-sonnet-5-5", client=_StubBedrock("max_tokens"))
    with pytest.raises(ModelError, match="truncated"):
        await client.generate(system="s", user="u", schema={"type": "object"}, schema_name="X")


async def test_bedrock_forces_structured_tool_call():
    stub = _StubBedrock()
    client = BedrockClient("au.anthropic.claude-sonnet-5-5", client=stub)
    out = await client.generate(system="s", user="u", schema={"type": "object"}, schema_name="X")
    assert json.loads(out) == {"ok": True}
    assert stub.kwargs["toolConfig"]["toolChoice"] == {"tool": {"name": "X"}}
    assert stub.kwargs["modelId"].startswith("au.")
