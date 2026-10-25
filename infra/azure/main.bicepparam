using 'main.bicep'

param prefix = 'tra'
param image = ''  // set after the first push to ACR, then re-deploy

param audiences = {
  'mcp-reference': 'api://tra-mcp-reference'
  'mcp-artefacts': 'api://tra-mcp-artefacts'
}

// App (client) IDs of the orchestrator's and specialists' app registrations.
param mcpAllowedCallers = [
  '<orchestrator-app-id>'
  '<specialist-app-id>'
]

// Regional deployments only. Confirm the model offers the Standard (regional) SKU in Australia East first.
param gptDeployments = []
