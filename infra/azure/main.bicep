// TRA agent on Microsoft Foundry, Australia East.
//
// Creates the platform the hosted agents run on. The agents themselves (one
// orchestrator, six specialists) are data-plane resources with no Bicep type;
// deploy_agents.py creates them after this template, from the same image.
//
// - VNet with subnets for Foundry agent injection, Container Apps and private endpoints
// - Foundry account (AIServices) with network injection, local auth off, public access off
// - Foundry project, and regional ("Standard") GPT deployments in Australia East only
// - ACR (Premium, private), Key Vault (RBAC), Log Analytics and Application Insights
// - state storage, and audit storage with a time-based immutability policy
// - Container Apps environment (internal) running the two MCP servers
// - private endpoints and DNS zones for everything above
//
// The VNet must exist when the Foundry account is created: network injection
// cannot be added to an existing account.

targetScope = 'resourceGroup'

@description('Must be Australia East: hosted agents and regional GPT deployments are both available there.')
@allowed(['australiaeast'])
param location string = 'australiaeast'

@description('Short prefix for resource names, lower case.')
@minLength(3)
@maxLength(10)
param prefix string = 'tra'

@description('Image for the MCP servers and hosted agents, e.g. <acr>.azurecr.io/tra-agent:foundry-<sha>. Leave empty on the first run.')
param image string = ''

@description('Regional GPT deployments. Only list models that offer the regional Standard SKU in Australia East.')
param gptDeployments array = []
// Example: [{ name: 'gpt-critic', model: '<model>', version: '<version>', capacity: 50 }]

@description('Entra tenant and IdP values for token validation.')
param tenantId string = subscription().tenantId

@description('Application ID URIs: mcp-reference, mcp-artefacts.')
param audiences object

@description('Client IDs allowed to call the MCP servers (orchestrator and specialists).')
param mcpAllowedCallers array

@description('Audit retention in days for the immutability policy.')
param auditRetentionDays int = 2557

param vnetAddressSpace string = '10.40.0.0/20'

var suffix = uniqueString(resourceGroup().id)
var tags = { project: 'tra-agent', 'data-classification': 'OFFICIAL-Sensitive' }
var issuer = '${environment().authentication.loginEndpoint}${tenantId}/v2.0'
var jwks = '${environment().authentication.loginEndpoint}${tenantId}/discovery/v2.0/keys'

// Built-in role definition IDs
var roles = {
  acrPull: '7f951dca-d4a0-4fbd-8e75-9c71c0d27e86'
  blobDataContributor: 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
  keyVaultSecretsUser: '4633458b-17de-408a-b874-0445c86b69e6'
}

// ------------------------------------------------------------------ network

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${prefix}-vnet'
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: [vnetAddressSpace] }
    subnets: [
      {
        name: 'agents'
        properties: {
          addressPrefix: cidrSubnet(vnetAddressSpace, 24, 0)
          delegations: [{ name: 'foundry', properties: { serviceName: 'Microsoft.App/environments' } }]
        }
      }
      {
        name: 'apps'
        properties: {
          addressPrefix: cidrSubnet(vnetAddressSpace, 23, 1)
          delegations: [{ name: 'aca', properties: { serviceName: 'Microsoft.App/environments' } }]
        }
      }
      {
        name: 'endpoints'
        properties: {
          addressPrefix: cidrSubnet(vnetAddressSpace, 24, 4)
          privateEndpointNetworkPolicies: 'Enabled'
        }
      }
    ]
  }
}

var agentsSubnetId = vnet.properties.subnets[0].id
var appsSubnetId = vnet.properties.subnets[1].id
var endpointsSubnetId = vnet.properties.subnets[2].id

// ------------------------------------------------------------------ observability

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${prefix}-logs-${suffix}'
  location: location
  tags: tags
  properties: { sku: { name: 'PerGB2018' }, retentionInDays: 365 }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: '${prefix}-ai-${suffix}'
  location: location
  kind: 'web'
  tags: tags
  properties: { Application_Type: 'other', WorkspaceResourceId: logs.id, DisableLocalAuth: true }
}

// ------------------------------------------------------------------ Foundry

resource foundry 'Microsoft.CognitiveServices/accounts@2025-06-01' = {
  name: '${prefix}-foundry-${suffix}'
  location: location
  tags: tags
  kind: 'AIServices'
  sku: { name: 'S0' }
  identity: { type: 'SystemAssigned' }
  properties: {
    customSubDomainName: '${prefix}-foundry-${suffix}'
    allowProjectManagement: true
    disableLocalAuth: true
    publicNetworkAccess: 'Disabled'
    networkAcls: { defaultAction: 'Deny' }
    networkInjections: [
      { scenario: 'agent', subnetArmId: agentsSubnetId, useMicrosoftManagedNetwork: false }
    ]
  }
}

resource project 'Microsoft.CognitiveServices/accounts/projects@2025-06-01' = {
  parent: foundry
  name: '${prefix}-project'
  location: location
  identity: { type: 'SystemAssigned' }
  properties: { displayName: 'TRA agent', description: 'Threat and risk assessment agent' }
}

@batchSize(1)
resource deployments 'Microsoft.CognitiveServices/accounts/deployments@2025-06-01' = [for d in gptDeployments: {
  parent: foundry
  name: d.name
  // Standard = regional processing in Australia East. Never GlobalStandard or DataZone for this workload.
  sku: { name: 'Standard', capacity: d.capacity }
  properties: { model: { format: 'OpenAI', name: d.model, version: d.version } }
}]

// ------------------------------------------------------------------ registry and secrets

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: '${prefix}acr${suffix}'
  location: location
  tags: tags
  sku: { name: 'Premium' }
  properties: { adminUserEnabled: false, publicNetworkAccess: 'Disabled' }
}

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: '${prefix}-kv-${suffix}'
  location: location
  tags: tags
  properties: {
    tenantId: tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enablePurgeProtection: true
    softDeleteRetentionInDays: 90
    publicNetworkAccess: 'Disabled'
  }
}

// ------------------------------------------------------------------ storage

var storageCommon = {
  allowBlobPublicAccess: false
  allowSharedKeyAccess: false
  minimumTlsVersion: 'TLS1_2'
  publicNetworkAccess: 'Disabled'
  supportsHttpsTrafficOnly: true
  networkAcls: { defaultAction: 'Deny', bypass: 'None' }
}

resource stateAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: take('${prefix}state${suffix}', 24)
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: 'ZRS' }
  properties: storageCommon
}

resource stateBlob 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: stateAccount
  name: 'default'
  properties: { isVersioningEnabled: true, deleteRetentionPolicy: { enabled: true, days: 30 } }
}

resource stateContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: stateBlob
  name: 'tra'
}

resource auditAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: take('${prefix}audit${suffix}', 24)
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: 'ZRS' }
  properties: storageCommon
}

resource auditBlob 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: auditAccount
  name: 'default'
}

resource auditContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: auditBlob
  name: 'audit'
}

// Unlocked here so the template can be re-run; lock it once (build guide, step 4).
// A locked policy cannot be shortened or removed, which is the point.
resource auditImmutability 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = {
  parent: auditContainer
  name: 'default'
  properties: {
    immutabilityPeriodSinceCreationInDays: auditRetentionDays
    allowProtectedAppendWrites: false
  }
}

// ------------------------------------------------------------------ private endpoints

var privateLinks = [
  { name: 'foundry', id: foundry.id, group: 'account', zones: ['privatelink.cognitiveservices.azure.com', 'privatelink.openai.azure.com', 'privatelink.services.ai.azure.com'] }
  { name: 'acr', id: acr.id, group: 'registry', zones: ['privatelink.azurecr.io'] }
  { name: 'vault', id: vault.id, group: 'vault', zones: ['privatelink.vaultcore.azure.net'] }
  { name: 'state', id: stateAccount.id, group: 'blob', zones: ['privatelink.blob.${environment().suffixes.storage}'] }
  { name: 'audit', id: auditAccount.id, group: 'blob', zones: ['privatelink.blob.${environment().suffixes.storage}'] }
]

var zoneNames = union(flatten(map(privateLinks, l => l.zones)), [])

resource zones 'Microsoft.Network/privateDnsZones@2020-06-01' = [for z in zoneNames: {
  name: z
  location: 'global'
  tags: tags
}]

resource zoneLinks 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = [for (z, i) in zoneNames: {
  parent: zones[i]
  name: '${prefix}-vnet'
  location: 'global'
  properties: { virtualNetwork: { id: vnet.id }, registrationEnabled: false }
}]

resource endpoints 'Microsoft.Network/privateEndpoints@2024-05-01' = [for l in privateLinks: {
  name: '${prefix}-pe-${l.name}'
  location: location
  tags: tags
  properties: {
    subnet: { id: endpointsSubnetId }
    privateLinkServiceConnections: [
      { name: l.name, properties: { privateLinkServiceId: l.id, groupIds: [l.group] } }
    ]
  }
}]

resource endpointZones 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = [for (l, i) in privateLinks: {
  parent: endpoints[i]
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [for z in l.zones: {
      name: replace(z, '.', '-')
      properties: { privateDnsZoneId: resourceId('Microsoft.Network/privateDnsZones', z) }
    }]
  }
  dependsOn: [zones]
}]

// ------------------------------------------------------------------ MCP servers (Container Apps)

resource mcpIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${prefix}-mcp-id'
  location: location
  tags: tags
}

resource appsEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${prefix}-apps'
  location: location
  tags: tags
  properties: {
    vnetConfiguration: { infrastructureSubnetId: appsSubnetId, internal: true }
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: { customerId: logs.properties.customerId, sharedKey: logs.listKeys().primarySharedKey }
    }
    zoneRedundant: true
  }
}

var mcpServers = image == '' ? [] : ['reference', 'artefacts']

resource mcpApps 'Microsoft.App/containerApps@2024-03-01' = [for name in mcpServers: {
  name: '${prefix}-mcp-${name}'
  location: location
  tags: tags
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${mcpIdentity.id}': {} } }
  properties: {
    managedEnvironmentId: appsEnv.id
    configuration: {
      ingress: { external: false, targetPort: 8000, transport: 'http', allowInsecure: false }
      registries: [{ server: acr.properties.loginServer, identity: mcpIdentity.id }]
    }
    template: {
      containers: [
        {
          name: 'mcp'
          image: image
          resources: { cpu: json('0.5'), memory: '1Gi' }
          env: [
            { name: 'TRA_ENTRY', value: 'tra_platform.foundry' }
            { name: 'TRA_ROLE', value: 'mcp-${name}' }
            { name: 'PORT', value: '8000' }
            { name: 'TRA_IDP_ISSUER', value: issuer }
            { name: 'TRA_IDP_JWKS_URL', value: jwks }
            { name: 'TRA_AUDIENCE', value: audiences['mcp-${name}'] }
            { name: 'TRA_ALLOWED_CALLERS', value: join(mcpAllowedCallers, ',') }
            { name: 'AZURE_CLIENT_ID', value: mcpIdentity.properties.clientId }
          ]
          probes: [{ type: 'Liveness', tcpSocket: { port: 8000 } }]
        }
      ]
      scale: { minReplicas: 1, maxReplicas: 3 }
    }
  }
}]

// ------------------------------------------------------------------ role assignments

resource projectPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: acr
  name: guid(acr.id, project.id, roles.acrPull)
  properties: { principalId: project.identity.principalId, principalType: 'ServicePrincipal', roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.acrPull) }
}

resource mcpPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: acr
  name: guid(acr.id, mcpIdentity.id, roles.acrPull)
  properties: { principalId: mcpIdentity.properties.principalId, principalType: 'ServicePrincipal', roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.acrPull) }
}

resource mcpSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, mcpIdentity.id, roles.keyVaultSecretsUser)
  properties: { principalId: mcpIdentity.properties.principalId, principalType: 'ServicePrincipal', roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.keyVaultSecretsUser) }
}

// ------------------------------------------------------------------ outputs

output projectEndpoint string = '${foundry.properties.endpoint}api/projects/${project.name}'
output acrLoginServer string = acr.properties.loginServer
output stateUri string = '${stateAccount.properties.primaryEndpoints.blob}${stateContainer.name}'
output auditUri string = '${auditAccount.properties.primaryEndpoints.blob}${auditContainer.name}'
output stateAccountId string = stateAccount.id
output auditAccountId string = auditAccount.id
output mcpEndpoints object = image == '' ? {} : {
  reference: { endpoint: 'https://${mcpApps[0].properties.configuration.ingress.fqdn}/mcp', audience: audiences['mcp-reference'] }
  artefacts: { endpoint: 'https://${mcpApps[1].properties.configuration.ingress.fqdn}/mcp', audience: audiences['mcp-artefacts'] }
}
output idpIssuer string = issuer
output idpJwksUrl string = jwks
