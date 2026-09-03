targetScope = 'subscription'

@minLength(1)
@maxLength(64)
@description('Name of the azd environment; drives resource naming and the scanner resource group name.')
param environmentName string

@minLength(1)
@description('Azure region for all resources.')
param location string

@description('Days to suppress repeat alerts while an exposure is ongoing.')
param alertCooldownDays int = 3

@description('Email address that receives exposure and scanner-error notifications.')
param notificationEmail string

@description('Comma-separated sensitive destination ports flagged when open to the internet. Default: SSH, RDP, SQL Server, MySQL, PostgreSQL.')
param sensitivePorts string = '22,3389,1433,3306,5432'

@description('Portfolio project slug, used for the "project" tag and the demo resource names.')
param projectSlug string = 'nsg-scanner'

@description('Environment tag value. Distinct from the azd environment name.')
param environmentTag string = 'dev'

var scannerTags = {
  'azd-env-name': environmentName
  portfolio: 'azure-devops-portfolio'
  project: projectSlug
  environment: environmentTag
}

var demoTags = {
  portfolio: 'azure-devops-portfolio'
  project: projectSlug
  environment: environmentTag
}

// Custom single-permission role. Subscription scope is deliberate and justified:
// the scan is subscription-wide by design (the genuine self-use case). This is
// tighter than built-in Reader, which grants read on every resource type.
resource nsgPostureReader 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(subscription().id, 'nsg-posture-reader', environmentName)
  properties: {
    roleName: 'NSG Posture Reader (${environmentName})'
    description: 'Read network security groups only. For the NSG Posture Scanner Function. Single action, subscription scope.'
    type: 'CustomRole'
    assignableScopes: [ subscription().id ]
    permissions: [
      {
        actions: [ 'Microsoft.Network/networkSecurityGroups/read' ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
  }
}

resource scannerRg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: 'rg-${environmentName}'
  location: location
  tags: scannerTags
}

resource demoRg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: 'rg-${projectSlug}-demo-${environmentTag}'
  location: location
  tags: demoTags
}

module resources 'resources.bicep' = {
  name: 'resources'
  scope: scannerRg
  params: {
    location: location
    environmentName: environmentName
    tags: scannerTags
    alertCooldownDays: alertCooldownDays
    notificationEmail: notificationEmail
    sensitivePorts: sensitivePorts
  }
}

module demo 'demo.bicep' = {
  name: 'demo'
  scope: demoRg
  params: {
    location: location
    tags: demoTags
    projectSlug: projectSlug
    environmentTag: environmentTag
  }
}

// Assign the custom role to the Function's managed identity at subscription scope.
// Split into its own module: the assignment name derives from the Function's
// principal ID (a resources.bicep output), which BCP120 forbids in a top-level
// resource name. Deterministic name -> idempotent re-provision; principalType
// avoids a failure on Entra replication lag for the freshly-created identity.
module rbac 'rbac.bicep' = {
  name: 'nsg-reader-assignment'
  scope: subscription()
  params: {
    functionPrincipalId: resources.outputs.functionPrincipalId
    roleDefinitionId: nsgPostureReader.id
  }
}

output AZURE_RESOURCE_GROUP string = scannerRg.name
output FUNCTION_APP_NAME string = resources.outputs.functionAppName
output STORAGE_ACCOUNT_NAME string = resources.outputs.storageAccountName
output DEMO_NSG_NAME string = demo.outputs.nsgName
