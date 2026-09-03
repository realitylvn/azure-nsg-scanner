// Deployed as a subscription-scoped module from main.bicep. Assigns the custom
// single-action "NSG Posture Reader" role to the scanner Function's managed
// identity at subscription scope - the scan is subscription-wide by design.
//
// This lives in its own module because the assignment's deterministic name is
// derived from the Function's principal ID, which is a module output of
// resources.bicep and therefore not known at the start of the top-level
// deployment (Bicep BCP120). Passing it in as a parameter here lets the nested
// deployment compute the name once the value is resolved.

targetScope = 'subscription'

@description('Principal ID of the scanner Function App system-assigned identity.')
param functionPrincipalId string

@description('Resource ID of the custom "NSG Posture Reader" role definition.')
param roleDefinitionId string

resource nsgReaderAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, functionPrincipalId, roleDefinitionId)
  properties: {
    roleDefinitionId: roleDefinitionId
    principalId: functionPrincipalId
    principalType: 'ServicePrincipal'
  }
}
