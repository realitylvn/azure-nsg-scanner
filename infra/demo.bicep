// Deliberately-flawed demo target for the NSG Scanner. Deployed as a module of
// main.bicep into rg-nsg-scanner-demo-dev - part of the standard `azd up`, no
// separate hand-run deploy and no portal step. `azd down` removes it.
//
// The scanner is subscription-wide; in practice this is the only NSG that will
// exist for it to find. Two rules are genuine misconfigurations (SSH and RDP open
// to the internet); the third (HTTPS/443 open) is benign and must NOT be flagged -
// it proves the scanner is selective, not "everything internet-facing is bad".

@description('Azure region.')
param location string

param tags object

@description('Portfolio project slug - see azure-naming-conventions.md.')
param projectSlug string

@description('Environment tag value.')
param environmentTag string

var nsgName = 'nsg-${projectSlug}-demo-${environmentTag}'
var vnetName = 'vnet-${projectSlug}-demo-${environmentTag}'

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: nsgName
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'allow-ssh-from-internet'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
      {
        name: 'allow-rdp-from-internet'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '3389'
        }
      }
      {
        name: 'allow-https-from-internet'
        properties: {
          priority: 120
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: vnetName
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [ '10.0.0.0/16' ]
    }
    subnets: [
      {
        name: 'snet-workload'
        properties: {
          addressPrefix: '10.0.1.0/24'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}

output nsgName string = nsg.name
