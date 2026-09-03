# Azure Naming & Tagging Convention — Portfolio-Wide Standard

Applies to all five projects (Cost Sentinel, Offboarding Automator, Drift Detector, NSG Scanner, Ops Dashboard). Based on Microsoft's Cloud Adoption Framework naming guidance — not invented for this, so it's also a legitimate AZ-104 governance talking point.

## Pattern

`<resource-type-abbreviation>-<project-slug>-<environment>`

Azd's own uniqueness token still handles global-uniqueness requirements (storage accounts, Function Apps) automatically — this convention governs the human-readable part, not the suffix azd appends.

## Project slugs (one per repo, used everywhere below)

| Project | Slug |
|---|---|
| Azure Cost Sentinel | `cost-sentinel` |
| M365 Offboarding Automator | `offboarding` |
| Infrastructure Drift Detector | `drift-detector` |
| Network Security Scanner | `nsg-scanner` |
| Ops Aggregation Dashboard | `ops-dashboard` |

## Environment

All five are `dev` for now (no prod tier exists for personal portfolio tools). The environment slot stays in the pattern so it's a one-word change if that ever isn't true.

## Resource type abbreviations (CAF standard, only the ones this portfolio uses)

| Resource | Abbreviation | Example |
|---|---|---|
| Resource group | `rg` | `rg-cost-sentinel-dev` |
| Storage account | `st` | `stcostsentineldev<token>` — **no hyphens**, storage account names can't contain them |
| App Service plan | `plan` | `plan-cost-sentinel-dev` |
| Function App | `func` | `func-cost-sentinel-dev` |
| Automation Account | `aa` | `aa-offboarding-dev` |
| Log Analytics workspace | `log` | `log-cost-sentinel-dev` |
| Application Insights | `appi` | `appi-cost-sentinel-dev` |
| Action Group | `ag` | `ag-cost-sentinel-dev` |
| Budget | `budget` | `budget-cost-sentinel-dev` |
| Virtual network | `vnet` | `vnet-nsg-scanner-demo-dev` |
| Subnet | `snet` | `snet-workload` (subnets are named by purpose, not the pattern — they're already scoped by their parent vnet) |
| Network security group | `nsg` | `nsg-scanner-demo-dev` — the slug `nsg-scanner` already leads with the `nsg` abbreviation, so the token is not repeated (see caveat below) |
| Custom role definition | *(none)* | `NSG Posture Reader (nsg-scanner-dev)` — role names must be unique tenant-wide, so the env is suffixed in parentheses |

## Azd environment naming

The azd environment name drives all of the above automatically — set it correctly once at `azd env new`, never leave it as the generic `dev` default:

```
azd env new <project-slug>-dev
```

## Tagging standard

Apply to the resource group (inherited by contained resources where supported) and explicitly on any resource that doesn't inherit:

```
portfolio: azure-devops-portfolio
project: <project-slug>
environment: dev
```

Purpose: the Ops Dashboard project can later query across all resource groups by the `portfolio` tag instead of hardcoding resource group names — small cost now, real convenience once project 5 needs to aggregate across the other four.

## Storage account naming caveat

Storage account names are lowercase alphanumeric only, 3–24 characters, globally unique, no hyphens. The project slug gets concatenated without separators (`stcostsentineldev`) before azd's uniqueness token is appended — verify the combined length stays under 24 characters before the token, since long slugs (`nsg-scanner` → `stnsgscannerdev` is fine, but watch this on any future project with a longer name).

## NSG Scanner demo-resource naming caveat

The NSG Scanner deploys a deliberately-flawed demo VNet + NSG into its own
resource group. The pattern qualifier for these follows Drift Detector's
`rg-drift-detector-reference-dev` precedent — `<abbr>-<slug>-demo-dev`:

- `rg-nsg-scanner-demo-dev`
- `vnet-nsg-scanner-demo-dev`
- `nsg-scanner-demo-dev` — when the slug already leads with the resource-type
  abbreviation (here slug `nsg-scanner`, abbreviation `nsg`), the token is not
  repeated. The mechanical output would be `nsg-nsg-scanner-demo-dev`; the
  duplicate `nsg-` is collapsed so the name reads as a normally-prefixed NSG
  next to its `vnet-` and `rg-` siblings.

## Documentation placeholders (use in every committed file — never the real value)

| Real thing | Placeholder | Example value for illustration |
|---|---|---|
| tenant ID | `<TENANT_ID>` | `aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb` |
| subscription ID | `<SUBSCRIPTION_ID>` | `11111111-0000-2222-3333-444444444444` |
| principal / object ID (managed identity, SP, user) | `<PRINCIPAL_ID>` | — |
| app / client ID | `<CLIENT_ID>` | — |
| resource ID path | `/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RG_NAME>/...` | — |
| tenant domain | `contoso.onmicrosoft.com` | — |
| owner / user email | `user@contoso.com` | — |
| billing account / enrollment ID | `<BILLING_ACCOUNT_ID>` | — |

Resource names built from the pattern above (`func-nsg-scanner-dev`, etc.) carry
no secret and may be shown as-is. GUIDs, resource-ID paths, the real tenant
domain, and real emails are not — replace them with the placeholder at the point
of capture (in `REVIEW.md` command logs, redact the command *and* its output in
the same edit). Redact the azd uniqueness token only where it sits next to a
subscription ID.

Pre-commit scan (run in the project root before every commit and push):

```
git grep -nIE '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|/subscriptions/[0-9a-fA-F-]{36}|[a-z0-9-]+\.onmicrosoft\.com'
```

Every hit that is not an obvious placeholder is a finding — replace and re-scan
until clean.
