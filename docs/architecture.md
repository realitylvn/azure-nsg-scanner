# Architecture

```mermaid
%%{init: {'theme':'base', 'themeVariables': {
  'fontSize':'14px',
  'primaryColor':'#252d3a',
  'primaryTextColor':'#e6e9ef',
  'primaryBorderColor':'#5b6675',
  'lineColor':'#8b95a5',
  'textColor':'#e6e9ef',
  'edgeLabelBackground':'#252d3a'
}}}%%
flowchart LR
    timer(["Timer — daily 06:00 UTC"]) --> fn["nsg_scan<br/>Azure Function · Python · Consumption"]
    fn -->|"custom role · NSG read · subscription scope"| arg["Azure Resource Graph<br/>every NSG in the subscription"]
    fn -->|"read / write timestamp · account key"| state[("last-alert.json<br/>dedupe cooldown")]
    fn -->|"'NsgExposureFound:' / 'NsgScannerError:' trace"| appi["Application Insights"]
    appi --> alerts["Log Alerts<br/>alert-exposure · alert-error"]
    alerts --> ag["Action Group"] --> email(["Email"])
    demo["Demo VNet + NSG<br/>rg-nsg-scanner-demo-dev · open SSH/RDP rules"] -.->|"found by the scan"| arg

    classDef built fill:#1e3a5f,stroke:#5b8fd6,stroke-width:2px,color:#eaf2fb;
    classDef ext   fill:#252d3a,stroke:#5b6675,color:#e6e9ef;
    class fn built;
    class timer,arg,state,appi,alerts,ag,email,demo ext;
```

**Services used:** Bicep + `azd`, Azure Functions (Consumption / Y1), Azure
Resource Graph, Storage (dedupe blob), Log Analytics, Application Insights, Azure
Monitor scheduled query rules, Action Groups. GitHub Actions for template + test
validation.

The scanner stores nothing about past scans. Every run issues one KQL query
against Azure Resource Graph for the current state of every network security
group in the subscription, evaluates each custom inbound rule against a fixed set
of risk criteria (Allow + Inbound + TCP/any + internet-facing source + a
sensitive destination port), and on any match logs a plain-English
`NsgExposureFound:` trace. The only persisted state is a single timestamp blob
that suppresses repeat alerts while an exposure is ongoing.

**Auth:** the Function's system-assigned managed identity holds exactly one role
— a custom role with the single action `Microsoft.Network/networkSecurityGroups/read`,
assigned at subscription scope because the scan is subscription-wide by design.
The dedupe blob is reached with an account-key connection string (an app setting,
encrypted at rest), so no data-plane role is added. No stored secrets, no client
credentials.

**On a finding:** the Function logs `NsgExposureFound:` to Application Insights;
a `scheduledQueryRules` Log Alert matches that trace and fires an Action Group
email. A separate higher-severity rule watches for `NsgScannerError:` — raised on
an unexpected failure — so the scanner cannot silently go dark.
