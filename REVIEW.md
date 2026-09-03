# NSG Scanner — build review & learning log

Personal study companion to this project. Unlike `README.md` (public /
recruiter-facing), this file tracks *why* each decision was made and logs every
`az` / `azd` command as it runs, so the reasoning isn't reconstructed from memory
afterwards. Written progressively at each build checkpoint, same as Cost
Sentinel, the Offboarding Automator, and Drift Detector.

Design spec: `docs/superpowers/specs/2026-09-02-nsg-scanner-design.md`.
Implementation plan: `docs/superpowers/plans/2026-09-02-nsg-scanner.md`.

---

## What this is

Scans a subscription's network security groups for common exposure mistakes —
open RDP/SSH, overly broad inbound rules — and reports what's at risk. A daily
Azure Function runs one KQL query against Azure Resource Graph for every NSG in
the subscription, evaluates each custom inbound rule against a fixed set of risk
criteria, and on any match logs an `NsgExposureFound:` trace that a Log Alert
turns into an email — the same trace → alert → Action Group → inbox chain proven
in Cost Sentinel and Drift Detector.

Fourth and final core project in the portfolio. Forks **Drift Detector's**
skeleton (which is itself Cost Sentinel's pattern, carried forward once already):
`azd` + Python Consumption Function + subscription-scoped Bicep + GitHub Actions
validation. The Resource Graph query, the exposure-evaluation logic, the custom
RBAC role, and the deliberately-flawed demo target are net-new.

---

## Checkpoint 1 — scaffold (Task 1)

- **Forked from Drift Detector, not Cost Sentinel directly.** Project 3 already
  carried Cost Sentinel's pattern forward once (single-file `function_app.py`
  with the pure logic split from the I/O shell, the account-key dedupe blob, the
  two-alert Bicep, validation-only CI, `==`-pinned deps). Starting from the more
  recent copy means less to re-adapt. What changes regardless of fork source:
  the enumeration mechanism (Azure Resource Graph, not a per-resource management
  SDK) and the decision logic (`evaluate_exposure`, not `evaluate_drift`).

- **Dependency swap.** `azure-mgmt-storage` (Drift Detector read one storage
  account directly) is dropped; `azure-mgmt-resourcegraph==8.0.1` is added. All
  four runtime deps pinned with `==` and verified to resolve
  (`py -m pip download -r function/requirements.txt --no-deps`) — the
  reproducible-build discipline from Cost Sentinel's two lost deploy cycles.
  `azure-functions==1.25.0`, `azure-identity==1.25.3`, `azure-storage-blob==12.30.1`
  reused unchanged from Drift Detector's validated set.

- **The demo target ships in the main deploy.** Drift Detector split its
  reference storage account into a separate `az deployment group create` because
  it needed a cross-resource-group `Reader` assignment ordered after that group
  existed, and because a false-positive-sensitive before/after demo wanted a
  clean "legitimate redeploy = zero drift" one-liner. Neither applies here: the
  scanner's RBAC assignment is at *subscription* scope (nothing to order against
  a demo RG), and the scanner's value is "here's what's already wrong" — a clean
  first-run finding is the whole demo, no revert step. So `infra/main.bicep`
  creates both resource groups and both modules in one `azd up`, with no manual
  portal step. `azd down` removes the demo too — documented, not a surprise.

- **No compiled-template artifact.** Drift Detector shipped
  `reference_template.json` (a compiled Bicep template as its definition of
  intended state) plus a CI freshness job. The NSG Scanner has neither — the demo
  NSG is a *scan target*, evaluated against fixed risk criteria, not diffed
  against an expected template.

- **`test_function_indexes.py` first (TDD, red → green).** Asserts the worker
  indexes exactly `["nsg_scan"]` with a single `timerTrigger` binding — the check
  a plain `azd deploy` skips (it reports success even when zero functions load,
  which bit Cost Sentinel twice). Failed with `ModuleNotFoundError: function_app`,
  then passed once the minimal timer stub was written.

- **Repo hygiene from the start.** `git init` on 2026-09-02; `.gitignore` covers
  `.azure` (azd env files carry the subscription ID) and `docs/superpowers/`
  (spec + plan are internal working material — auditable on the workstation, not
  shipped in the portfolio repo). Branch `build/nsg-scanner-v1`, merges back via
  the finishing-a-development-branch flow.

### AZ-900 / AZ-104 domains touched at this checkpoint

- **IaC / reproducible builds** — `==`-pinned dependencies, conscious SDK
  selection, verified resolution before first use.
- **Data protection in version control** — `.gitignore` scoped so internal
  planning docs and azd env files (subscription ID) never enter history;
  placeholder tokens the rule for every committed file.

---

## Checkpoint 2 — Function entrypoint (Tasks 2–4)

- **Pure logic split from the I/O shell, same as Cost Sentinel and Drift
  Detector.** `evaluate_exposure` takes a list of normalized NSG dicts plus
  config (sensitive ports, last-alert timestamp, now, cooldown) and returns a
  `ScanDecision` — no Azure calls, no clock, no globals. Every risk rule is
  covered by a branch test (16 in `test_exposure_logic.py`): benign HTTPS is
  clean, a deny rule is clean, an outbound rule is clean, a UDP-only rule is
  clean, `0.0.0.0/0` counts as internet-facing, a private CIDR does not, the
  cooldown suppresses and then re-alerts.

- **Port ranges are evaluated by integer containment, not string match.** A rule
  opening `3000-4000` to the internet is a finding for *both* MySQL (3306) and
  RDP (3389) — one broad range rule produces one finding per sensitive port it
  spans. `100-200` produces nothing. This is the port-range edge case from the
  kickoff, and the reason `_port_spec_matches` parses `LO-HI` rather than
  comparing strings.

- **`build_nsg_list` absorbs the two ARM shapes.** Azure populates exactly one of
  `sourceAddressPrefix` (string) or `sourceAddressPrefixes` (array) per rule, and
  likewise for destination ports. The normalizer merges both into one list and
  drops `None`/empty, so `evaluate_exposure` never sees the split.
  `defaultSecurityRules` is discarded here — none of the platform defaults allow
  inbound Internet to a sensitive port, and evaluating them would produce noise.

- **Entrypoint is a thin shell.** `nsg_scan` reads five env vars, runs one KQL
  query via `ResourceGraphClient` (paged on `skip_token`), hands the rows to
  `build_nsg_list` then `evaluate_exposure`, and logs one of four outcomes.

- **Two distinct failure paths, deliberately different.** A transient
  `AzureError` from Resource Graph (throttle, 5xx) logs *without* a prefix and
  returns — a one-off blip must not page anyone. Any *other* exception logs with
  the `NsgScannerError:` prefix that the severity-2 alert matches, because an
  unexpected failure means the scanner can't be trusted to have run. This mirrors
  Drift Detector's `AzureError` vs bare-`Exception` split.

- **Dedupe blob reached with an account-key connection string, not the managed
  identity.** The identity holds one control-plane role
  (`Microsoft.Network/networkSecurityGroups/read`); it has no data-plane role on
  the storage account. `STATE_STORAGE_CONNECTION_STRING` is the same account key
  already present for `AzureWebJobsStorage`. Adding a `Storage Blob Data`
  assignment just to write one timestamp would widen the identity for no
  isolation gain — the exact bug that cost Cost Sentinel and Drift Detector a
  checkpoint each, avoided here by design.

- **Worker-indexing check reproduced locally.** `function_app.app.get_functions()`
  returns exactly `['nsg_scan']` / `['timerTrigger']` after the new
  `azure-mgmt-resourcegraph` / `azure-storage-blob` imports are added — a broken
  import would register zero functions in Azure while `azd deploy` still reports
  success.

### AZ-900 / AZ-104 domains touched at this checkpoint

- **Azure Resource Graph** — subscription-wide resource querying with KQL, the
  AZ-104 "manage and monitor resources" tool for fleet-scale questions.
- **Network security groups** — inbound rule model (`direction`, `access`,
  `protocol`, source prefix, destination port range, priority), custom vs default
  rules.
- **Least privilege / identity** — control-plane vs data-plane role distinction;
  reusing an in-boundary credential instead of adding a role.
- **Testable design** — pure decision function with branch coverage, I/O isolated
  to an entrypoint that itself has no business logic.

---

## Checkpoint 3 — Bicep (Tasks 5–8)

- **One `azd up`, two resource groups.** `main.bicep` (`targetScope = 'subscription'`)
  creates `rg-nsg-scanner-dev` (the scanner) and `rg-nsg-scanner-demo-dev` (the
  deliberately-flawed target) and deploys a module into each. Drift Detector
  split its reference target into a separate hand-run deploy because it needed a
  cross-RG role assignment ordered after that group existed, and because its
  before/after demo wanted a clean "redeploy = zero drift" one-liner. Neither
  applies here: the scanner's assignment is subscription-scoped (nothing to order
  against a demo RG) and the demo's whole point is a first-run finding. `azd down`
  removes both — stated in the README, not a surprise.

- **Custom single-action role instead of built-in Reader.**
  `NSG Posture Reader (nsg-scanner-dev)` grants exactly
  `Microsoft.Network/networkSecurityGroups/read` and nothing else. Built-in
  `Reader` would grant read on every resource type in the subscription — far more
  than the scan needs. Subscription scope is the one deliberate width: the scan
  is subscription-wide by design, which is the genuine self-use case, not scope
  creep. Built-in `Reader` at subscription scope stays documented as the fallback
  if the custom action set turns out to be insufficient for Resource Graph
  (verified live at Task 9 — **the custom role was sufficient; fallback not
  used**).

- **The role assignment is its own module (`rbac.bicep`).** Bicep BCP120 forbids
  deriving a resource's name from a value not known at the start of the
  deployment, and the assignment's deterministic `guid()` name uses the
  Function's principal ID — a `resources.bicep` output. Passing that output into
  a subscription-scoped nested module lets the name be computed once the value
  resolves. Same reason Drift Detector kept its assignment in `reference-rbac.bicep`.

- **Deploy-time privilege.** Defining a role and assigning it at subscription
  scope needs `Owner` or `User Access Administrator`
  (`Microsoft.Authorization/roleAssignments/write`) — more than the `Contributor`
  a plain resource deploy needs. Jonathan owns the subscription; noted in README
  and here so a future reader with only `Contributor` knows why the deploy fails.

- **`principalType: 'ServicePrincipal'`** on the assignment so it doesn't fail on
  Entra replication lag while the freshly-created managed identity propagates.

- **Demo NSG carries a deliberate true-negative.** Three inbound-Allow-from-Internet
  rules: SSH (22) and RDP (3389) are genuine misconfigurations the scanner must
  flag; HTTPS (443) is benign and must *not* be flagged. Without the 443 rule the
  demo only proves the scanner fires — with it, the demo proves the scanner is
  selective.

- **Alert queries are string-coupled to the Python trace prefixes.**
  `alert-exposure` matches `traces | where message startswith "NsgExposureFound:"`,
  `alert-error` matches `"NsgScannerError:"`. Both scoped to the App Insights
  resource, not the Log Analytics workspace — only that scope exposes the classic
  `traces` table alias (Cost Sentinel's first provision failed on exactly this).
  `groupShortName: 'nsgscanner'` is 10 chars, under the 12-char Action Group limit.

- **CI is validation-only.** `az bicep build` + `pytest`, no cloud credentials, no
  deploy job — provisioning stays a workstation operation (the standing
  no-OIDC-pipeline decision). No reference-freshness job: unlike Drift Detector
  there is no compiled template artifact to keep in sync.

### AZ-900 / AZ-104 domains touched at this checkpoint

- **Virtual networking** — VNet, subnet, NSG association, inbound security rules.
- **RBAC / custom roles** — `roleDefinitions` with a single `Actions` entry,
  `assignableScopes`, control-plane scope choice, deploy-time privilege
  requirements.
- **IaC / deployment scopes** — subscription-scoped Bicep, resource-group
  modules, nested-deployment name resolution (BCP120), `azd` parameter binding.
- **Monitoring** — `scheduledQueryRules` log alerts, Action Groups, alert
  severity, `autoMitigate`.
- **Service limits** — Action Group short-name length, storage account name rules.

---

## Checkpoint 4 — provision & deploy (Task 9)

- **Identity gate before any resource creation.** `az account show` confirmed the
  target is **LVN Subscription** (`<SUBSCRIPTION_ID>`) in tenant `<TENANT_ID>`,
  signed in as `user@contoso.com` — a *user* account, which matters here because
  defining a role and assigning it at subscription scope needs `Owner` /
  `User Access Administrator`, not the `Contributor` a plain resource deploy
  needs. The identifier scan (`git grep` for GUIDs, `/subscriptions/…` paths,
  `*.onmicrosoft.com`) returned only the placeholder rows in
  `azure-naming-conventions.md` — clean before deploy, as required before every
  push and every provision.

- **Preview before apply.** `azd provision --preview` and a full
  `az deployment sub what-if` both came back greenfield — 15 creates, zero
  modifies or deletes, no quota block on the `Microsoft.Web` / Y1 family in
  East US 2. The subscription-scoped **role assignment** does not appear in
  what-if output (`Microsoft.Authorization/roleAssignments` is a documented
  what-if blind spot); it is created by the `rbac.bicep` nested module at deploy
  time and verified directly afterwards.

- **`azd up` — 1 min 43 s** (provisioning 1:11, function deploy 0:32). One
  command, both resource groups, all 15 resources, the remote Oryx build, and the
  function package. No authorization error on the role definition or assignment —
  the `Owner`-on-subscription prerequisite held.

- **Worker indexed exactly `nsg_scan`.** `az functionapp function list` shows one
  function, a single `timerTrigger` binding, `schedule: "0 0 6 * * *"`,
  `runOnStartup: false`, not disabled. This is the check `azd deploy` skips — it
  reports success even when a broken import registers zero functions (Cost
  Sentinel hit that twice). The worker loaded the new
  `azure-mgmt-resourcegraph` / `azure-storage-blob` imports without failure.

- **The custom single-action role works as scoped — no Reader fallback.** This
  was the one live-verified unknown carried since Checkpoint 3: whether
  `Microsoft.Network/networkSecurityGroups/read` alone is enough for the
  Function's managed identity to enumerate NSGs through Azure Resource Graph, or
  whether Resource Graph needs the broader read surface of built-in `Reader`. A
  manual trigger of the deployed function produced, in App Insights, exactly:

  ```
  NsgExposureFound: 2 exposed rule/port combination(s) across 1 NSG(s) -
  nsg-nsg-scanner-demo-dev/allow-rdp-from-internet exposes port 3389 to Internet;
  nsg-nsg-scanner-demo-dev/allow-ssh-from-internet exposes port 22 to Internet
  ```

  The identity read the demo NSG through Resource Graph with no `403` and no
  empty result. The custom role stands; `infra/main.bicep` is unchanged and there
  is nothing to commit from this task. Built-in `Reader` at subscription scope
  remains the documented fallback in Checkpoint 3, now marked "not needed".

- **The account-key dedupe path works.** The same trigger wrote
  `state/last-alert.json` (54 bytes, timestamped to the run) via
  `STATE_STORAGE_CONNECTION_STRING` — the account key already present for
  `AzureWebJobsStorage`, not the managed identity, which holds no data-plane role
  on the storage account. This is the control-plane-vs-data-plane bug that cost
  Cost Sentinel and Drift Detector a checkpoint each; here the write succeeded
  first time.

- **Still pending (Task 10).** The exposure trace and the RBAC/dedupe paths are
  confirmed live; the alert *email* delivery, the second-run `suppressed` cooldown
  trace, and a synthetic `NsgScannerError:` injection are the remaining end-to-end
  checks.

### AZ-900 / AZ-104 domains touched at this checkpoint

- **Provisioning & deployment** — `azd up` (provision + package + deploy in one),
  ARM what-if as a pre-apply safety check, deployment scopes.
- **RBAC in practice** — a custom role definition proven sufficient against a
  real workload; the deploy-time privilege (`Owner` / UAA) that assigning at
  subscription scope requires.
- **Managed identity** — system-assigned identity reading cross-resource-group
  data through Resource Graph with a single control-plane action.
- **Monitoring & diagnostics** — App Insights `traces`, manual function trigger
  via the admin API, verifying deployment by observed behaviour not exit code.

---

## Command log

IDs in commands and pasted output are redacted to the placeholders in
`azure-naming-conventions.md` at the moment of capture, not in a later pass.

| Command | What it did / why |
|---|---|
| `git init` / `git config user.*` | Project-scoped repo inside `azure-nsg-scanner/`, isolated from any stray `.git` higher up the tree. |
| `git branch -m master main` / `git checkout -b build/nsg-scanner-v1` | Renamed the default branch to `main` for portfolio consistency; feature branch for the implementation work. |
| `py -m venv .venv` + `.venv\Scripts\pip install -r requirements-dev.txt` | Local test environment. `requirements-dev.txt` pulls in `function/requirements.txt` so the unit tests import the same pinned runtime deps that deploy. |
| `py -m pip download -r function/requirements.txt --no-deps --dest %TEMP%\nsgver` | Verified all four pinned runtime versions resolve before committing them. All four `Saved`. |
| `.venv\Scripts\pytest tests/test_function_indexes.py -v` | Red then green: the worker-indexing test failed on `ModuleNotFoundError: function_app`, then passed once `function/function_app.py` had the `nsg_scan` timer stub. |
| `.venv\Scripts\pytest -q` (Tasks 2–4) | Red → green per task: `test_exposure_logic.py` (16), `test_normalization.py` (6), then the full suite at 23 passed after the entrypoint landed. |
| `python -c "import function_app; function_app.app.get_functions()"` (run from `function/`) | Post-entrypoint worker-indexing check: returns `['nsg_scan']` / `['timerTrigger']` with the new `azure-mgmt-resourcegraph` + `azure-storage-blob` imports resolving. |
| `az bicep build --file infra/resources.bicep --stdout` | Compiled clean (module scope note expected — `main.bicep` sets `targetScope`). |
| `az bicep build --file infra/demo.bicep --stdout` | Compiled clean. |
| `az bicep build --file infra/main.bicep --stdout` | First run: `BCP120` on the role-assignment name (derived from a module output). Fixed by extracting `infra/rbac.bicep`; recompiled clean. |
| `az account show` | Confirmed target: LVN Subscription (`<SUBSCRIPTION_ID>`), tenant `<TENANT_ID>`, user `user@contoso.com`. Ran before the azd env was touched. |
| `azd env new nsg-scanner-dev` + `azd env set AZURE_LOCATION / AZURE_SUBSCRIPTION_ID / NOTIFICATION_EMAIL` | Created and populated the azd environment. Subscription ID and email set from real values locally; they live only in the git-ignored `.azure/` tree. |
| `azd provision --preview` | Greenfield preview — 2 RGs + function stack + VNet, no quota block. (azd's preview under-reports; see next row.) |
| `az deployment sub what-if --template-file infra/main.bicep …` | Full pre-apply diff: 15 creates, 0 modify/delete, including the custom role definition and both alert rules. `roleAssignments` not shown (what-if limitation). |
| `azd up` | Provision + deploy in one, 1 min 43 s. All resources created; function package deployed and built remotely. |
| `az functionapp function list -g rg-nsg-scanner-dev -n <FUNCTION_APP_NAME> -o table` | Worker-index check: exactly `nsg_scan`, `timerTrigger`, `0 0 6 * * *`, not disabled. |
| `az role definition list --custom-role-only true` / `az role assignment list --assignee <PRINCIPAL_ID>` | Confirmed the custom `NSG Posture Reader` role (single action, subscription scope) and its one assignment to the Function's managed identity. |
| `curl -X POST …/admin/functions/nsg_scan -H "x-functions-key: ***"` | Manual trigger of the deployed timer function (HTTP 202) to verify RBAC live. |
| `az monitor app-insights query --analytics-query "traces \| where …"` | Retrieved the run's trace: the expected `NsgExposureFound: 2 …` line naming SSH(22) + RDP(3389), 443 absent. |
| `az storage blob show --connection-string *** -c state -n last-alert.json` | Confirmed the dedupe blob was written by the run via the account-key connection string. |
