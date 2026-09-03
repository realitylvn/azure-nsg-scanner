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
