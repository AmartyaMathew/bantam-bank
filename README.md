# Bantam

Bantam is a synthetic-money digital bank for learning, security engineering,
and operational-resilience analysis. It is not a real bank and must never hold
real customer data, credentials, card data, or funds.

This repository is intentionally deployment-focused. It contains the source
needed to build and run the hardened single-host Docker Compose stack, generate
the deterministic human-readable workflow graph, and publish the interactive
FAIR-informed report to GitHub Pages. Security tests and their small CI-only
Compose harness remain because they are deployment gates, not optional demo
assets.

Bantam is deployed here: https://bantam.live/login

## Deploy Bantam on GCP

For a three-month evaluation, a Compute Engine `e2-medium` (2 vCPU, 4 GiB RAM)
with Ubuntu 24.04 and a 30–50 GiB balanced persistent disk is a comfortable
single-host target for roughly ten concurrent demo users and one repository
graph/Mistral request at a time.

The production bundle lives under `deploy/digitalocean/` for path compatibility,
but it is cloud-neutral and can run on a GCP VM. Follow the
[single-host production runbook](deploy/digitalocean/README.md) for firewall,
DNS, secret generation, TLS, administrator bootstrap, backups, and updates.

The abbreviated deployment sequence is:

```bash
./deploy/digitalocean/prepare.sh \
  bantam.example.com \
  operator@example.com \
  super-admin@example.com

docker compose \
  --env-file deploy/digitalocean/production.env \
  -f deploy/digitalocean/compose.yml build

./deploy/digitalocean/validate-deployment.sh \
  deploy/digitalocean/production.env

docker compose \
  --env-file deploy/digitalocean/production.env \
  -f deploy/digitalocean/compose.yml up -d
```

`prepare.sh` generates independent production secrets and internal TLS
material. It does not create deterministic user passwords. The optional third prepare argument marks a matching `BANK_ADMIN` email as
the super admin for scoped admin RBAC. The first bank administrator is created
interactively with the runbook's `bootstrap-bank-admin` command.

The production React build starts with empty login fields and contains no
Codespaces seed emails or password. `npm run build` fails if one of those
deterministic credentials appears in `web/dist`.

## Publish the FAIR report on GitHub Pages

The report combines the committed workflow catalogue with the reviewed risk
model. It runs Monte Carlo simulations in the browser; no server or browser-side
credential is required.

1. In GitHub, select **Settings → Pages → Build and deployment → GitHub
   Actions**.
2. Merge a reviewed change into `main`.
3. `.github/workflows/resilience-pages.yml` verifies the workflow catalogue,
   tests the public-data boundary, builds an immutable `_site` artifact, and
   deploys it.


HTML cannot watch a repository by itself; the GitHub Actions workflow is what
rebuilds Pages whenever `main` changes.

## Workflow graph and Mistral attack trees

The bank-admin workflow explorer is generated deterministically from Python
ASTs, FastAPI routes, parameterised PostgreSQL operations, and migrations.
Service functions, guards, exact signatures, table reads, locking queries,
durable effects, database constraints, and concise flow explanations are
generated from those sources and available through progressive disclosure.

An administrator may optionally send a bounded, redacted graph projection to
Mistral. Bantam validates the returned JSON and every cited graph/flow ID before
storing and displaying the attack tree. Mistral output cannot add executable
code, authorization decisions, or graph facts.

## Attack trees on GitHub Pages

The published report ships three curated attack trees over Bantam's own code
graph, and lets a reader generate more. Every tree renders in two registers: a
**MITRE ATT&CK view** with technique identifiers, tactics, AND/OR operators and
cited graph evidence, and a **plain-English view** that drops the jargon and
describes each step the way you would explain it to a colleague in the business.
The toggle sits above the tree; both describe the same structure.

`report/attack-trees.json` holds the curated trees, one for each risk scenario in
`report/risk-model.json`. The build checks that every node cites a flow or graph
node that still exists and that the named scenario is real, so a renamed route or
a deleted scenario fails the build rather than shipping a tree that points at
something that is gone.

The tree is drawn as a moveable graph: drag any step, drag the background to pan,
scroll to zoom, and select a step to read it in full. Nodes are focusable, and
arrow keys move a focused step for anyone not using a pointer. Nothing is
loaded to do this — the layout and interaction are a few hundred lines of the
report's own JavaScript, because the page's Content-Security-Policy allows no
third-party script.

Selecting a tree also prices it. A three-assumption view of the Monte Carlo lab
appears below the graph: how often a full traversal happens, what one traversal
costs, what the bank can absorb, and which control programme is in place. It
reports the expected annual loss, the worst year in a hundred, and the share of
years above tolerance, and it hands off to the full lab with the scenario already
selected.


## Attack trees, Monte Carlo, and remediation

The bank-admin and risk-analyst workspaces include an **Attack lab** that turns
the generated graph into quantified loss scenarios. It runs in four steps, and
the boundary between the model's job and Bantam's job is deliberate.

1. **Graph in.** Bantam projects a bounded, redacted slice of the deterministic
   catalogue (or of a pinned repository snapshot), derives a software inventory
   from graph evidence alone, and reads the current company financial profile.
2. **Attack trees out.** Mistral returns several MITRE ATT&CK-referenced attack
   trees with AND/OR decomposition and FAIR-style GBP loss estimates. Bantam
   rejects the whole response if a tree cites a graph node, flow, technique, or
   financial input name it was never sent, or if a tree is not a valid tree.
   ATT&CK links are built locally from the validated identifiers.
3. **Simulation.** An analyst picks one tree, and Bantam - not the model - runs
   the Monte Carlo: attempts per year from a Poisson draw, AND/OR propagation
   through the tree, PERT loss sampling, detection, the maximum credible single
   loss cap, and insurance retention and cover. The seed and iteration count are
   stored with the result, so any run reproduces exactly.
4. **Remediation.** The chosen tree and the simulation summary go back to
   Mistral, which proposes fixes aimed at the attack steps that actually carried
   the successful events, priced against the security budget. Selecting
   remediations re-runs the same seeded simulation, so residual risk and payback
   are computed here rather than claimed by the model.

The **Company financials** page holds every figure those estimates are measured
against - revenue, balance sheet, operating profile, impact tolerance, security
budget, and insurance. Saving appends an immutable version, and each analysis
pins the version it used so an old simulation never changes underneath a
decision. The shipped figures are illustrative planning assumptions for a
synthetic bank, not accounts.

Attack trees are proposals about how an attack could be structured. They are not
confirmed vulnerabilities, and the money is arithmetic over editable
assumptions.

Both workspaces are scoped admin permissions in their own right - `attack_lab`
and `company_financials` - so graph access does not imply the right to change
the figures a loss estimate is measured against. Risk analysts reach both
through their role.

## Repository map

| Path | Deployment purpose |
|---|---|
| `bantam/` | FastAPI service, workers, ledger, security, graph generation, and attack-tree integration |
| `web/` | Production React/Nginx image |
| `migrations/` | PostgreSQL schema and durable invariants |
| `security/aspis/` | ASVS catalogue and normalized evidence support |
| `deploy/digitalocean/` | Hardened cloud-neutral single-host Compose bundle |
| `deploy/docker-compose*.yml` | CI-only live PostgreSQL/NATS authorization and ledger checks |
| `report/` | FAIR model and static GitHub Pages application |
| `bantam/attack_simulation.py` | Attack-tree generation, Monte Carlo engine, and remediation |
| `bantam/financials.py` | Versioned company financial assumptions |
| `bantam/company_financials.json` | Shipped default financial profile |
| `scripts/resilience_report.py` | Public-safe report builder |
| `scripts/attack_tree_library.py` | Shared attack-tree schema, prompt, and structural rules |
| `scripts/generate_attack_trees.py` | Refresh the curated trees where a secret is safe |
| `report/attack-trees.json` | Curated trees in MITRE and plain-English form |
| `tests/` | Deployment security and publication-boundary gates |


