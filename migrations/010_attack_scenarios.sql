-- Quantified attack-scenario analysis over the deterministic workflow graph.
--
-- Every row here is analysis metadata: reviewed financial planning assumptions,
-- model-proposed attack trees, seeded Monte Carlo results, and model-proposed
-- remediations. Nothing in these tables can move money, grant a role, or change
-- an authorization decision; the application never reads them on a banking path.

-- Append-only company financial assumptions. A new reviewed set is a new
-- version; history is never rewritten so a simulation can name the exact
-- figures it used.
CREATE TABLE IF NOT EXISTS company_financial_profiles (
    profile_id UUID PRIMARY KEY,
    version INTEGER NOT NULL UNIQUE CHECK (version > 0),
    profile JSONB NOT NULL CHECK (jsonb_typeof(profile) = 'object'),
    profile_digest CHAR(64) NOT NULL CHECK (profile_digest ~ '^[0-9a-f]{64}$'),
    change_note TEXT NOT NULL DEFAULT '' CHECK (char_length(change_note) <= 500),
    created_by UUID NOT NULL REFERENCES user_accounts(user_id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS company_financial_profiles_version_idx
    ON company_financial_profiles (version DESC);

-- One model request produces one immutable set of MITRE-referenced attack
-- trees, pinned to the graph digest and the financial profile version that
-- were sent with it.
CREATE TABLE IF NOT EXISTS attack_scenario_sets (
    scenario_set_id UUID PRIMARY KEY,
    graph_source TEXT NOT NULL CHECK (
        graph_source IN ('BUILTIN', 'REPOSITORY_SNAPSHOT')
    ),
    repository_graph_snapshot_id UUID NULL
        REFERENCES repository_graph_snapshots(snapshot_id) ON DELETE RESTRICT,
    graph_digest CHAR(64) NOT NULL CHECK (graph_digest ~ '^[0-9a-f]{64}$'),
    financial_profile_version INTEGER NOT NULL CHECK (financial_profile_version >= 0),
    financial_profile_digest CHAR(64) NOT NULL
        CHECK (financial_profile_digest ~ '^[0-9a-f]{64}$'),
    -- The exact figures sent to the model are pinned here so that every later
    -- simulation of this set uses the same assumptions the trees were built on.
    financial_profile JSONB NOT NULL CHECK (jsonb_typeof(financial_profile) = 'object'),
    software_inventory JSONB NOT NULL CHECK (jsonb_typeof(software_inventory) = 'object'),
    model_result JSONB NOT NULL CHECK (jsonb_typeof(model_result) = 'object'),
    created_by UUID NOT NULL REFERENCES user_accounts(user_id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT attack_scenario_sets_snapshot_matches_source CHECK (
        (graph_source = 'REPOSITORY_SNAPSHOT') = (repository_graph_snapshot_id IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS attack_scenario_sets_created_at_idx
    ON attack_scenario_sets (created_at DESC);

-- A seeded Monte Carlo run of one chosen attack tree. Seed and iteration count
-- are stored so any reviewer can reproduce the distribution exactly.
CREATE TABLE IF NOT EXISTS attack_simulations (
    simulation_id UUID PRIMARY KEY,
    scenario_set_id UUID NOT NULL
        REFERENCES attack_scenario_sets(scenario_set_id) ON DELETE RESTRICT,
    scenario_id TEXT NOT NULL CHECK (char_length(scenario_id) BETWEEN 1 AND 120),
    iterations INTEGER NOT NULL CHECK (iterations BETWEEN 1000 AND 50000),
    seed BIGINT NOT NULL CHECK (seed BETWEEN 0 AND 4294967295),
    remediation_plan_id UUID NULL,
    applied_remediation_ids JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(applied_remediation_ids) = 'array'),
    result JSONB NOT NULL CHECK (jsonb_typeof(result) = 'object'),
    created_by UUID NOT NULL REFERENCES user_accounts(user_id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS attack_simulations_scenario_idx
    ON attack_simulations (scenario_set_id, created_at DESC);

-- Model-proposed remediations for one simulated scenario. Every remediation
-- cites attack-tree nodes, graph evidence, and inventory components that were
-- supplied in the request; unknown citations are rejected before storage.
CREATE TABLE IF NOT EXISTS attack_remediation_plans (
    remediation_plan_id UUID PRIMARY KEY,
    simulation_id UUID NOT NULL
        REFERENCES attack_simulations(simulation_id) ON DELETE RESTRICT,
    scenario_set_id UUID NOT NULL
        REFERENCES attack_scenario_sets(scenario_set_id) ON DELETE RESTRICT,
    scenario_id TEXT NOT NULL CHECK (char_length(scenario_id) BETWEEN 1 AND 120),
    model_result JSONB NOT NULL CHECK (jsonb_typeof(model_result) = 'object'),
    created_by UUID NOT NULL REFERENCES user_accounts(user_id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS attack_remediation_plans_simulation_idx
    ON attack_remediation_plans (simulation_id, created_at DESC);

-- Declared after both tables exist: a residual run points back at the plan
-- whose remediations were applied to it.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'attack_simulations_remediation_plan_fkey'
    ) THEN
        ALTER TABLE attack_simulations
            ADD CONSTRAINT attack_simulations_remediation_plan_fkey
            FOREIGN KEY (remediation_plan_id)
            REFERENCES attack_remediation_plans(remediation_plan_id) ON DELETE RESTRICT;
    END IF;
END
$$;

-- The attack lab and the company financial profile are separate administrator
-- concerns from the workflow graph: graph access should not imply the right to
-- change the figures a loss estimate is measured against. Existing BANK_ADMIN
-- accounts keep their previous breadth, matching the 009 migration.
ALTER TABLE admin_permissions
    DROP CONSTRAINT IF EXISTS admin_permissions_scope_check;

ALTER TABLE admin_permissions
    ADD CONSTRAINT admin_permissions_scope_check CHECK (
        scope IN (
            'admin_users',
            'customers',
            'transactions',
            'risk',
            'audit',
            'asvs',
            'aspis_auditors',
            'reconciliation',
            'workflows',
            'attack_lab',
            'company_financials'
        )
    );

INSERT INTO admin_permissions (user_id, scope)
SELECT u.user_id, scope.scope
FROM user_accounts u
CROSS JOIN (VALUES ('attack_lab'), ('company_financials')) AS scope(scope)
WHERE u.role = 'BANK_ADMIN'
ON CONFLICT DO NOTHING;
