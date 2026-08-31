-- Immutable, commit-pinned repository graphs. Repository source is parsed but
-- never imported or executed. Mistral output is display-only metadata over the
-- deterministic graph stored in graph.
CREATE TABLE IF NOT EXISTS repository_graph_snapshots (
    snapshot_id UUID PRIMARY KEY,
    repository TEXT NOT NULL CHECK (
        repository ~ '^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$'
    ),
    requested_ref TEXT NOT NULL CHECK (char_length(requested_ref) BETWEEN 1 AND 180),
    root_path TEXT NOT NULL DEFAULT '' CHECK (char_length(root_path) <= 500),
    resolved_commit TEXT NOT NULL CHECK (resolved_commit ~ '^[0-9a-f]{40,64}$'),
    language TEXT NOT NULL CHECK (language IN ('python', 'terraform', 'mixed')),
    source_sha256 CHAR(64) NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}$'),
    graph_digest CHAR(64) NOT NULL CHECK (graph_digest ~ '^[0-9a-f]{64}$'),
    graph JSONB NOT NULL CHECK (jsonb_typeof(graph) = 'object'),
    model_result JSONB NOT NULL CHECK (jsonb_typeof(model_result) = 'object'),
    created_by UUID NOT NULL REFERENCES user_accounts(user_id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS repository_graph_snapshots_created_at_idx
    ON repository_graph_snapshots (created_at DESC);

CREATE INDEX IF NOT EXISTS repository_graph_snapshots_source_idx
    ON repository_graph_snapshots (repository, root_path, created_at DESC);

-- Administrator-authored views over built-in or repository workflow graphs.
-- These definitions document existing code paths; they never execute banking
-- operations or alter authorization policy.
CREATE TABLE IF NOT EXISTS workflow_definitions (
    workflow_id UUID PRIMARY KEY,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 3 AND 100),
    description TEXT NOT NULL DEFAULT '' CHECK (char_length(description) <= 500),
    actor_role TEXT NOT NULL CHECK (
        actor_role IN (
            'PUBLIC',
            'CUSTOMER',
            'BANK_ADMIN',
            'RISK_ANALYST',
            'COMPLIANCE_AUDITOR',
            'ASPIS_AUDITOR',
            'ASPIS_ADMIN',
            'SYSTEM'
        )
    ),
    node_ids JSONB NOT NULL CHECK (
        jsonb_typeof(node_ids) = 'array'
        AND jsonb_array_length(node_ids) BETWEEN 1 AND 160
    ),
    graph_digest CHAR(64) NOT NULL CHECK (graph_digest ~ '^[0-9a-f]{64}$'),
    repository_graph_snapshot_id UUID NULL REFERENCES repository_graph_snapshots(snapshot_id)
        ON DELETE RESTRICT,
    created_by UUID NOT NULL REFERENCES user_accounts(user_id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS workflow_definitions_created_at_idx
    ON workflow_definitions (created_at DESC);

CREATE INDEX IF NOT EXISTS workflow_definitions_repository_graph_idx
    ON workflow_definitions (repository_graph_snapshot_id, created_at DESC);
