-- Add scoped administrator permissions without changing the coarse role model.
CREATE TABLE IF NOT EXISTS admin_permissions (
    user_id UUID NOT NULL
        REFERENCES user_accounts(user_id) ON DELETE RESTRICT,
    scope TEXT NOT NULL
        CHECK (
            scope IN (
                'admin_users',
                'customers',
                'transactions',
                'risk',
                'audit',
                'asvs',
                'aspis_auditors',
                'reconciliation',
                'workflows'
            )
        ),
    granted_by UUID REFERENCES user_accounts(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, scope)
);

CREATE INDEX IF NOT EXISTS admin_permissions_scope_idx
    ON admin_permissions (scope, user_id);

-- Existing production BANK_ADMIN users retain their previous broad access after
-- the migration. New UI-created administrators receive only selected scopes.
INSERT INTO admin_permissions (user_id, scope)
SELECT u.user_id, scope.scope
FROM user_accounts u
CROSS JOIN (
    VALUES
        ('admin_users'),
        ('customers'),
        ('transactions'),
        ('risk'),
        ('audit'),
        ('asvs'),
        ('aspis_auditors'),
        ('reconciliation'),
        ('workflows')
) AS scope(scope)
WHERE u.role = 'BANK_ADMIN'
ON CONFLICT DO NOTHING;
