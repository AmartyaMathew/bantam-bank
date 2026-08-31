-- Add a self-service assurance role without granting bank-wide auditor powers.
ALTER TABLE user_accounts
    DROP CONSTRAINT user_accounts_role_check;

ALTER TABLE user_accounts
    ADD CONSTRAINT user_accounts_role_check
    CHECK (
        role IN (
            'CUSTOMER',
            'BANK_ADMIN',
            'RISK_ANALYST',
            'COMPLIANCE_AUDITOR',
            'ASPIS_AUDITOR',
            'SERVICE_ACCOUNT'
        )
    );
