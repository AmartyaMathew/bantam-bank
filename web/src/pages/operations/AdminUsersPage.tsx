import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck, UserCog, UserPlus } from "lucide-react";
import { useMemo, useState } from "react";
import type { FormEvent } from "react";
import { api } from "../../api";
import { Button, EmptyState, ErrorState, LoadingState, PageHeader, Panel, StatusPill, useToast } from "../../components/ui";
import type { AdminPermissionScope } from "../../types";
import { formatDate, humanize, shortId } from "../../utils";

const permissionLabels: Record<AdminPermissionScope, string> = {
  admin_users: "Create admins",
  customers: "Customers & KYC",
  transactions: "Transactions",
  risk: "Risk queue",
  audit: "Audit trail",
  asvs: "ASVS assurance",
  aspis_auditors: "Auditor approvals",
  reconciliation: "Reconciliation",
  workflows: "Workflow graph",
  attack_lab: "Attack lab",
  company_financials: "Company financials",
};

const starterPermissions: AdminPermissionScope[] = ["customers", "transactions"];

export function AdminUsersPage() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [form, setForm] = useState({
    email: "",
    password: "",
    permissions: starterPermissions,
  });
  const query = useQuery({ queryKey: ["admin-users"], queryFn: api.adminUsers });
  const permissions = useMemo(
    () => query.data?.available_permissions ?? (Object.keys(permissionLabels) as AdminPermissionScope[]),
    [query.data],
  );
  const create = useMutation({
    mutationFn: api.createAdminUser,
    onSuccess: (created) => {
      queryClient.invalidateQueries({ queryKey: ["admin-users"] });
      setForm({ email: "", password: "", permissions: starterPermissions });
      toast.success("Admin created", created.email);
    },
    onError: (error) => toast.error("Admin creation failed", error),
  });

  const togglePermission = (scope: AdminPermissionScope) => {
    setForm((current) => {
      const selected = current.permissions.includes(scope);
      return {
        ...current,
        permissions: selected
          ? current.permissions.filter((permission) => permission !== scope)
          : [...current.permissions, scope],
      };
    });
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    create.mutate(form);
  };

  if (query.isLoading) return <LoadingState label="Loading admin users" />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => query.refetch()} />;

  const users = query.data?.users ?? [];

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Super admin"
        title="Admin users"
        description="Create scoped bank administrators and control which operational workspaces they can access."
      />
      <Panel>
        <form className="registration-form" onSubmit={submit}>
          <div className="field-row">
            <label>
              Admin email
              <input
                type="email"
                value={form.email}
                onChange={(event) => setForm((current) => ({ ...current, email: event.target.value }))}
                autoComplete="off"
                required
              />
            </label>
            <label>
              Temporary password
              <input
                type="password"
                value={form.password}
                onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))}
                minLength={14}
                autoComplete="new-password"
                required
              />
              <small>The admin should change this pattern after first sign-in and enroll TOTP MFA.</small>
            </label>
          </div>
          <div className="permission-grid" role="group" aria-label="Admin permissions">
            {permissions.map((scope) => (
              <label className="permission-option" key={scope}>
                <input
                  type="checkbox"
                  checked={form.permissions.includes(scope)}
                  onChange={() => togglePermission(scope)}
                />
                <span>
                  <strong>{permissionLabels[scope] ?? humanize(scope)}</strong>
                  <small>{scope}</small>
                </span>
              </label>
            ))}
          </div>
          <Button type="submit" disabled={create.isPending || form.permissions.length === 0}>
            {create.isPending ? "Creating admin..." : <><UserPlus size={17} /> Create admin</>}
          </Button>
        </form>
      </Panel>
      <Panel padded={false}>
        {users.length === 0 ? (
          <EmptyState
            title="No bank admins"
            description="Create a scoped admin to delegate operational access."
          />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Admin</th>
                  <th>Status</th>
                  <th>MFA</th>
                  <th>Permissions</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <tr key={user.user_id}>
                    <td>
                      <div className="identity-cell">
                        <span className="avatar small"><UserCog size={16} /></span>
                        <div>
                          <strong>{user.email}</strong>
                          <code>{shortId(user.user_id)}</code>
                          {user.is_super_admin && <span className="decision-complete"><ShieldCheck size={15} /> Super admin</span>}
                        </div>
                      </div>
                    </td>
                    <td><StatusPill value={user.status} /></td>
                    <td><StatusPill value={user.mfa_enabled ? "ENABLED" : "NOT_ENABLED"} /></td>
                    <td>
                      <div className="tag-list">
                        {user.permissions.map((permission) => (
                          <span className="tag" key={permission}>{permissionLabels[permission] ?? humanize(permission)}</span>
                        ))}
                      </div>
                    </td>
                    <td>{formatDate(user.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
