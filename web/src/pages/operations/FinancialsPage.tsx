import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  BadgePoundSterling,
  Building2,
  History,
  RotateCcw,
  Save,
  ShieldAlert,
  TriangleAlert,
  Users,
} from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../../api";
import { useAuth } from "../../auth";
import {
  Button,
  ErrorState,
  LoadingState,
  PageHeader,
  Panel,
  useToast,
} from "../../components/ui";
import { formatDate, formatGbp, shortId } from "../../utils";
import type { CompanyFinancialProfile } from "../../types";

type Section = keyof Pick<
  CompanyFinancialProfile,
  "income" | "balance_sheet" | "operations" | "risk_appetite" | "insurance"
>;

interface FieldSpec {
  section: Section;
  field: string;
  label: string;
  hint: string;
  unit: "gbp" | "count" | "percent";
}

// Every figure the simulator or a model prompt can read is declared here, so a
// reviewer can see the whole surface in one place rather than hunting through
// the form.
const FIELDS: FieldSpec[] = [
  { section: "income", field: "annual_revenue_gbp", label: "Annual revenue", hint: "Total income for the reporting year.", unit: "gbp" },
  { section: "income", field: "net_income_gbp", label: "Net income", hint: "Profit after operating expenses.", unit: "gbp" },
  { section: "income", field: "operating_expenses_gbp", label: "Operating expenses", hint: "Annual cost of running the bank.", unit: "gbp" },
  { section: "balance_sheet", field: "total_assets_gbp", label: "Total assets", hint: "Everything the bank holds.", unit: "gbp" },
  { section: "balance_sheet", field: "customer_deposits_gbp", label: "Customer deposits", hint: "Money owed back to customers.", unit: "gbp" },
  { section: "balance_sheet", field: "shareholder_equity_gbp", label: "Shareholder equity", hint: "Assets minus liabilities; the loss-absorbing buffer.", unit: "gbp" },
  { section: "balance_sheet", field: "liquid_reserves_gbp", label: "Liquid reserves", hint: "Cash available at short notice.", unit: "gbp" },
  { section: "operations", field: "active_customers", label: "Active customers", hint: "Accounts in regular use.", unit: "count" },
  { section: "operations", field: "daily_payment_volume_gbp", label: "Daily payment volume", hint: "Value moved on an average day.", unit: "gbp" },
  { section: "operations", field: "average_payment_gbp", label: "Average payment", hint: "Typical single transfer size.", unit: "gbp" },
  { section: "operations", field: "employees", label: "Employees", hint: "Headcount available to respond to an incident.", unit: "count" },
  { section: "risk_appetite", field: "impact_tolerance_gbp", label: "Impact tolerance", hint: "The board's maximum tolerable annual loss.", unit: "gbp" },
  { section: "risk_appetite", field: "maximum_credible_single_loss_gbp", label: "Maximum credible single loss", hint: "Caps any one simulated event.", unit: "gbp" },
  { section: "risk_appetite", field: "annual_security_budget_gbp", label: "Annual security budget", hint: "What remediation proposals should respect.", unit: "gbp" },
  { section: "risk_appetite", field: "cost_of_capital_pct", label: "Cost of capital", hint: "Used when judging whether a control pays back.", unit: "percent" },
  { section: "insurance", field: "cyber_cover_gbp", label: "Cyber cover limit", hint: "Most the insurer pays in a year.", unit: "gbp" },
  { section: "insurance", field: "retention_gbp", label: "Insurance retention", hint: "The excess the bank pays on every event.", unit: "gbp" },
];

const SECTION_TITLES: Record<Section, string> = {
  income: "Income statement",
  balance_sheet: "Balance sheet",
  operations: "Operating profile",
  risk_appetite: "Risk appetite",
  insurance: "Insurance programme",
};

const SECTION_ORDER: Section[] = [
  "income",
  "balance_sheet",
  "operations",
  "risk_appetite",
  "insurance",
];

function readField(profile: CompanyFinancialProfile, spec: FieldSpec): number {
  const section = profile[spec.section] as unknown as Record<string, number>;
  return section[spec.field] ?? 0;
}

function writeField(
  profile: CompanyFinancialProfile,
  spec: FieldSpec,
  value: number,
): CompanyFinancialProfile {
  return {
    ...profile,
    [spec.section]: { ...profile[spec.section], [spec.field]: value },
  };
}

function formatField(value: number, unit: FieldSpec["unit"]): string {
  if (unit === "gbp") return formatGbp(value);
  if (unit === "percent") return `${value}%`;
  return new Intl.NumberFormat("en-GB").format(value);
}

export function FinancialsPage() {
  const toast = useToast();
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const query = useQuery({ queryKey: ["company-financials"], queryFn: api.companyFinancials });
  const [draft, setDraft] = useState<CompanyFinancialProfile | null>(null);
  const [changeNote, setChangeNote] = useState("");
  const canEdit = user?.role === "BANK_ADMIN";

  const current = query.data?.current;
  useEffect(() => {
    if (current) setDraft(current.profile);
  }, [current]);

  const mutation = useMutation({
    mutationFn: (profile: CompanyFinancialProfile) =>
      api.updateCompanyFinancials(profile, changeNote),
    onSuccess: (saved) => {
      toast.success(`Version ${saved.version} saved`, "New attack-tree analyses will use these figures.");
      setChangeNote("");
      queryClient.invalidateQueries({ queryKey: ["company-financials"] });
      queryClient.invalidateQueries({ queryKey: ["attack-scenarios"] });
    },
    onError: (error) => toast.error("The profile was not saved", error),
  });

  if (query.isError) return <ErrorState error={query.error} onRetry={() => query.refetch()} />;
  const overview = query.data;
  if (!overview || !draft || !current) return <LoadingState label="Loading company financials" />;
  const dirty = JSON.stringify(draft) !== JSON.stringify(current.profile);

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Risk quantification inputs"
        title="Company financials"
        description="The figures every attack-tree cost estimate and Monte Carlo simulation is measured against. Change a number here and the next analysis uses it."
        action={
          canEdit ? (
            <Button onClick={() => mutation.mutate(draft)} disabled={!dirty || mutation.isPending}>
              <Save size={16} /> {mutation.isPending ? "Saving…" : "Save reviewed version"}
            </Button>
          ) : undefined
        }
      />

      <Panel className="financials-scope">
        <span><TriangleAlert size={22} /></span>
        <div>
          <strong>These are planning assumptions, not accounts</strong>
          <p>{draft.statement_of_scope}</p>
        </div>
      </Panel>

      <div className="metric-grid">
        <Panel className="metric-card">
          <div className="metric-card-head"><span>Annual revenue</span><BadgePoundSterling /></div>
          <strong>{formatGbp(draft.income.annual_revenue_gbp)}</strong>
          <small>{draft.legal_entity}</small>
        </Panel>
        <Panel className="metric-card">
          <div className="metric-card-head"><span>Impact tolerance</span><ShieldAlert /></div>
          <strong>{formatGbp(draft.risk_appetite.impact_tolerance_gbp)}</strong>
          <small>Annual loss the board will accept</small>
        </Panel>
        <Panel className="metric-card">
          <div className="metric-card-head"><span>Shareholder equity</span><Building2 /></div>
          <strong>{formatGbp(draft.balance_sheet.shareholder_equity_gbp)}</strong>
          <small>Loss-absorbing buffer</small>
        </Panel>
        <Panel className="metric-card">
          <div className="metric-card-head"><span>Active customers</span><Users /></div>
          <strong>{new Intl.NumberFormat("en-GB").format(draft.operations.active_customers)}</strong>
          <small>{draft.operations.employees} employees</small>
        </Panel>
      </div>

      {SECTION_ORDER.map((section) => (
        <Panel key={section} padded={false}>
          <div className="panel-heading panel-heading-padded">
            <div>
              <p className="eyebrow">{SECTION_TITLES[section]}</p>
              <h2>{SECTION_TITLES[section]}</h2>
            </div>
          </div>
          <div className="financial-field-grid">
            {FIELDS.filter((spec) => spec.section === section).map((spec) => (
              <label key={`${spec.section}.${spec.field}`} className="financial-field">
                <span>{spec.label}</span>
                <input
                  type="number"
                  min={0}
                  step={spec.unit === "percent" ? 0.1 : 1}
                  value={readField(draft, spec)}
                  disabled={!canEdit}
                  onChange={(event) =>
                    setDraft(writeField(draft, spec, Number(event.target.value)))
                  }
                />
                <small>{spec.hint}</small>
                <em>{formatField(readField(draft, spec), spec.unit)}</em>
              </label>
            ))}
          </div>
        </Panel>
      ))}

      <Panel padded={false}>
        <div className="panel-heading panel-heading-padded">
          <div>
            <p className="eyebrow">Regulatory context</p>
            <h2>{draft.regulatory.regime}</h2>
          </div>
        </div>
        <div className="financial-field-grid">
          <div className="financial-field static">
            <span>Maximum penalty</span>
            <strong>{draft.regulatory.maximum_penalty_pct_of_revenue}% of revenue</strong>
            <small>Upper bound on a regulatory fine used when sizing secondary loss.</small>
          </div>
          <div className="financial-field static">
            <span>Breach notification window</span>
            <strong>{draft.regulatory.notification_window_hours} hours</strong>
            <small>Where notification is required, it is made without undue delay and within this window where feasible.</small>
          </div>
          <div className="financial-field static">
            <span>Fiscal year</span>
            <strong>{draft.fiscal_year}</strong>
            <small>The reporting year these assumptions describe.</small>
          </div>
        </div>
      </Panel>

      {draft.notes.length > 0 && (
        <Panel>
          <p className="eyebrow">How these figures are used</p>
          <ul className="financial-notes">
            {draft.notes.map((note) => <li key={note}>{note}</li>)}
          </ul>
        </Panel>
      )}

      {canEdit && (
        <Panel>
          <p className="eyebrow">Save a reviewed version</p>
          <h2>Every version is kept</h2>
          <p>Saving appends an immutable version. Analyses already run keep the figures they were built on, so an old simulation never changes underneath a decision.</p>
          <label className="financial-note-field">
            <span>What changed and who approved it</span>
            <input
              type="text"
              maxLength={500}
              value={changeNote}
              placeholder="Finance sign-off for FY26 planning figures"
              onChange={(event) => setChangeNote(event.target.value)}
            />
          </label>
          <div className="financial-actions">
            <Button onClick={() => mutation.mutate(draft)} disabled={!dirty || mutation.isPending}>
              <Save size={16} /> {mutation.isPending ? "Saving…" : "Save reviewed version"}
            </Button>
            <Button variant="secondary" onClick={() => setDraft(overview.repository_default)}>
              <RotateCcw size={16} /> Load repository defaults
            </Button>
            <Button variant="ghost" onClick={() => setDraft(current.profile)} disabled={!dirty}>
              Discard changes
            </Button>
          </div>
        </Panel>
      )}

      <Panel padded={false}>
        <div className="panel-heading panel-heading-padded">
          <div>
            <p className="eyebrow">Version history</p>
            <h2>Reviewed versions</h2>
          </div>
          <span className="graph-digest"><History size={14} /> current v{current.version}</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Version</th><th>Saved</th><th>Note</th><th>Digest</th></tr>
            </thead>
            <tbody>
              {overview.history.length === 0 ? (
                <tr><td colSpan={4}>No reviewed version saved yet; the repository defaults are in use.</td></tr>
              ) : (
                overview.history.map((entry) => (
                  <tr key={entry.profile_id}>
                    <td>v{entry.version}</td>
                    <td>{formatDate(entry.created_at, true)}</td>
                    <td>{entry.change_note || "—"}</td>
                    <td><code>{shortId(entry.profile_digest)}</code></td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
