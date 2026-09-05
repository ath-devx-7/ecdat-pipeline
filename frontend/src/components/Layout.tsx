import { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useParams } from "react-router-dom";
import { api, type Policy } from "../api";

// The frame around every screen: the product name, the scan tabs when a scan
// is open, and the policy staleness banner (§6) — an air-gapped install cannot
// fetch a newer pack, so the UI has to say when the loaded one is old.
export default function Layout() {
  const { scanId } = useParams();
  const [policy, setPolicy] = useState<Policy | null>(null);

  useEffect(() => {
    api.policy().then(setPolicy).catch(() => setPolicy(null));
  }, []);

  const tab = ({ isActive }: { isActive: boolean }) =>
    `rounded-md px-3 py-1.5 text-sm font-medium ${
      isActive ? "bg-slate-900 text-white" : "text-slate-700 hover:bg-slate-200"
    }`;

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-7xl items-center gap-6 px-4 py-3">
          <Link to="/" className="whitespace-nowrap text-lg font-bold tracking-tight">
            Quantum Lens
          </Link>
          <span className="text-xs text-slate-500">
            Enterprise Cryptographic Discovery &amp; Analysis Tool
          </span>
          <nav className="ml-auto flex items-center gap-1">
            <NavLink to="/" end className={tab}>
              New scan
            </NavLink>
            {scanId && (
              <>
                <NavLink to={`/scans/${scanId}`} end className={tab}>
                  Overview
                </NavLink>
                <NavLink to={`/scans/${scanId}/findings`} className={tab}>
                  Findings
                </NavLink>
                <NavLink to={`/scans/${scanId}/drift`} className={tab}>
                  Drift
                </NavLink>
                <NavLink to={`/scans/${scanId}/roadmap`} className={tab}>
                  Roadmap
                </NavLink>
              </>
            )}
          </nav>
        </div>
      </header>
      {policy && <StalenessBanner policy={policy} />}
      <main className="mx-auto max-w-7xl px-4 py-6">
        <Outlet context={{ policy }} />
      </main>
    </div>
  );
}

export function StalenessBanner({ policy }: { policy: Policy }) {
  if (!policy.stale) return null;
  return (
    <div className="border-b border-amber-300 bg-amber-50 px-4 py-2 text-sm text-amber-900">
      <div className="mx-auto max-w-7xl">
        <strong>Policy pack {policy.version} is {policy.age_days} days old</strong> (published{" "}
        {policy.published}; warning threshold {policy.staleness_warning_days} days). An
        air-gapped install cannot fetch updates — a newer pack has to be carried in.
      </div>
    </div>
  );
}
