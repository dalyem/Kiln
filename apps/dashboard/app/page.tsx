import { type DashboardDoctor, type DashboardGateway, type DashboardIncident, getDashboardData } from "../lib/api";
import { AutoRefresh } from "./auto-refresh";

export const dynamic = "force-dynamic";

function modeBadge(providerMode: string, mutationEnabled: boolean) {
  if (providerMode === "fake") return "FAKE PROVIDER";
  if (!mutationEnabled) return "READ-ONLY";
  return "MUTATION ENABLED";
}

export default async function DashboardPage() {
  const data = await getDashboardData();
  return (
    <main className="mx-auto max-w-6xl p-6 md:p-10">
      <header className="mb-10 flex flex-wrap items-center justify-between gap-4 border-b border-zinc-800 pb-5">
        <div>
          <p className="mb-2 font-mono text-xs tracking-[0.22em] text-amber-300">KILN / INFRASTRUCTURE</p>
          <h1 className="m-0 text-3xl font-semibold tracking-tight">Control plane</h1>
        </div>
        {data.status && <span className="rounded border border-amber-400/50 bg-amber-300/10 px-3 py-1.5 font-mono text-xs font-semibold text-amber-200">{modeBadge(data.status.providerMode, data.status.mutationEnabled)}</span>}
      </header>
      <AutoRefresh checkedAt={data.doctor?.checkedAt} />

      {data.error ? (
        <section className="rounded-md border border-red-400/40 bg-red-400/10 p-5" aria-live="polite">
          <h2 className="m-0 text-base font-semibold">Control plane unavailable</h2>
          <p className="mb-0 mt-2 text-sm text-zinc-300">{data.error}</p>
        </section>
      ) : (
        <>
          <section className="mb-8 grid gap-3 md:grid-cols-4">
            <Stat label="Installation" value={data.status?.installationId ?? "Unknown"} />
            <Stat label="Provider" value={data.status?.providerMode ?? "Unknown"} />
            <Stat label="Persistence" value={data.status?.persistence ?? "Unknown"} />
            <Stat label="Repairs" value={data.status?.monitoring?.repairEnabled ? "Enabled" : "Unavailable"} />
          </section>
          <Monitoring doctor={data.doctor} gateways={data.gateways ?? []} incidents={data.incidents ?? []} error={data.monitoringError} />
          <section className="overflow-hidden rounded-md border border-zinc-800">
            <div className="flex items-center justify-between border-b border-zinc-800 px-5 py-4">
              <div>
                <h2 className="m-0 text-base font-semibold">Kiln-owned resources</h2>
                <p className="mb-0 mt-1 text-sm text-zinc-400">External Proxmox resources are not listed here.</p>
              </div>
              <span className="font-mono text-xs text-zinc-400">{data.resources?.length ?? 0} records</span>
            </div>
            <ResourceTable resources={data.resources ?? []} />
          </section>
        </>
      )}
    </main>
  );
}

function Monitoring({ doctor, gateways, incidents, error }: { doctor?: DashboardDoctor; gateways: DashboardGateway[]; incidents: DashboardIncident[]; error?: string }) {
  if (!doctor) {
    return <section className="mb-8 rounded-md border border-amber-400/40 bg-amber-300/10 p-5"><h2 className="m-0 text-base font-semibold">Network monitoring</h2><p className="mb-0 mt-2 text-sm text-zinc-300">Monitoring data is unavailable. Kiln will not treat this as ready.</p></section>;
  }
  return (
    <section className="mb-8 overflow-hidden rounded-md border border-zinc-800">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800 px-5 py-4">
        <div><h2 className="m-0 text-base font-semibold">Network monitoring</h2><p className="mb-0 mt-1 text-sm text-zinc-400">Observed {doctor.checkedAt}. Repairs are unavailable in this release.</p></div>
        <HealthBadge value={doctor.overall} />
      </div>
      {error && <p className="m-0 border-b border-amber-400/30 bg-amber-300/10 px-5 py-3 text-sm text-amber-100">{error}</p>}
      <GatewayTable doctor={doctor} gateways={gateways} />
      <IncidentList incidents={incidents.length > 0 ? incidents : doctor.incidents} />
      {doctor.limitations.length > 0 && <div className="border-t border-zinc-800 px-5 py-4 text-sm text-zinc-400"><p className="m-0 font-mono text-xs uppercase tracking-wide text-zinc-500">Monitoring limits</p><ul className="mb-0 mt-2 space-y-1 pl-5">{doctor.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul></div>}
    </section>
  );
}

function HealthBadge({ value }: { value: "HEALTHY" | "DEGRADED" | "UNKNOWN" }) {
  const style = value === "HEALTHY" ? "border-emerald-400/50 bg-emerald-300/10 text-emerald-200" : value === "DEGRADED" ? "border-red-400/50 bg-red-400/10 text-red-200" : "border-amber-400/50 bg-amber-300/10 text-amber-200";
  return <span className={`rounded border px-3 py-1.5 font-mono text-xs font-semibold ${style}`}>{value}</span>;
}

function GatewayTable({ doctor, gateways }: { doctor: DashboardDoctor; gateways: DashboardGateway[] }) {
  const byNode = new Map(gateways.map((gateway) => [gateway.metadata.node, gateway]));
  if (doctor.nodes.length === 0) return <p className="m-0 border-b border-zinc-800 px-5 py-4 text-sm text-amber-100">No eligible provider nodes were observed. Kiln cannot admit new sandbox workloads.</p>;
  return <div className="overflow-x-auto border-b border-zinc-800"><table className="w-full border-collapse text-left text-sm"><thead className="bg-zinc-900/50 font-mono text-xs uppercase tracking-wide text-zinc-500"><tr><th className="px-5 py-3">Node</th><th className="px-5 py-3">Gateway</th><th className="px-5 py-3">Readiness</th><th className="px-5 py-3">Last observation</th><th className="px-5 py-3">Evidence</th></tr></thead><tbody>{doctor.nodes.map((node) => { const gateway = byNode.get(node.node); return <tr className="border-t border-zinc-800" key={node.node}><td className="px-5 py-3 font-mono text-xs">{node.node}</td><td className="px-5 py-3 font-mono text-xs text-amber-200">{node.gatewayId ?? "unconfigured"}</td><td className="px-5 py-3"><span className={node.status === "READY" ? "text-emerald-200" : "text-amber-200"}>{node.status}</span></td><td className="px-5 py-3 font-mono text-xs text-zinc-400">{gateway?.health?.observedAt ?? "no observation"}</td><td className="px-5 py-3 text-xs text-zinc-400">{node.checks.map((check) => `${check.status}: ${check.message}`).join(" ") || "No evidence"}</td></tr>; })}</tbody></table></div>;
}

function IncidentList({ incidents }: { incidents: DashboardIncident[] }) {
  if (incidents.length === 0) return <div className="px-5 py-4 text-sm text-zinc-400">No open gateway incidents.</div>;
  return <div className="divide-y divide-zinc-800">{incidents.map((incident) => <article className="px-5 py-4" key={incident.id}><div className="flex flex-wrap items-center justify-between gap-2"><p className="m-0 font-mono text-xs text-amber-200">{incident.id} / {incident.code} / {incident.node}</p><p className="m-0 font-mono text-xs text-zinc-500">Last seen {incident.lastSeenAt}</p></div><p className="mb-0 mt-2 text-sm text-zinc-200">{incident.message}</p>{incident.guidance.length > 0 && <ul className="mb-0 mt-2 space-y-1 pl-5 text-sm text-zinc-400">{incident.guidance.map((guidance) => <li key={guidance}>{guidance}</li>)}</ul>}</article>)}</div>;
}

function Stat({ label, value }: { label: string; value: string }) {
  return <div className="rounded-md border border-zinc-800 bg-zinc-900/40 p-4"><p className="m-0 font-mono text-xs uppercase tracking-wide text-zinc-500">{label}</p><p className="mb-0 mt-2 truncate font-mono text-sm text-zinc-100">{value}</p></div>;
}

function ResourceTable({ resources }: { resources: { id: string; type: string; ownership: string; state: string; node: string | null; expiresAt: string | null }[] }) {
  if (resources.length === 0) return <p className="m-0 p-5 text-sm text-zinc-400">No Kiln-owned resources exist.</p>;
  return <div className="overflow-x-auto"><table className="w-full border-collapse text-left text-sm"><thead className="bg-zinc-900/50 font-mono text-xs uppercase tracking-wide text-zinc-500"><tr><th className="px-5 py-3">ID</th><th className="px-5 py-3">Type</th><th className="px-5 py-3">Ownership</th><th className="px-5 py-3">State</th><th className="px-5 py-3">Node</th><th className="px-5 py-3">Expires</th></tr></thead><tbody>{resources.map((resource) => <tr className="border-t border-zinc-800" key={resource.id}><td className="px-5 py-3 font-mono text-amber-200">{resource.id}</td><td className="px-5 py-3">{resource.type}</td><td className="px-5 py-3 font-mono text-xs">{resource.ownership}</td><td className="px-5 py-3">{resource.state}</td><td className="px-5 py-3 font-mono text-xs text-zinc-400">{resource.node ?? "unassigned"}</td><td className="px-5 py-3 font-mono text-xs text-zinc-400">{resource.expiresAt ?? "persistent"}</td></tr>)}</tbody></table></div>;
}
