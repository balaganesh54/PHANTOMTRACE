'use client';

import { useEffect, useState } from 'react';
import { useParams, usePathname } from 'next/navigation';
import Layout from '@/components/Layout';
import { api } from '@/lib/api';

type AnyRecord = Record<string, any>;

const riskClass = (risk: string = '') => {
  const r = risk.toUpperCase();
  if (r === 'CRITICAL' || r === 'HIGH') return 'text-red-400';
  if (r === 'MEDIUM' || r === 'SUSPICIOUS') return 'text-amber-400';
  if (r === 'LOW' || r === 'PASS' || r === 'SUCCESS') return 'text-green-400';
  return 'text-slate-300';
};

const statusBadge = (value: string = '') => {
  const v = value.toUpperCase();
  if (['FAIL', 'HIGH', 'CRITICAL', 'SUSPICIOUS'].includes(v)) return 'bg-red-500/10 text-red-400 border-red-500/30';
  if (['MEDIUM', 'WARNING', 'POTENTIAL'].includes(v)) return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
  if (['PASS', 'LOW', 'SUCCESS', 'OBSERVED'].includes(v)) return 'bg-green-500/10 text-green-400 border-green-500/30';
  return 'bg-slate-500/10 text-slate-300 border-slate-500/30';
};

function Card({ title, children, className = '' }: { title?: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={`panel p-5 ${className}`}>
      {title && <h2 className="text-lg font-bold mb-4">{title}</h2>}
      {children}
    </div>
  );
}

function Loading() {
  return <div className="panel p-8 text-slate-400">Loading investigation evidence…</div>;
}

function ErrorBox({ error }: { error: string }) {
  return <div className="panel p-6 border-red-500/30 text-red-300">Unable to load this section: {error}</div>;
}

export default function SubPage() {
  const { id } = useParams<{ id: string }>();
  const path = usePathname().split('/').pop() || '';
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    const ep =
      path === 'headers' ? 'headers' :
      path === 'iocs' ? 'iocs' :
      path === 'urls' ? 'urls' :
      path === 'domains' ? 'domains' :
      path === 'mitre' ? 'mitre' :
      path === 'timeline' ? 'timeline' : null;

    if (!ep) return;
    setData(null);
    setError('');
    api(`/investigations/${id}/${ep}`)
      .then(setData)
      .catch((e) => setError(e?.message || 'Unknown API error'));
  }, [id, path]);

  if (path === 'report') return <Report id={id} />;
  if (path === 'graph') return <Graph id={id} />;

  const titleMap: AnyRecord = {
    headers: 'HEADER FORENSICS',
    iocs: 'IOC EXPLORER',
    urls: 'URL ANALYSIS',
    domains: 'DOMAIN INTELLIGENCE',
    mitre: 'MITRE ATT&CK',
    timeline: 'INVESTIGATION TIMELINE',
  };

  return (
    <Layout>
      <div className="p-6 md:p-8 space-y-6">
        <div>
          <div className="text-xs text-cyan-400 font-bold tracking-widest">PHANTOMTRACE / INVESTIGATION</div>
          <h1 className="text-3xl font-black mt-1">{titleMap[path] || path.toUpperCase()}</h1>
          <p className="muted mt-1">Evidence extracted from the analyzed email. Unknown values are shown as UNKNOWN.</p>
        </div>

        {error ? <ErrorBox error={error} /> : !data ? <Loading /> :
          path === 'headers' ? <HeadersView data={data} /> :
          path === 'iocs' ? <IocsView data={data} /> :
          path === 'urls' ? <UrlsView data={data} /> :
          path === 'domains' ? <DomainsView data={data} /> :
          path === 'mitre' ? <MitreView data={data} /> :
          path === 'timeline' ? <TimelineView data={data} /> :
          <Card><pre className="text-xs whitespace-pre-wrap">{JSON.stringify(data, null, 2)}</pre></Card>
        }
      </div>
    </Layout>
  );
}

function HeadersView({ data }: { data: AnyRecord[] }) {
  const auth = data.find((h) => h.key?.toLowerCase() === 'authentication-results')?.value || '';
  const getAuth = (name: string) => {
    const m = auth.match(new RegExp(`${name}=([a-zA-Z]+)`, 'i'));
    return m ? m[1].toUpperCase() : 'UNKNOWN';
  };

  const fields = ['From', 'To', 'Cc', 'Reply-To', 'Return-Path', 'Subject', 'Date', 'Message-ID'];
  const lookup = (key: string) => data.find((h) => h.key?.toLowerCase() === key.toLowerCase())?.value || 'UNKNOWN';

  return (
    <div className="space-y-6">
      <Card title="Authentication Analysis">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {['SPF', 'DKIM', 'DMARC'].map((name) => {
            const status = getAuth(name.toLowerCase());
            return (
              <div key={name} className="rounded-xl border border-slate-700 p-4 bg-slate-900/40">
                <div className="text-sm muted">{name}</div>
                <div className={`text-2xl font-black mt-1 ${riskClass(status)}`}>{status}</div>
                <p className="text-xs muted mt-2">
                  {status === 'UNKNOWN'
                    ? 'No authentication result was found in the uploaded message.'
                    : `${name} result was read from the Authentication-Results header.`}
                </p>
              </div>
            );
          })}
        </div>
      </Card>

      <Card title="Message Headers">
        <div className="divide-y divide-slate-800">
          {fields.map((key) => (
            <div key={key} className="grid grid-cols-1 md:grid-cols-[180px_1fr] gap-3 py-3">
              <div className="text-sm font-bold text-slate-400">{key}</div>
              <div className="text-sm break-all">{lookup(key)}</div>
            </div>
          ))}
        </div>
      </Card>

      <Card title="All Parsed Headers">
        <div className="space-y-3">
          {data.map((h, i) => (
            <div key={`${h.key}-${i}`} className="rounded-lg bg-slate-900/50 border border-slate-800 p-3">
              <div className="text-xs font-bold text-cyan-400">{h.key}</div>
              <div className="text-sm mt-1 break-all text-slate-300">{h.value}</div>
            </div>
          ))}
        </div>
      </Card>

      <Card title="SMTP Relay Path">
        <div className="flex flex-col md:flex-row md:items-center gap-3">
          <Relay label="Sender" value={lookup('From')} />
          <span className="text-cyan-400 hidden md:block">→</span>
          <Relay label="Mail Server / Relay" value="See Received headers above" />
          <span className="text-cyan-400 hidden md:block">→</span>
          <Relay label="Destination" value={lookup('To')} />
        </div>
        <p className="text-xs muted mt-4">The backend currently records only parsed headers; unobserved relay metadata is not invented.</p>
      </Card>
    </div>
  );
}

function Relay({ label, value }: { label: string; value: string }) {
  return <div className="flex-1 rounded-xl border border-slate-700 bg-slate-900/40 p-4">
    <div className="text-xs text-cyan-400 font-bold">{label}</div>
    <div className="text-sm mt-2 break-all">{value}</div>
  </div>;
}

function IocsView({ data }: { data: AnyRecord[] }) {
  return (
    <Card title={`${data.length} Indicators of Compromise`}>
      {!data.length ? <div className="muted">No IOCs were extracted.</div> :
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="text-left text-slate-400 border-b border-slate-700">
              <th className="py-3 pr-4">IOC</th><th className="py-3 pr-4">Type</th><th className="py-3 pr-4">Source</th><th className="py-3 pr-4">Risk</th><th className="py-3 pr-4">Confidence</th><th className="py-3">Status</th>
            </tr></thead>
            <tbody>
              {data.map((x, i) => <tr key={i} className="border-b border-slate-800/80">
                <td className="py-4 pr-4 font-mono text-xs break-all max-w-md">{x.value}</td>
                <td className="py-4 pr-4"><span className="badge border border-cyan-500/30 bg-cyan-500/10 text-cyan-300">{x.type}</span></td>
                <td className="py-4 pr-4 text-slate-400">{x.source || 'UNKNOWN'}</td>
                <td className={`py-4 pr-4 font-bold ${riskClass(x.risk)}`}>{x.risk || 'UNKNOWN'}</td>
                <td className="py-4 pr-4">{x.confidence != null ? `${x.confidence}%` : 'UNKNOWN'}</td>
                <td className="py-4"><span className={`badge border ${statusBadge(x.status)}`}>{x.status || 'UNKNOWN'}</span></td>
              </tr>)}
            </tbody>
          </table>
        </div>}
    </Card>
  );
}

function UrlsView({ data }: { data: AnyRecord[] }) {
  return (
    <div className="space-y-4">
      {data.length === 0 && <Card><div className="muted">No URLs were extracted.</div></Card>}
      {data.map((x, i) => {
        let reasons: any = x.reasons;
        try { reasons = typeof reasons === 'string' ? JSON.parse(reasons) : reasons; } catch { /* keep raw */ }
        return <Card key={i}>
          <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4">
            <div className="min-w-0">
              <div className="text-xs text-cyan-400 font-bold">URL #{i + 1}</div>
              <div className="font-mono text-sm break-all mt-2">{x.value}</div>
            </div>
            <span className={`badge border self-start ${statusBadge(x.risk)}`}>{x.risk || 'UNKNOWN'}</span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-5">
            <Mini title="Domain" value={x.domain || 'UNKNOWN'} />
            <Mini title="Protocol" value={x.protocol || 'UNKNOWN'} />
            <Mini title="Redirects" value={x.redirects ?? 'UNKNOWN'} />
            <Mini title="Reputation" value={x.reputation || 'UNKNOWN'} />
          </div>
          <div className="mt-4 text-xs muted">Reasons</div>
          <ul className="mt-2 list-disc list-inside text-sm text-slate-300">
            {(Array.isArray(reasons) ? reasons : [reasons || 'No additional reason recorded.']).map((r: any, j: number) => <li key={j}>{String(r)}</li>)}
          </ul>
          <button type="button" className="btn mt-5 border border-slate-700 text-slate-300 cursor-default" title="Safe analysis is local in this prototype; suspicious URLs are never opened automatically.">Analyze Safely</button>
        </Card>;
      })}
    </div>
  );
}

function DomainsView({ data }: { data: AnyRecord[] }) {
  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
      {data.length === 0 && <Card><div className="muted">No domains were extracted.</div></Card>}
      {data.map((x, i) => <Card key={i} title={x.name || 'UNKNOWN'}>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {[
            ['Age', x.age], ['Registrar', x.registrar], ['Nameservers', x.nameservers],
            ['MX', x.mx], ['A / AAAA', x.a_records], ['ASN', x.asn],
            ['Hosting', x.hosting], ['Reputation', x.reputation]
          ].map(([k, v]) => <Mini key={String(k)} title={String(k)} value={String(v || 'UNKNOWN')} />)}
        </div>
        <div className="text-xs muted mt-4">Only information available from the prototype analyzer is displayed. Unknown fields are not inferred.</div>
      </Card>)}
    </div>
  );
}

function MitreView({ data }: { data: AnyRecord[] }) {
  const observed = data.filter((x) => x.classification === 'OBSERVED');
  const potential = data.filter((x) => x.classification === 'POTENTIAL');

  return (
    <div className="space-y-6">
      <Card title="Detected Techniques">
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          {data.length === 0 && <div className="muted">No MITRE ATT&CK techniques were mapped.</div>}
          {data.map((x, i) => <div key={i} className="rounded-xl border border-slate-700 bg-slate-900/40 p-5">
            <div className="flex justify-between gap-3">
              <div>
                <div className="font-mono text-cyan-400 font-bold">{x.technique_id}</div>
                <div className="font-bold mt-1">{x.technique}</div>
              </div>
              <span className={`badge border ${statusBadge(x.classification)}`}>{x.classification}</span>
            </div>
            <div className="mt-4 text-sm">Confidence: <b>{x.confidence}%</b></div>
            <div className="mt-3 text-sm text-slate-400">Evidence</div>
            <p className="mt-1 text-sm text-slate-300">{x.evidence || 'UNKNOWN'}</p>
          </div>)}
        </div>
      </Card>
      <div className="grid grid-cols-2 gap-4">
        <Mini title="Observed techniques" value={String(observed.length)} />
        <Mini title="Potential techniques" value={String(potential.length)} />
      </div>
    </div>
  );
}

function TimelineView({ data }: { data: AnyRecord[] }) {
  return (
    <Card title="Investigation Timeline">
      {!data.length ? <div className="muted">No timeline events recorded.</div> :
        <div className="relative ml-2 border-l border-cyan-500/30">
          {data.map((x, i) => <div key={i} className="relative pl-7 pb-8 last:pb-0">
            <div className="absolute -left-[7px] top-1 w-3 h-3 rounded-full bg-cyan-400 ring-4 ring-[#111827]" />
            <div className="flex flex-wrap items-center gap-3">
              <span className="font-mono text-cyan-400 text-sm">{x.timestamp}</span>
              <span className={`badge border ${statusBadge(x.severity)}`}>{x.severity || 'info'}</span>
            </div>
            <div className="font-bold mt-2">{x.event}</div>
            <div className="text-sm muted mt-1">{x.detail}</div>
          </div>)}
        </div>}
    </Card>
  );
}

function Mini({ title, value }: { title: string; value: string }) {
  return <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-3 min-w-0">
    <div className="text-xs text-slate-500">{title}</div>
    <div className="text-sm font-semibold mt-1 break-all">{value}</div>
  </div>;
}

function Report({ id }: { id: string }) {
  const [d, setD] = useState<any>(null);
  const [headers, setHeaders] = useState<AnyRecord[]>([]);
  const [iocs, setIocs] = useState<AnyRecord[]>([]);
  const [urls, setUrls] = useState<AnyRecord[]>([]);
  const [domains, setDomains] = useState<AnyRecord[]>([]);
  const [mitre, setMitre] = useState<AnyRecord[]>([]);
  const [timeline, setTimeline] = useState<AnyRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    setLoading(true);
    Promise.all([
      api(`/investigations/${id}`),
      api(`/investigations/${id}/headers`),
      api(`/investigations/${id}/iocs`),
      api(`/investigations/${id}/urls`),
      api(`/investigations/${id}/domains`),
      api(`/investigations/${id}/mitre`),
      api(`/investigations/${id}/timeline`),
    ]).then(([inv, h, i, u, dom, m, t]) => {
      if (!active) return;
      setD(inv); setHeaders(h); setIocs(i); setUrls(u); setDomains(dom); setMitre(m); setTimeline(t);
    }).catch((e) => active && setError(e?.message || 'Unable to load report data.'))
      .finally(() => active && setLoading(false));
    return () => { active = false; };
  }, [id]);

  const downloadPdf = async () => {
    setDownloading(true);
    try {
      const url = `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api'}/investigations/${id}/report/pdf`;
      window.location.assign(url);
    } finally {
      window.setTimeout(() => setDownloading(false), 1200);
    }
  };

  if (loading) return <Layout><div className="p-8"><Loading /></div></Layout>;
  if (error || !d) return <Layout><div className="p-8"><ErrorBox error={error || 'Investigation not found.'} /></div></Layout>;

  const risk = d.risk || { score: 0, level: 'UNKNOWN', factors: [] };
  const auth = d.auth || {};
  const summary = risk.factors?.length
    ? risk.factors.map((f: any) => `+${f.points} ${f.reason}`).join('. ')
    : 'No suspicious factors were observed by the local analyzer.';

  return (
    <Layout>
      <div className="p-6 md:p-8 space-y-6 max-w-7xl mx-auto">
        <div className="flex flex-col lg:flex-row lg:items-end lg:justify-between gap-5">
          <div>
            <div className="text-xs text-cyan-400 font-bold tracking-widest">PHANTOMTRACE / INVESTIGATION REPORT</div>
            <h1 className="text-3xl md:text-4xl font-black mt-1">Forensic Investigation Report</h1>
            <p className="muted mt-2">Complete browser-readable report generated from the stored investigation evidence.</p>
          </div>
          <div className="flex gap-3">
            <button type="button" onClick={downloadPdf} disabled={downloading} className="btn bg-[#00D4FF] text-slate-950 disabled:opacity-60">
              {downloading ? 'Preparing PDF…' : 'Download PDF'}
            </button>
            <button type="button" onClick={() => window.print()} className="btn border border-slate-700 text-slate-200">Print / Save</button>
          </div>
        </div>

        {d.demo && <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-300"><strong>DEMO DATA:</strong> This investigation contains synthetic demonstration evidence. It must not be treated as real-world threat intelligence.</div>}

        <Card>
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
            <div>
              <div className="text-xs muted">CASE ID</div><div className="font-mono text-sm mt-1 break-all">{d.id}</div>
              <div className="text-2xl font-black mt-4">{d.email?.subject || d.case_name || 'UNKNOWN'}</div>
              <div className="muted mt-1">{d.email?.sender || 'UNKNOWN'} → {d.email?.recipient || 'UNKNOWN'}</div>
            </div>
            <div className="rounded-2xl border border-slate-700 bg-slate-900/60 p-5 min-w-48">
              <div className="text-xs muted">OVERALL RISK</div>
              <div className={`text-4xl font-black mt-1 ${riskClass(risk.level)}`}>{risk.score}<span className="text-base text-slate-400">/100</span></div>
              <div className={`font-black mt-1 ${riskClass(risk.level)}`}>{risk.level}</div>
            </div>
          </div>
        </Card>

        <div className="grid md:grid-cols-4 gap-4">
          <ReportStat title="IOCs" value={iocs.length} />
          <ReportStat title="URLs" value={urls.length} />
          <ReportStat title="Domains" value={domains.length} />
          <ReportStat title="MITRE Techniques" value={mitre.length} />
        </div>

        <Card title="Executive Summary">
          <p className="text-slate-300 leading-7">This report summarizes the local PHANTOMTRACE analysis of the submitted email. Findings below are derived from parsed message evidence and configured demo-mode rules. External reputation or geolocation data is shown as UNKNOWN when it was not available.</p>
          <div className="mt-5 rounded-xl border border-slate-700 bg-slate-900/50 p-4">
            <div className="text-sm font-bold">Why is this email suspicious?</div>
            <p className="muted mt-2 leading-6">{summary}</p>
          </div>
        </Card>

        <Card title="Email Details">
          <DetailGrid items={[
            ['Case Name', d.case_name], ['Status', d.status], ['Analysis Time', d.analyzed_at || 'UNKNOWN'],
            ['Subject', d.email?.subject], ['Sender', d.email?.sender], ['Recipient', d.email?.recipient],
          ]} />
        </Card>

        <Card title="Authentication Analysis">
          <div className="grid md:grid-cols-3 gap-4">
            {[['SPF', auth.spf], ['DKIM', auth.dkim], ['DMARC', auth.dmarc]].map(([name, value]) => (
              <div key={String(name)} className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                <div className="text-sm muted">{name}</div><div className={`text-2xl font-black mt-1 ${riskClass(String(value))}`}>{value || 'UNKNOWN'}</div>
                <p className="text-xs muted mt-2">Status read from Authentication-Results when present; otherwise UNKNOWN.</p>
              </div>
            ))}
          </div>
        </Card>

        <Card title={`Header Analysis (${headers.length} parsed headers)`}>
          <div className="divide-y divide-slate-800">
            {headers.length ? headers.map((h, idx) => <div key={`${h.key}-${idx}`} className="grid md:grid-cols-[200px_1fr] gap-3 py-3"><div className="text-sm font-bold text-cyan-300">{h.key}</div><div className="text-sm text-slate-300 break-all">{h.value || 'UNKNOWN'}</div></div>) : <div className="muted">No parsed headers available.</div>}
          </div>
        </Card>

        <Card title="Risk Assessment">
          <div className="space-y-3">
            {risk.factors?.length ? risk.factors.map((f: any, idx: number) => <div key={idx} className="flex items-start justify-between gap-4 rounded-lg border border-slate-800 bg-slate-900/40 p-3"><span className="text-slate-300">{f.reason}</span><span className="font-black text-red-400 shrink-0">+{f.points}</span></div>) : <div className="muted">No risk factors recorded.</div>}
          </div>
        </Card>

        <Card title="IOC Findings">
          {iocs.length ? <div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="text-left text-slate-400 border-b border-slate-700"><th className="py-3 pr-4">IOC</th><th className="py-3 pr-4">Type</th><th className="py-3 pr-4">Risk</th><th className="py-3 pr-4">Confidence</th><th className="py-3">Status</th></tr></thead><tbody>{iocs.map((x, idx) => <tr key={idx} className="border-b border-slate-800"><td className="py-3 pr-4 font-mono text-xs break-all">{x.value}</td><td className="py-3 pr-4">{x.type}</td><td className={`py-3 pr-4 font-bold ${riskClass(x.risk)}`}>{x.risk}</td><td className="py-3 pr-4">{x.confidence ?? 'UNKNOWN'}%</td><td className="py-3">{x.status || 'UNKNOWN'}</td></tr>)}</tbody></table></div> : <div className="muted">No IOCs were extracted.</div>}
        </Card>

        <Card title="URL Findings">
          {urls.length ? <div className="space-y-3">{urls.map((x, idx) => <div key={idx} className="rounded-xl border border-slate-700 bg-slate-900/40 p-4"><div className="flex justify-between gap-4"><div className="font-mono text-sm break-all">{x.value}</div><span className={`badge border ${statusBadge(x.risk)}`}>{x.risk || 'UNKNOWN'}</span></div><div className="grid md:grid-cols-4 gap-3 mt-4"><Mini title="Domain" value={x.domain || 'UNKNOWN'} /><Mini title="Protocol" value={x.protocol || 'UNKNOWN'} /><Mini title="Redirects" value={x.redirects ?? 'UNKNOWN'} /><Mini title="Reputation" value={x.reputation || 'UNKNOWN'} /></div></div>)}</div> : <div className="muted">No URLs were extracted.</div>}
        </Card>

        <Card title="Domain Findings">
          {domains.length ? <div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="text-left text-slate-400 border-b border-slate-700"><th className="py-3 pr-4">Domain</th><th className="py-3 pr-4">Age</th><th className="py-3 pr-4">Registrar</th><th className="py-3 pr-4">ASN</th><th className="py-3">Reputation</th></tr></thead><tbody>{domains.map((x, idx) => <tr key={idx} className="border-b border-slate-800"><td className="py-3 pr-4 font-mono">{x.name}</td><td className="py-3 pr-4">{x.age || 'UNKNOWN'}</td><td className="py-3 pr-4">{x.registrar || 'UNKNOWN'}</td><td className="py-3 pr-4">{x.asn || 'UNKNOWN'}</td><td className="py-3">{x.reputation || 'UNKNOWN'}</td></tr>)}</tbody></table></div> : <div className="muted">No domains were extracted.</div>}
        </Card>

        <Card title="MITRE ATT&CK Mapping">
          {mitre.length ? <div className="grid md:grid-cols-2 gap-4">{mitre.map((x, idx) => <div key={idx} className="rounded-xl border border-slate-700 bg-slate-900/40 p-4"><div className="flex justify-between gap-3"><div><div className="text-cyan-300 font-black">{x.technique_id}</div><div className="font-bold mt-1">{x.technique}</div></div><span className={`badge border ${statusBadge(x.classification)}`}>{x.classification}</span></div><div className="text-sm muted mt-3">Confidence: {x.confidence ?? 'UNKNOWN'}%</div><div className="text-sm text-slate-300 mt-2">{x.evidence || 'UNKNOWN'}</div></div>)}</div> : <div className="muted">No MITRE techniques were mapped.</div>}
        </Card>

        <Card title="Investigation Timeline">
          {timeline.length ? <div className="relative ml-2 border-l border-slate-700 pl-6 space-y-5">{timeline.map((x, idx) => <div key={idx} className="relative"><span className="absolute -left-[31px] top-1.5 h-3 w-3 rounded-full bg-cyan-400 shadow-[0_0_0_4px_#111827]"/><div className="text-xs text-cyan-300 font-bold">{x.timestamp}</div><div className="font-bold mt-1">{x.event}</div><div className="text-sm muted mt-1">{x.detail}</div></div>)}</div> : <div className="muted">No timeline events recorded.</div>}
        </Card>

        <Card title="Limitations & Recommendations">
          <ul className="list-disc list-inside text-slate-300 space-y-2">
            <li>Demo mode uses local parsing and deterministic heuristic scoring.</li>
            <li>External reputation, WHOIS, ASN and geolocation values may be UNKNOWN without configured intelligence providers.</li>
            <li>Suspicious URLs are displayed for analysis but are not automatically opened.</li>
            <li>Do not treat synthetic demo evidence as real-world threat intelligence.</li>
          </ul>
        </Card>

        <div className="flex justify-end gap-3 pb-8">
          <button type="button" onClick={downloadPdf} disabled={downloading} className="btn bg-[#00D4FF] text-slate-950 disabled:opacity-60">{downloading ? 'Preparing PDF…' : 'Download Full PDF Report'}</button>
        </div>
      </div>
    </Layout>
  );
}

function ReportStat({ title, value }: { title: string; value: string | number }) {
  return <div className="panel p-4"><div className="text-xs muted uppercase tracking-wider">{title}</div><div className="text-2xl font-black mt-1">{value}</div></div>;
}

function DetailGrid({ items }: { items: [string, any][] }) {
  return <div className="grid md:grid-cols-2 gap-x-8">{items.map(([label, value]) => <div key={label} className="border-b border-slate-800 py-3"><div className="text-xs muted">{label}</div><div className="text-sm mt-1 break-all">{value || 'UNKNOWN'}</div></div>)}</div>;
}

function Graph({ id }: { id: string }) {
  const [g, setG] = useState<any>();
  const [error, setError] = useState('');
  useEffect(() => {
    api(`/investigations/${id}/graph`).then(setG).catch((e) => setError(e?.message || 'Unable to load graph'));
  }, [id]);
  if (error) return <Layout><div className="p-8"><ErrorBox error={error} /></div></Layout>;
  if (!g) return <Layout><div className="p-8"><Loading /></div></Layout>;
  return <GraphCanvas g={g} />;
}

function GraphCanvas({ g }: { g: any }) {
  const RF = require('@xyflow/react');
  const [nodes, setNodes] = useState<any[]>([]);
  const [edges, setEdges] = useState<any[]>([]);

  useEffect(() => {
    if (!g) return;
    setNodes((g.nodes || []).map((n: any, i: number) => ({
      id: n.id,
      data: { label: n.label },
      position: { x: 80 + (i % 3) * 240, y: 80 + Math.floor(i / 3) * 150 },
      style: { background: '#111827', color: '#e5e7eb', border: '1px solid #00D4FF', borderRadius: 12, padding: 12, width: 180 }
    })));
    setEdges((g.edges || []).map((e: any, i: number) => ({ id: 'e' + i, source: e.source, target: e.target, animated: true })));
  }, [g]);

  return <Layout><div className="p-8"><h1 className="text-3xl font-black">THREAT GRAPH</h1>
    <div className="panel mt-6 h-[600px] overflow-hidden"><RF.ReactFlow nodes={nodes} edges={edges} fitView>
      <RF.Background /><RF.Controls /><RF.MiniMap />
    </RF.ReactFlow></div>
  </div></Layout>;
}
