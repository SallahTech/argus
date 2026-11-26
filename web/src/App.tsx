import { useCallback, useEffect, useRef, useState } from 'react';
import { api, type ArgusEvent, type CaseFile, type Graph, type Overview, type ThreatNumber } from './api';
import { ThreatGraph } from './Graph';
import { CaseFilePanel, Feed, NumbersPanel } from './Panels';

function Clock() {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <span className="clock">
      {now.toISOString().slice(0, 10)} {now.toISOString().slice(11, 19)} UTC
    </span>
  );
}

/** Countdown to the next intel sweep: the Machine is always about to look again. */
function SweepCountdown({ next, onSweep }: { next: string | null | undefined; onSweep: () => void }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  if (!next) return null;
  const left = Math.max(0, Math.round((new Date(next).getTime() - now) / 1000));
  const mm = String(Math.floor(left / 60)).padStart(2, '0');
  const ss = String(left % 60).padStart(2, '0');
  return (
    <button className="sweep-timer" onClick={onSweep} title="Pull fresh KEV + EPSS now">
      <span className="muted small">NEXT INTEL SWEEP</span> <span className={left < 10 ? 'c-yellow' : ''}>{mm}:{ss}</span>
    </button>
  );
}

/** ?repo=<name>&case=<id> keeps the view across reloads and makes it linkable. */
const urlParam = (k: 'repo' | 'case') => new URLSearchParams(window.location.search).get(k);
function setUrl(params: { repo?: string | null; case?: string | null }, mode: 'push' | 'replace' = 'push') {
  const u = new URL(window.location.href);
  for (const [k, v] of Object.entries(params)) (v ? u.searchParams.set(k, v) : u.searchParams.delete(k));
  if (u.href !== window.location.href) window.history[mode === 'push' ? 'pushState' : 'replaceState'](null, '', u);
}

export default function App() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [repoId, setRepoId] = useState<string | null>(null);
  const [graph, setGraph] = useState<Graph>({ nodes: [], edges: [], hidden: 0 });
  const [numbers, setNumbers] = useState<ThreatNumber[]>([]);
  const [events, setEvents] = useState<ArgusEvent[]>([]);
  const [caseFile, setCaseFile] = useState<CaseFile | null>(null);
  const [showQuiet, setShowQuiet] = useState(false);
  const [offline, setOffline] = useState(false);
  const refreshTimer = useRef<number | undefined>(undefined);
  const overviewRef = useRef<Overview | null>(null);

  const refresh = useCallback(async (rid: string | null) => {
    try {
      const ov = await api.overview();
      setOverview(ov);
      overviewRef.current = ov;
      setOffline(false);
      // first load: the repo named in the URL, else the first one
      const id = rid ?? ov.repos.find((r) => r.name === urlParam('repo'))?.id ?? ov.repos[0]?.id ?? null;
      if (id !== rid) setRepoId(id);
      const name = ov.repos.find((r) => r.id === id)?.name;
      if (name && urlParam('repo') !== name) setUrl({ repo: name }, 'replace');
      if (id) {
        const [g, n] = await Promise.all([api.graph(id), api.numbers(id)]);
        setGraph(g);
        setNumbers(n);
      }
    } catch {
      setOffline(true);
    }
  }, []);

  useEffect(() => {
    void refresh(repoId);
  }, [repoId, refresh]);

  // live feed: initial history, then server-sent events
  useEffect(() => {
    api.events().then(setEvents).catch(() => setOffline(true));
    const es = new EventSource('/api/events/stream');
    es.onmessage = (m) => {
      const e: ArgusEvent = JSON.parse(m.data);
      setEvents((prev) => [e, ...prev].slice(0, 120));
      if (['SCAN_START', 'SCAN_DONE', 'NEW_NUMBER', 'ESCALATED', 'RESOLVED', 'SCAN_ERROR', 'INTEL', 'SCORE_CHANGED', 'LOCKFILE'].includes(e.type)) {
        clearTimeout(refreshTimer.current);
        refreshTimer.current = window.setTimeout(() => setRepoId((r) => (void refresh(r), r)), 400);
      }
    };
    es.onerror = () => setOffline(true);
    es.onopen = () => setOffline(false);
    return () => es.close();
  }, [refresh]);

  // reopen the case from the URL after a reload; follow back/forward
  useEffect(() => {
    const syncFromUrl = () => {
      const r = overviewRef.current?.repos.find((x) => x.name === urlParam('repo'));
      if (r) setRepoId(r.id);
      const c = urlParam('case');
      if (!c) setCaseFile(null);
      else
        api.caseFile(c).then(setCaseFile).catch(() => {
          setCaseFile(null);
          setUrl({ case: null }, 'replace'); // resolved or unknown case
        });
    };
    if (urlParam('case')) syncFromUrl();
    window.addEventListener('popstate', syncFromUrl);
    return () => window.removeEventListener('popstate', syncFromUrl);
  }, []);

  const openCase = async (id: string) => {
    setCaseFile(await api.caseFile(id));
    setUrl({ case: id });
  };
  const closeCase = () => {
    setCaseFile(null);
    setUrl({ case: null });
  };
  const selectRepo = (r: { id: string; name: string }) => {
    setRepoId(r.id);
    setCaseFile(null);
    setUrl({ repo: r.name, case: null });
  };
  const openByPackage = (pkg: string) => {
    const n = numbers.find((x) => x.name === pkg);
    if (n) void openCase(n.id);
  };

  const repo = overview?.repos.find((r) => r.id === repoId);
  const t = overview?.totals;
  const status = offline ? 'OFFLINE' : overview?.scanning ? 'SCANNING' : 'OBSERVING';

  return (
    <div className="app">
      <div className="scanlines" />
      <header className="top">
        <div className="brand">
          <svg width="22" height="22" viewBox="0 0 32 32">
            <path d="M2 10V2h8M22 2h8v8M30 22v8h-8M10 30H2v-8" fill="none" stroke="var(--yellow)" strokeWidth="3" />
            <circle cx="16" cy="16" r="4" fill="var(--yellow)" className={status === 'SCANNING' ? 'blink' : ''} />
          </svg>
          <span>ARGUS</span>
          <span className={`status s-${status.toLowerCase()}`}>{status}</span>
        </div>
        <div className="stats">
          <Stat label="ASSETS" value={t?.packages} />
          <Stat label="REACHABLE" value={t?.reachable} />
          <Stat label="VULNS" value={t?.vulnerabilities} />
          <Stat label="RELEVANT" value={t?.relevant} cls="c-yellow" />
          <Stat label="THREATS" value={t?.critical} cls="c-red" />
        </div>
        <div className="top-right">
          <SweepCountdown next={overview?.watch?.nextSweepAt} onSweep={() => void api.sweep()} />
          <Clock />
          <button className="btn" disabled={overview?.scanning} onClick={() => void api.scan()}>
            {overview?.scanning ? 'SCANNING…' : 'SCAN NOW'}
          </button>
        </div>
      </header>

      {overview && overview.repos.length > 1 && (
        <nav className="tabs">
          {overview.repos.map((r) => (
            <button key={r.id} className={r.id === repoId ? 'active' : ''} onClick={() => selectRepo(r)}>
              {r.name}
              {r.critical > 0 && <span className="c-red"> ●{r.critical}</span>}
              {r.relevant > 0 && <span className="c-yellow"> ●{r.relevant}</span>}
            </button>
          ))}
        </nav>
      )}

      <main className="grid">
        <section className="panel view">
          <header className="panel-head">
            <span>
              MACHINE VIEW {repo && <span className="muted">// {repo.name}{repo.internetFacing ? ' · internet-facing' : ''}</span>}
            </span>
            <span className="muted">
              {repo?.lastScannedAt ? `last observed ${new Date(repo.lastScannedAt).toLocaleTimeString(undefined, { hour12: false })}` : ''}
            </span>
          </header>
          <ThreatGraph graph={graph} scanning={!!overview?.scanning} onSelect={openByPackage} />
          <div className="legend">
            <span><i className="lg lg-white" /> observed</span>
            <span><i className="lg lg-yellow" /> relevant</span>
            <span><i className="lg lg-red" /> threat</span>
            <span className="muted">hover to trace a path · click a box to open its case</span>
          </div>
        </section>

        {caseFile ? (
          <CaseFilePanel file={caseFile} onClose={closeCase} />
        ) : (
          <NumbersPanel
            numbers={numbers}
            showQuiet={showQuiet}
            onToggleQuiet={() => setShowQuiet((s) => !s)}
            onSelect={(id) => void openCase(id)}
            selected={null}
          />
        )}

        <Feed events={events} />
      </main>
    </div>
  );
}

function Stat({ label, value, cls = '' }: { label: string; value?: number; cls?: string }) {
  return (
    <div className="stat">
      <div className="muted small">{label}</div>
      <div className={`stat-v ${cls}`}>{value ?? '—'}</div>
    </div>
  );
}
