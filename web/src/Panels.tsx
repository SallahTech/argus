import { useEffect, useState } from 'react';
import type { ArgusEvent, CaseFile, FeatureCheck, Level, ThreatNumber } from './api';

const cls = (level: Level | null | undefined) => (level === 'CRITICAL' ? 'c-red' : level === 'RELEVANT' ? 'c-yellow' : 'c-white');

/** Types text out like a terminal. */
export function Typed({ text, speed = 18 }: { text: string; speed?: number }) {
  const [n, setN] = useState(0);
  useEffect(() => {
    setN(0);
    const t = setInterval(() => setN((x) => (x >= text.length ? (clearInterval(t), x) : x + 1)), speed);
    return () => clearInterval(t);
  }, [text, speed]);
  return (
    <>
      {text.slice(0, n)}
      {n < text.length && <span className="caret">█</span>}
    </>
  );
}

export function NumbersPanel({ numbers, showQuiet, onToggleQuiet, onSelect, selected }: {
  numbers: ThreatNumber[];
  showQuiet: boolean;
  onToggleQuiet: () => void;
  onSelect: (id: string) => void;
  selected: string | null;
}) {
  const active = numbers.filter((n) => n.level !== 'IRRELEVANT');
  const quiet = numbers.filter((n) => n.level === 'IRRELEVANT');
  const list = showQuiet ? numbers : active;
  return (
    <section className="panel numbers">
      <header className="panel-head">
        <span>NUMBERS</span>
        <span className="muted">
          {active.length} active · {quiet.length} irrelevant
        </span>
      </header>
      <div className="numbers-list">
        {!active.length && !showQuiet && <div className="muted pad">No relevant numbers. The Machine is watching.</div>}
        {list.map((n) => (
          <button key={n.id} className={`number ${cls(n.level)} ${selected === n.id ? 'sel' : ''}`} onClick={() => onSelect(n.id)}>
            <div className="number-top">
              <span className="case">#{n.caseNo}</span>
              <span className="score">{n.score}</span>
            </div>
            <div className="number-name">
              {n.name}
              <span className="muted">@{n.version}</span>
            </div>
            <div className="number-meta">
              <span className={`pill ${cls(n.level)}`}>{n.level}</span>
              {n.notExploitable && <span className="pill pill-safe">NOT EXPLOITABLE</span>}
              <span className="muted">
                {n.findings.length} vuln{n.findings.length > 1 ? 's' : ''}
                {n.findings.some((f) => f.kevDateAdded) && ' · EXPLOITED'}
                {n.fixVersion ? ` · fix ${n.fixVersion}` : ' · no fix'}
              </span>
            </div>
          </button>
        ))}
      </div>
      <button className="link" onClick={onToggleQuiet}>
        {showQuiet ? 'hide irrelevant' : `show ${quiet.length} irrelevant`}
      </button>
    </section>
  );
}

/** Is the vulnerable part of the package actually used here? One line per distinct check. */
function FeatureChecks({ file }: { file: CaseFile }) {
  const seen = new Map<string, { check: FeatureCheck; ids: string[] }>();
  for (const f of file.findings) {
    if (!f.check) continue;
    const k = `${f.check.status}|${f.check.feature}`;
    const e = seen.get(k) ?? { check: f.check, ids: [] };
    e.ids.push(f.cveId ?? f.vulnId);
    seen.set(k, e);
  }
  if (!seen.size) return null;
  const unchecked = file.findings.filter((f) => !f.check).length;
  return (
    <div className="block">
      <div className="muted small">FEATURE CHECK</div>
      {[...seen.values()].map(({ check, ids }) => (
        <div key={check.status + check.feature} className={`check check-${check.status}`}>
          <div className="check-head">
            <span className="check-mark">{check.status === 'unused' ? '✓' : '!'}</span>
            <span>
              {check.status === 'unused'
                ? check.kind === 'build-time'
                  ? 'Build time only: never runs in production'
                  : `Not exploitable here: ${check.feature} never used`
                : `In use: ${check.feature}`}
            </span>
          </div>
          <div className="check-detail">{check.detail.replace(/^not exploitable here: /i, '')}</div>
          {check.status === 'used' &&
            check.evidence.map((e) => (
              <code key={e} className="check-ev">
                {e}
              </code>
            ))}
          {check.kind === 'build-time' && <code className="check-ev">{['your code', ...check.evidence].join(' → ')}</code>}
          <div className="muted small">{ids.join(' · ')}</div>
        </div>
      ))}
      {unchecked > 0 && <div className="muted small">{unchecked} other vulnerabilit{unchecked > 1 ? 'ies' : 'y'}: no feature rule, scored on reachability</div>}
    </div>
  );
}

function fixSnippet(c: CaseFile): string | null {
  if (!c.fixVersion) return null;
  const direct = c.path.length === 1;
  return direct
    ? `npm install ${c.name}@${c.fixVersion}`
    : `// package.json\n"overrides": {\n  "${c.name}": "^${c.fixVersion}"\n}`;
}

export function CaseFilePanel({ file, onClose }: { file: CaseFile; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const snippet = fixSnippet(file);
  const top = file.findings[0];
  return (
    <section className={`panel case ${cls(file.level)}`}>
      <header className="panel-head">
        <span>
          CASE FILE <span className="case">#{file.caseNo}</span>
        </span>
        <button className="link" onClick={onClose}>
          close ✕
        </button>
      </header>
      <div className="case-body">
        <div className="case-subject">
          <div className="muted small">SUBJECT</div>
          <div className="subject">
            <Typed text={`${file.name}@${file.version}`} />
          </div>
          <div className="muted small">observed in {file.repo} since {new Date(file.firstSeenAt).toLocaleString()}</div>
        </div>

        <div className="assessment">
          <div>
            <div className="muted small">ASSESSMENT</div>
            <div className={`level ${cls(file.level)}`}>{file.level === 'CRITICAL' ? 'THREAT' : file.level}</div>
          </div>
          <div className="score-big">{file.score}</div>
        </div>
        <div className="bar">
          <div className={`bar-fill bg-${cls(file.level)}`} style={{ width: `${file.score}%` }} />
          <div className="bar-mark" style={{ left: '40%' }} />
          <div className="bar-mark" style={{ left: '70%' }} />
        </div>

        <div className="block">
          <div className="muted small">ATTACK PATH</div>
          <div className="path">
            {['your code', ...file.path].map((p, i, a) => (
              <span key={p + i}>
                <span className={i === a.length - 1 ? cls(file.level) : ''}>{p}</span>
                {i < a.length - 1 && <span className="arrow"> → </span>}
              </span>
            ))}
          </div>
        </div>

        <div className="block">
          <div className="muted small">WHY</div>
          <ul className="reasons">
            {top.reasons.map((r) => (
              <li key={r} className={/KEV|MALICIOUS|ransomware/.test(r) ? 'c-red' : ''}>
                {r}
              </li>
            ))}
          </ul>
        </div>

        <FeatureChecks file={file} />

        <div className="block">
          <div className="muted small">VULNERABILITIES ({file.findings.length})</div>
          {file.findings.map((f) => (
            <a key={f.vulnId} className="vuln" href={`https://osv.dev/vulnerability/${f.vulnId}`} target="_blank" rel="noreferrer">
              <span className={`vscore ${cls(f.level)}`}>{f.score}</span>
              <span className="vid">{f.cveId ?? f.vulnId}</span>
              <span className="vsum">{f.summary}</span>
              <span className="muted small">
                {f.severity.toLowerCase()}
                {f.epss != null && ` · EPSS ${(f.epss * 100).toFixed(1)}%`}
                {f.kevDateAdded && ' · in KEV'}
                {f.fixVersion && ` · fixed in ${f.fixVersion}`}
              </span>
            </a>
          ))}
        </div>

        <div className="block">
          <div className="muted small">TIMELINE</div>
          <ol className="timeline">
            {file.timeline.map((t, i) => (
              <li key={i} className={cls(t.level ?? null)}>
                <span className="t-at">{new Date(t.at).toISOString().slice(0, 10)}</span>
                <span className="t-kind">{t.kind.replace('_', ' ')}</span>
                <span className="t-text">{t.text}</span>
              </li>
            ))}
          </ol>
        </div>

        <div className="block">
          <div className="muted small">COUNTERMEASURE</div>
          {snippet ? (
            <>
              <pre className="snippet">{snippet}</pre>
              <button
                className="btn"
                onClick={() => {
                  void navigator.clipboard?.writeText(snippet);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1500);
                }}
              >
                {copied ? 'COPIED' : 'COPY FIX'}
              </button>
              {file.unfixed > 0 && <div className="muted small">{file.unfixed} vulnerabilities have no fix yet</div>}
            </>
          ) : (
            <div className="muted">No patched version published yet. Monitor.</div>
          )}
        </div>
      </div>
    </section>
  );
}

const time = (iso: string) => new Date(iso).toLocaleTimeString(undefined, { hour12: false });

export function Feed({ events }: { events: ArgusEvent[] }) {
  return (
    <section className="panel feed">
      <header className="panel-head">
        <span>LIVE FEED</span>
        <span className="muted">{events.length} events</span>
      </header>
      <div className="feed-list">
        {events.map((e, i) => (
          <div key={e.id} className={`feed-row ${cls(e.level)} ${e.type === 'SCAN_STEP' ? 'muted' : ''}`}>
            <span className="f-at">{time(e.at)}</span>
            <span className="f-type">{e.type.replace('_', ' ')}</span>
            <span className="f-msg">{i === 0 ? <Typed text={e.message} speed={10} /> : e.message}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
