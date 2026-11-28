import { useEffect, useRef, useState } from 'react';
import { fmtDateTime, fmtTime } from './time';
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
              <span className="case-no">{n.caseNo}</span>
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
                {!n.fixVersion
                  ? ' · no fix'
                  : n.path.length > 1
                    ? ` · via ${n.path[0]} · pin ${n.fixVersion}`
                    : n.direct
                      ? ` · fix ${n.fixVersion}`
                      : ` · dev tooling`}
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
                  : check.kind === 'platform'
                    ? `Not exploitable here: needs ${check.feature}`
                    : `Not exploitable here: ${check.feature} never used`
                : check.kind === 'platform'
                  ? `Affected platform: ${check.feature}`
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

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="btn"
      onClick={() => {
        void navigator.clipboard?.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
    >
      {copied ? 'COPIED' : 'COPY'}
    </button>
  );
}

/** The case file, as a drawer over the page: Esc or the backdrop closes it, focus moves into it. */
export function CaseFilePanel({ file, onClose }: { file: CaseFile; onClose: () => void }) {
  const closeRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
      opener?.focus?.(); // give focus back to what opened the case
    };
  }, [onClose]);
  const top = file.findings[0];
  const cm = file.countermeasure;
  return (
    <div className="drawer-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
    <aside className={`panel case drawer ${cls(file.level)}`} role="dialog" aria-modal="true" aria-labelledby="case-title">
      <header className="panel-head">
        <span id="case-title">
          CASE FILE <span className="case-no">{file.caseNo}</span>
        </span>
        <button className="link" onClick={onClose} ref={closeRef} aria-label="Close case file (Esc)">
          close ✕
        </button>
      </header>
      <div className="case-body">
        <div className="case-subject">
          <div className="muted small">SUBJECT</div>
          <div className="subject">
            <Typed text={`${file.name}@${file.version}`} />
          </div>
          <div className="muted small">observed in {file.repo} since {fmtDateTime(file.firstSeenAt)}</div>
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
                <span className="t-at">{t.kind === 'DISCLOSED' || t.kind === 'EXPLOITED' ? t.at.slice(0, 10) : fmtDateTime(t.at)}</span>
                <span className="t-kind">{t.kind.replace('_', ' ')}</span>
                <span className="t-text">{t.text}</span>
              </li>
            ))}
          </ol>
        </div>

        <div className="block">
          <div className="muted small">COUNTERMEASURE</div>
          {cm ? (
            <>
              <div className="cm-summary">{cm.summary}</div>
              {cm.options.map((o) => (
                <div key={o.title} className="cm-option">
                  <div className="cm-title">{o.title}</div>
                  <pre className="snippet">{o.code}</pre>
                  <CopyButton text={o.code} />
                </div>
              ))}
              {file.unfixed > 0 && <div className="muted small">{file.unfixed} vulnerabilities have no fix yet</div>}
            </>
          ) : (
            <div className="muted">No patched version published yet. Monitor.</div>
          )}
        </div>
      </div>
    </aside>
    </div>
  );
}

const time = (iso: string) => fmtTime(iso);

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
