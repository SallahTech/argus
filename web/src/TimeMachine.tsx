import { useEffect, useRef } from 'react';
import type { HistoryFrame, HistoryReport } from './api';

const ts = (d: string) => new Date(d + 'T00:00:00Z').getTime();
import { fmtDateTime } from './time';

/** history dates are calendar days (YYYY-MM-DD): shown as they are, no time zone shifting */
const fmt = (d: string) => d;

const NOTE_ORDER = ['exploited', 'critical', 'relevant', 'resolved', 'lockfile'] as const;
const tickKind = (f: HistoryFrame) => NOTE_ORDER.find((k) => f.notes.some((n) => n.kind === k));

/** Time-proportional track: frames sit where their date is, ticks mark what happened. */
export function Scrubber({
  report,
  index,
  onChange,
  playing,
  onTogglePlay,
}: {
  report: HistoryReport;
  index: number;
  onChange: (i: number) => void;
  playing: boolean;
  onTogglePlay: () => void;
}) {
  const track = useRef<HTMLDivElement>(null);
  const frames = report.frames;
  const t0 = ts(report.from);
  const t1 = Math.max(ts(report.to), t0 + 1);
  const pos = (d: string) => ((ts(d) - t0) / (t1 - t0)) * 100;
  const frame = frames[index];

  const pick = (clientX: number) => {
    const r = track.current!.getBoundingClientRect();
    const t = t0 + Math.min(1, Math.max(0, (clientX - r.left) / r.width)) * (t1 - t0);
    // the frame in force at that moment: the last one on or before it
    let best = 0;
    frames.forEach((f, i) => ts(f.date) <= t && (best = i));
    onChange(best);
  };

  // keyboard: arrows step through frames
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      // leave keys alone when something else handles them (a focused button, a form field, an open case)
      if (e.defaultPrevented || ['INPUT', 'TEXTAREA', 'BUTTON', 'A'].includes(t?.tagName) || t?.getAttribute?.('role') === 'button') return;
      if (document.querySelector('.drawer')) return;
      if (e.key === 'ArrowLeft') onChange(Math.max(0, index - 1));
      if (e.key === 'ArrowRight') onChange(Math.min(frames.length - 1, index + 1));
      if (e.key === 'Home') onChange(0);
      if (e.key === 'End') onChange(frames.length - 1);
      if (e.key === ' ') (e.preventDefault(), onTogglePlay());
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [index, frames.length, onChange, onTogglePlay]);

  return (
    <div className="scrubber">
      <button className="btn play" onClick={onTogglePlay} title="Play (space)" aria-label={playing ? 'Pause' : 'Play the timeline'}>
        {playing ? '❚❚' : '▶'}
      </button>
      <div className="scrub-date">
        <div className="scrub-day">{fmt(frame.date)}</div>
        <div className="muted small">
          {frame.counts.critical > 0 && <span className="c-red">{frame.counts.critical} threat · </span>}
          {frame.counts.relevant} relevant · {frame.counts.watched} watched
        </div>
      </div>
      <div
        className="track"
        ref={track}
        role="slider"
        tabIndex={0}
        aria-label="Time machine date"
        aria-valuemin={0}
        aria-valuemax={frames.length - 1}
        aria-valuenow={index}
        aria-valuetext={`${frame.date}: ${frame.counts.critical} threats, ${frame.counts.relevant} relevant`}
        onPointerDown={(e) => {
          (e.target as HTMLElement).setPointerCapture(e.pointerId);
          pick(e.clientX);
        }}
        onPointerMove={(e) => e.buttons === 1 && pick(e.clientX)}
      >
        <div className="track-line" />
        <div className="track-fill" style={{ width: `${pos(frame.date)}%` }} />
        {frames.map((f, i) => {
          const k = tickKind(f);
          return k ? <div key={i} className={`tick tick-${k}`} style={{ left: `${pos(f.date)}%` }} title={`${f.date}: ${f.notes.map((n) => n.text).join(', ')}`} /> : null;
        })}
        <div className="handle" style={{ left: `${pos(frame.date)}%` }} />
        <div className="track-labels">
          <span>{fmt(report.from)}</span>
          <span>today</span>
        </div>
      </div>
    </div>
  );
}

const NOTE_CLASS: Record<string, string> = { exploited: 'c-red', critical: 'c-red', relevant: 'c-yellow', resolved: 'c-white', lockfile: 'muted' };

export function TimeMachinePanel({
  report,
  index,
  onJump,
  onRefresh,
}: {
  report: HistoryReport;
  index: number;
  onJump: (date: string) => void;
  onRefresh: () => void;
}) {
  const s = report.summary;
  const frame = report.frames[index];
  const kev = report.findings.filter((f) => f.kevDate && f.firstRelevant).sort((a, b) => (b.leadDays ?? -1e9) - (a.leadDays ?? -1e9));
  const fixed = report.findings.filter((f) => f.firstRelevant && f.removedOn).sort((a, b) => b.daysOpen! - a.daysOpen!);
  return (
    <section className="panel numbers tm">
      <header className="panel-head">
        <span>TIME MACHINE</span>
        <span className="muted small">
          {report.stale ? 'updating… ' : ''}replayed {fmtDateTime(report.computedAt)}
          <button className="link inline" onClick={onRefresh} title="Replay again with fresh intel" aria-label="Replay again with fresh intel">
            ↻
          </button>
        </span>
      </header>
      <div className="case-body">
        <div className="tm-stats">
          <div>
            <div className="muted small">LEAD TIME</div>
            <div className="tm-big c-yellow">{s.medianLeadDays !== null ? `${s.medianLeadDays}d` : '—'}</div>
            <div className="muted small">median before CISA KEV</div>
          </div>
          <div>
            <div className="muted small">TIME TO FIX</div>
            <div className="tm-big">{s.medianDaysToFix !== null ? `${s.medianDaysToFix}d` : '—'}</div>
            <div className="muted small">median, relevant → upgraded</div>
          </div>
        </div>
        <div className="muted small">
          {report.snapshots.length} lockfile versions · {s.everRelevant} became relevant · {s.exploited} exploited · {s.stillOpen} still open
        </div>

        <div className="block">
          <div className="muted small">ON {frame.date}</div>
          {frame.notes.length ? (
            frame.notes.map((n, i) => (
              <div key={i} className={`tm-note ${NOTE_CLASS[n.kind]}`}>
                <span className="t-kind">{n.kind.toUpperCase()}</span> {n.text}
              </div>
            ))
          ) : (
            <div className="muted">Nothing changed. The Machine was watching.</div>
          )}
        </div>

        <div className="block">
          <div className="muted small">FLAGGED BEFORE CISA CONFIRMED EXPLOITATION</div>
          {!kev.length && <div className="muted">No vulnerability in this history was added to CISA KEV.</div>}
          {kev.map((f) => (
            <button key={f.vulnId + f.version} className="tm-row" onClick={() => onJump(f.firstRelevant!)}>
              <span className={f.leadDays && f.leadDays > 0 ? 'tm-lead' : 'muted'}>
                {f.leadDays === null ? 'n/a' : f.leadDays > 0 ? `+${f.leadDays}d` : `${f.leadDays}d`}
              </span>
              <span>
                {f.cveId ?? f.vulnId} <span className="muted">{f.name}@{f.version}</span>
                <div className="muted small">
                  relevant {f.firstRelevant} → KEV {f.kevDate}
                </div>
              </span>
            </button>
          ))}
        </div>

        <div className="block">
          <div className="muted small">FIXED</div>
          {!fixed.length && <div className="muted">No relevant finding was fixed in this period.</div>}
          {fixed.slice(0, 12).map((f) => (
            <button key={f.vulnId + f.version} className="tm-row" onClick={() => onJump(f.removedOn!)}>
              <span className="muted">{f.daysOpen}d</span>
              <span>
                {f.name}@{f.version} <span className="muted">{f.cveId ?? f.vulnId}</span>
                <div className="muted small">
                  {f.firstRelevant} → upgraded {f.removedOn}
                </div>
              </span>
            </button>
          ))}
        </div>
      </div>
    </section>
  );
}
