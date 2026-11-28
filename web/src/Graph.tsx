import type React from 'react';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { Graph, GraphNode, Level } from './api';

const COL_W = 232;
const NODE_W = 184;
const BIG_H = 44;
const QUIET_H = 22;
const GAP = 14;
const PAD = 30;
const MAX_ZOOM = 1.7;

interface Placed extends GraphNode {
  x: number;
  y: number;
  h: number;
  w: number;
}

const labelOf = (n: GraphNode) => (n.depth === 0 ? 'YOUR CODE' : n.id.length > 24 ? n.id.slice(0, 23) + '…' : n.id);
const isThreat = (n: GraphNode) => n.level === 'RELEVANT' || n.level === 'CRITICAL';

const color = (level: Level | null) =>
  level === 'CRITICAL' ? 'var(--red)' : level === 'RELEVANT' ? 'var(--yellow)' : 'var(--white)';

/**
 * Layered left-to-right layout. Column = depth. Each node is placed level with
 * the centre of its parents, then pushed down only as far as needed to avoid
 * overlaps, so children stay next to the box that pulls them in.
 */
function layout(graph: Graph) {
  const cols = new Map<number, GraphNode[]>();
  for (const n of graph.nodes) cols.set(n.depth, [...(cols.get(n.depth) ?? []), n]);
  const parents = new Map<string, string[]>();
  for (const e of graph.edges) parents.set(e.to, [...(parents.get(e.to) ?? []), e.from]);

  const placed = new Map<string, Placed>();
  const depths = [...cols.keys()].sort((a, b) => a - b);
  const size = (n: GraphNode) => {
    const big = !!n.level || n.depth === 0;
    return { h: big ? BIG_H : QUIET_H, w: big ? NODE_W : Math.min(NODE_W, labelOf(n).length * 6.4 + 22) };
  };

  for (const d of depths) {
    const col = cols.get(d)!;
    const desired = (n: GraphNode) => {
      const ps = (parents.get(n.id) ?? []).map((p) => placed.get(p)).filter(Boolean) as Placed[];
      if (!ps.length) return 0;
      return ps.reduce((s, p) => s + p.y + p.h / 2, 0) / ps.length - size(n).h / 2;
    };
    // nodes that lead somewhere sit nearest their parent; then threats; then the rest
    const hasKids = (n: GraphNode) => graph.edges.some((e) => e.from === n.id);
    col.sort(
      (a, b) =>
        desired(a) - desired(b) ||
        Number(isThreat(b)) - Number(isThreat(a)) ||
        b.score - a.score ||
        Number(hasKids(a)) - Number(hasKids(b)),
    );
    let cursor = -Infinity;
    const placedCol: Placed[] = [];
    for (const n of col) {
      const { h, w } = size(n);
      const y = Math.max(desired(n), cursor);
      const p = { ...n, x: PAD + d * COL_W, y, h, w };
      placed.set(n.id, p);
      placedCol.push(p);
      cursor = y + h + GAP;
    }
    // first column fans out evenly around the root
    if (d === 1 && placed.has('your code')) {
      const root = placed.get('your code')!;
      const top = placedCol[0].y;
      const bottom = cursor - GAP;
      const shift = root.y + root.h / 2 - (top + bottom) / 2;
      placedCol.forEach((p) => (p.y += shift));
    }
  }

  const all = [...placed.values()];
  const minY = Math.min(...all.map((p) => p.y));
  all.forEach((p) => (p.y += PAD - minY));
  const height = Math.max(...all.map((p) => p.y + p.h)) + PAD;
  const width = PAD * 2 + (depths.length - 1) * COL_W + NODE_W;
  return { placed, width, height };
}

/** Corner brackets: the signature of the Machine's view. */
function Brackets({ x, y, w, h, stroke, size = 8, width = 1.5 }: { x: number; y: number; w: number; h: number; stroke: string; size?: number; width?: number }) {
  const s = Math.min(size, h / 2);
  const d = [
    `M${x},${y + s}V${y}H${x + s}`,
    `M${x + w - s},${y}H${x + w}V${y + s}`,
    `M${x + w},${y + h - s}V${y + h}H${x + w - s}`,
    `M${x + s},${y + h}H${x}V${y + h - s}`,
  ].join('');
  return <path d={d} fill="none" stroke={stroke} strokeWidth={width} />;
}

/** Scale the drawing to fill the panel: zoom small graphs in, fit wide ones, scroll very tall ones. */
function useFit(width: number, height: number) {
  const ref = useRef<HTMLDivElement>(null);
  const [box, setBox] = useState({ w: 0, h: 0 });
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setBox({ w: e.contentRect.width, h: e.contentRect.height }));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const fitW = box.w / width;
  const fitBoth = Math.min(fitW, box.h / height);
  // if fitting the height would shrink text too much, fit the width and scroll instead
  const MIN_SCALE = 0.62; // below this the labels are unreadable: scroll inside the panel instead
  const scale = box.w ? Math.max(MIN_SCALE, Math.min(MAX_ZOOM, fitBoth > 0.75 * Math.min(fitW, 1) ? fitBoth : Math.min(fitW, 1))) : 1;
  return { ref, scale };
}

/** Union of several graphs: every box that ever appears, so positions stay put while scrubbing. */
export function unionGraph(graphs: Graph[]): Graph {
  const nodes = new Map<string, GraphNode>();
  const edges = new Map<string, Graph['edges'][number]>();
  for (const g of graphs) {
    for (const n of g.nodes) {
      const cur = nodes.get(n.id);
      if (!cur) nodes.set(n.id, { ...n });
      else {
        cur.depth = Math.min(cur.depth, n.depth);
        if (n.level && !cur.level) cur.level = n.level; // ever had findings -> full-size box
      }
    }
    for (const e of g.edges) edges.set(`${e.from}>${e.to}`, e);
  }
  return { nodes: [...nodes.values()], edges: [...edges.values()], hidden: 0 };
}

export function ThreatGraph({
  graph,
  layoutGraph,
  scanning,
  onSelect,
}: {
  graph: Graph;
  /** lay out this (bigger) graph instead, and draw `graph` on top of it: stable positions across frames */
  layoutGraph?: Graph;
  scanning: boolean;
  onSelect: (pkg: string) => void;
}) {
  const { placed: base, width, height } = useMemo(() => layout(layoutGraph ?? graph), [layoutGraph, graph]);
  // positions from the layout graph, everything else (level, score, version) from the current graph
  const placed = useMemo(() => {
    const m = new Map<string, Placed>();
    for (const n of graph.nodes) {
      const p = base.get(n.id);
      if (p) m.set(n.id, { ...n, x: p.x, y: p.y, h: p.h, w: p.w });
    }
    return m;
  }, [base, graph]);
  const { ref, scale } = useFit(width, height);
  const [hover, setHover] = useState<string | null>(null);

  // highlight every edge on a path through the hovered node
  const lit = useMemo(() => {
    if (!hover) return null;
    const set = new Set<string>([hover]);
    const up = (id: string) => graph.edges.filter((e) => e.to === id).forEach((e) => !set.has(e.from) && (set.add(e.from), up(e.from)));
    const down = (id: string) => graph.edges.filter((e) => e.from === id).forEach((e) => !set.has(e.to) && (set.add(e.to), down(e.to)));
    up(hover);
    down(hover);
    return set;
  }, [hover, graph]);

  return (
    <div className="graph-wrap" ref={ref}>
      {!graph.nodes.length ? (
        <div className="empty">AWAITING FIRST OBSERVATION…</div>
      ) : (
        <svg
          viewBox={`0 0 ${width} ${height}`}
          width={width * scale}
          height={height * scale}
          className="graph"
          role="group"
          aria-label={`Dependency graph: ${graph.nodes.filter((n) => n.level === 'RELEVANT' || n.level === 'CRITICAL').length} packages need attention. Tab to a package to open its case.`}
        >
          <defs>
            {/* user-space region: a perfectly horizontal edge has a zero-height bbox and would vanish */}
            <filter id="glow" filterUnits="userSpaceOnUse" x={-50} y={-50} width={width + 100} height={height + 100}>
              <feGaussianBlur stdDeviation="2.5" result="b" />
              <feMerge>
                <feMergeNode in="b" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {graph.edges.map((e) => {
            const a = placed.get(e.from);
            const b = placed.get(e.to);
            if (!a || !b) return null;
            const x1 = a.x + a.w, y1 = a.y + a.h / 2, x2 = b.x, y2 = b.y + b.h / 2;
            const mx = (x1 + x2) / 2;
            const d = `M${x1},${y1}C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
            const dim = lit && !(lit.has(e.from) && lit.has(e.to));
            return e.level && e.level !== 'IRRELEVANT' ? (
              <g key={`${e.from}>${e.to}`} opacity={dim ? 0.15 : 1}>
                <path d={d} className="edge-threat-base" stroke={color(e.level)} />
                <path d={d} className="edge-threat" stroke={color(e.level)} filter="url(#glow)" />
              </g>
            ) : (
              <path key={`${e.from}>${e.to}`} d={d} className="edge-quiet" opacity={dim ? 0.1 : 1} />
            );
          })}

          {[...placed.values()].map((n) => {
            const c = n.depth === 0 ? 'var(--white)' : color(n.level);
            const threat = isThreat(n);
            const watched = n.level === 'IRRELEVANT';
            const dim = lit && !lit.has(n.id);
            return (
              <g
                key={n.id}
                className={`node ${threat ? 'node-threat' : ''} ${n.level === 'CRITICAL' ? 'node-critical' : ''}`}
                opacity={dim ? 0.2 : threat || n.depth === 0 ? 1 : watched ? 0.75 : 0.55}
                onMouseEnter={() => setHover(n.id)}
                onMouseLeave={() => setHover(null)}
                style={{ cursor: n.level ? 'pointer' : 'default' }}
                // boxes with findings are real buttons for keyboard and screen readers
                {...(n.level
                  ? {
                      role: 'button',
                      tabIndex: 0,
                      'aria-label': `${n.id} ${n.version ?? ''}: ${n.level === 'CRITICAL' ? 'threat' : n.level.toLowerCase()}, score ${n.score}, ${n.vulns} vulnerabilit${n.vulns === 1 ? 'y' : 'ies'}. Open case.`,
                      onClick: () => onSelect(n.id),
                      onKeyDown: (e: React.KeyboardEvent) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          onSelect(n.id);
                        }
                      },
                      onFocus: () => setHover(n.id),
                      onBlur: () => setHover(null),
                    }
                  : { 'aria-hidden': true })}
              >
                {n.level && <rect className="focus-ring" x={n.x - 5} y={n.y - 5} width={n.w + 10} height={n.h + 10} />}
                {/* opaque so edges never show through a box */}
                <rect x={n.x} y={n.y} width={n.w} height={n.h} fill={threat || watched ? '#0b0b0b' : 'transparent'} />
                {threat && <rect x={n.x} y={n.y} width={n.w} height={n.h} fill={c} opacity={0.07} />}
                {watched && <rect x={n.x + 0.5} y={n.y + 0.5} width={n.w - 1} height={n.h - 1} className="watched-outline" />}
                <Brackets x={n.x} y={n.y} w={n.w} h={n.h} stroke={c} size={threat ? 10 : 5} width={threat ? 2 : 1} />
                {threat && (
                  <>
                    <rect x={n.x} y={n.y - 15} width={NODE_W * 0.56} height={13} fill={c} />
                    <text x={n.x + 4} y={n.y - 5} className="tag">
                      {n.level === 'CRITICAL' ? 'THREAT' : 'RELEVANT'} · {n.score}
                    </text>
                  </>
                )}
                <text x={n.x + 10} y={n.y + (n.h > QUIET_H ? 18 : 15)} className={threat || n.depth === 0 ? 'label' : 'label-quiet'} fill={c}>
                  {labelOf(n)}
                </text>
                {n.h > QUIET_H && n.depth > 0 && (
                  <text x={n.x + 10} y={n.y + 34} className="sub">
                    {n.version}
                    {n.vulns ? ` · ${n.vulns} vuln${n.vulns > 1 ? 's' : ''}` : ''}
                    {watched ? ' · watched' : ''}
                  </text>
                )}
                {n.depth === 0 && (
                  <text x={n.x + 10} y={n.y + 34} className="sub">
                    ENTRY POINT
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      )}
      {scanning && <div className="sweep" />}
      {graph.hidden > 0 && <div className="hidden-note">+{graph.hidden} reachable packages with no known vulnerabilities, not shown</div>}
    </div>
  );
}
