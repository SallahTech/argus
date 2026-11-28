import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { execFileSync } from 'child_process';
import { statSync } from 'fs';
import { Repository } from 'typeorm';
import { HistoryReport, replayHistory } from '../core/history/replay';
import { findLockfile } from '../core/lockfiles';
import { HistoryCacheEntity, RepositoryEntity } from './entities';
import { EventsService } from './events.service';
import { repoContext } from './repo-context';

const FRESH_MS = 24 * 60 * 60 * 1000;

export type CachedHistory = HistoryReport & { computedAt: string; stale: boolean };

/**
 * The time machine, cached in the database.
 *
 * - Fresh cache (same lockfile state, under 24h old): returned instantly.
 * - Stale cache (lockfile changed, or older than a day): returned instantly
 *   with stale: true, and a new replay runs in the background. An INTEL event
 *   tells the dashboard to reload when it's done.
 * - No cache: the replay runs and the caller waits for it (first run only).
 */
@Injectable()
export class HistoryService {
  private readonly log = new Logger('History');
  private readonly running = new Map<string, Promise<CachedHistory>>();

  constructor(
    @InjectRepository(HistoryCacheEntity) private readonly cache: Repository<HistoryCacheEntity>,
    private readonly events: EventsService,
  ) {}

  /** Everything the replay result depends on, except the date. */
  private keyFor(repo: RepositoryEntity, since?: string): string {
    const lock = findLockfile(repo.path);
    let head = '';
    try {
      head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repo.path, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    } catch {
      /* not a git repo */
    }
    const st = lock ? statSync(lock.file) : null;
    const ctx = repoContext(repo);
    return [since ?? '', ctx.internetFacing, ctx.platform ?? '', lock?.name ?? '', st?.mtimeMs ?? '', st?.size ?? '', head].join('|');
  }

  async get(repo: RepositoryEntity, opts: { since?: string; refresh?: boolean } = {}): Promise<CachedHistory> {
    const key = this.keyFor(repo, opts.since);
    const row = opts.refresh ? null : await this.cache.findOneBy({ repoId: repo.id });
    if (row) {
      const fresh = row.key === key && Date.now() - new Date(row.computedAt).getTime() < FRESH_MS;
      if (!fresh) void this.run(repo, key, opts.since).catch(() => {}); // refresh in the background
      return { ...(JSON.parse(row.report) as HistoryReport), computedAt: new Date(row.computedAt).toISOString(), stale: !fresh };
    }
    return this.run(repo, key, opts.since);
  }

  /** Replay unless one is already running for this repo. */
  private run(repo: RepositoryEntity, key: string, since?: string): Promise<CachedHistory> {
    const inflight = this.running.get(repo.id);
    if (inflight) return inflight;
    const started = Date.now();
    const p = replayHistory(repo.path, repoContext(repo), { since, frames: true })
      .then(async (r) => {
        const computedAt = new Date();
        await this.cache.save({ repoId: repo.id, key, computedAt, report: JSON.stringify(r) });
        const secs = Math.round((Date.now() - started) / 1000);
        this.log.log(`${repo.name}: ${r.frames?.length ?? 0} frames from ${r.snapshots.length} lockfile versions in ${secs}s`);
        const lead = r.summary.medianLeadDays !== null ? ` · median lead ${r.summary.medianLeadDays} days before KEV` : '';
        await this.events.emit({
          type: 'INTEL',
          repoName: repo.name,
          message: `TIME MACHINE replayed ${r.from} → ${r.to}: ${r.summary.everRelevant} became relevant, ${r.summary.exploited} exploited${lead}`,
        });
        return { ...r, computedAt: computedAt.toISOString(), stale: false };
      })
      .finally(() => this.running.delete(repo.id));
    this.running.set(repo.id, p);
    return p;
  }

  /** Make sure every repo has a replay ready, so the first click on TIME MACHINE is instant. */
  async warm(repos: RepositoryEntity[]): Promise<void> {
    for (const repo of repos) {
      if (await this.cache.findOneBy({ repoId: repo.id })) continue;
      try {
        await this.run(repo, this.keyFor(repo));
      } catch (e) {
        this.log.warn(`${repo.name}: no time machine (${(e as Error).message})`);
      }
    }
  }
}
