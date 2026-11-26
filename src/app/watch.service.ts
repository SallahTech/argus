import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { promises as fs } from 'fs';
import { IsNull, Not, Repository } from 'typeorm';
import { fetchEpss, fetchKev } from '../core/feeds';
import { findLockfile } from '../core/lockfiles';
import { LEVEL_RANK } from '../core/group';
import { assess } from '../core/scoring';
import { Dependency, Vulnerability } from '../core/types';
import { AlertService } from './alert.service';
import { FindingEntity, RepositoryEntity } from './entities';
import { EventsService } from './events.service';
import { ScanService } from './scan.service';

const minutes = (v: string | undefined, def: number) => (Number(v) > 0 ? Number(v) : def) * 60_000;

/**
 * The always-on part.
 * - Intel sweep (every WATCH_INTERVAL_MIN, default 10): pulls CISA KEV + EPSS and
 *   rescores every open finding from stored state. No rescan needed, so a CVE
 *   that starts being exploited escalates within minutes.
 * - Lockfile watcher (every 5s): when a watched repo's lockfile (npm, pnpm or yarn)
 *   changes (you upgraded or added something), it re-observes that repo.
 */
@Injectable()
export class WatchService implements OnModuleInit, OnModuleDestroy {
  private readonly log = new Logger('Watch');
  readonly intervalMs = minutes(process.env.WATCH_INTERVAL_MIN, 10);
  lastSweepAt: Date | null = null;
  nextSweepAt: Date | null = null;
  private kevKnown: Set<string> | null = null;
  private sweepTimer?: NodeJS.Timeout;
  private lockTimer?: NodeJS.Timeout;
  private readonly mtimes = new Map<string, number>();
  private readonly pending = new Map<string, number>();
  private sweeping = false;

  constructor(
    @InjectRepository(RepositoryEntity) private readonly repos: Repository<RepositoryEntity>,
    @InjectRepository(FindingEntity) private readonly findings: Repository<FindingEntity>,
    private readonly scanner: ScanService,
    private readonly alerts: AlertService,
    private readonly events: EventsService,
  ) {}

  onModuleInit() {
    if (process.env.WATCH === 'false') return;
    this.nextSweepAt = new Date(Date.now() + this.intervalMs);
    this.sweepTimer = setInterval(() => void this.sweep(), this.intervalMs);
    this.lockTimer = setInterval(() => void this.checkLockfiles(), 5000);
  }

  onModuleDestroy() {
    clearInterval(this.sweepTimer);
    clearInterval(this.lockTimer);
  }

  /** Re-score every open finding with fresh exploit intel. Returns how many scores moved. */
  async sweep(): Promise<number> {
    if (this.sweeping || this.scanner.isRunning) return 0;
    this.sweeping = true;
    this.nextSweepAt = new Date(Date.now() + this.intervalMs);
    try {
      const open = await this.findings.find({ where: { status: 'open', exposure: Not(IsNull()) } });
      const cves = [...new Set(open.map((f) => f.cveId).filter((c): c is string => !!c))];
      const [kev, epss] = await Promise.all([fetchKev(), cves.length ? fetchEpss(cves) : Promise.resolve(new Map())]);

      const newKev = this.kevKnown ? [...kev.keys()].filter((c) => !this.kevKnown!.has(c)) : [];
      this.kevKnown = new Set(kev.keys());
      const ours = open.filter((f) => f.cveId && kev.has(f.cveId) && !f.kevDateAdded).length;

      let moved = 0;
      for (const f of open) {
        if (await this.rescore(f, kev, epss)) moved++;
      }
      this.lastSweepAt = new Date();
      await this.events.emit({
        type: 'INTEL',
        level: ours ? 'CRITICAL' : null,
        message:
          `SWEEP CISA KEV ${kev.size} exploited CVEs` +
          (newKev.length ? ` (+${newKev.length} new)` : '') +
          ` · EPSS ${epss.size} refreshed · ` +
          (moved ? `${moved} score${moved > 1 ? 's' : ''} moved` : 'no change') +
          (ours ? ` · ${ours} of yours now exploited` : ''),
      });
      return moved;
    } catch (e) {
      this.log.error(`sweep failed: ${(e as Error).message}`);
      await this.events.emit({ type: 'SCAN_ERROR', message: `intel sweep failed: ${(e as Error).message}` });
      return 0;
    } finally {
      this.sweeping = false;
    }
  }

  private async rescore(
    f: FindingEntity,
    kev: Map<string, { dateAdded: string; ransomware: boolean }>,
    epss: Map<string, { score: number; percentile: number }>,
  ): Promise<boolean> {
    const dep: Dependency = {
      name: f.packageName,
      version: f.packageVersion,
      children: [],
      peers: [],
      path: f.path,
      ...f.exposure!,
    };
    const k = f.cveId ? kev.get(f.cveId) : undefined;
    const e = f.cveId ? epss.get(f.cveId) : undefined;
    const vuln: Vulnerability = {
      id: f.vulnId,
      aliases: [],
      cveIds: f.cveId ? [f.cveId] : [],
      summary: f.summary,
      severity: f.severity,
      malicious: f.malicious,
      fixedVersions: { [f.packageName]: f.fixVersion ? [f.fixVersion] : [] },
      kev: k ?? (f.kevDateAdded ? { dateAdded: f.kevDateAdded, ransomware: false } : undefined),
      epss: e ?? (f.epss != null ? { score: f.epss, percentile: f.epssPercentile ?? 0 } : undefined),
    };
    const a = assess(dep, vuln, { name: f.repository.name, internetFacing: f.repository.internetFacing });
    const newlyExploited = !!k && !f.kevDateAdded;
    f.epss = vuln.epss?.score ?? null;
    f.epssPercentile = vuln.epss?.percentile ?? null;
    f.kevDateAdded = vuln.kev?.dateAdded ?? null;
    if (a.score === f.score && !newlyExploited) {
      await this.findings.save(f);
      return false;
    }

    const prev = { score: f.score, level: f.level };
    Object.assign(f, { score: a.score, level: a.level, reasons: a.reasons });
    f.scoreHistory = [...f.scoreHistory, { at: new Date().toISOString(), score: a.score }];
    await this.findings.save(f);

    const pkgKey = `${f.packageName}@${f.packageVersion}`;
    const id = f.cveId ?? f.vulnId;
    const ev = { repoName: f.repository.name, packageKey: pkgKey, vulnId: f.vulnId, level: a.level };
    if (newlyExploited)
      await this.events.emit({ ...ev, level: 'CRITICAL', type: 'INTEL', message: `${id} in ${pkgKey} is now exploited in the wild (CISA KEV)` });
    if (LEVEL_RANK[a.level] > LEVEL_RANK[prev.level])
      await this.events.emit({ ...ev, type: 'ESCALATED', message: `${pkgKey} ${id} ${prev.level} → ${a.level} (${prev.score} → ${a.score})` });
    else if (a.level !== 'IRRELEVANT' || prev.level !== 'IRRELEVANT')
      await this.events.emit({ ...ev, type: 'SCORE_CHANGED', message: `${pkgKey} ${id} ${prev.score} → ${a.score}` });

    const alerted = f.alertedLevel ? LEVEL_RANK[f.alertedLevel] : 0;
    if (a.level !== 'IRRELEVANT' && LEVEL_RANK[a.level] > alerted) {
      await this.alerts.send(f);
      f.alertedLevel = a.level;
      await this.findings.save(f);
    }
    return true;
  }

  /** Rescan a repo once its lockfile (npm, pnpm or yarn) changes and then holds still for one tick. */
  private async checkLockfiles() {
    for (const repo of await this.repos.find()) {
      const lock = findLockfile(repo.path);
      if (!lock) continue;
      let mtime: number;
      try {
        mtime = (await fs.stat(lock.file)).mtimeMs;
      } catch {
        continue;
      }
      const known = this.mtimes.get(repo.id);
      if (known === undefined) {
        this.mtimes.set(repo.id, mtime);
        continue;
      }
      if (mtime === known) continue;
      if (this.pending.get(repo.id) !== mtime) {
        this.pending.set(repo.id, mtime); // npm may still be writing; wait one tick
        continue;
      }
      this.pending.delete(repo.id);
      this.mtimes.set(repo.id, mtime);
      await this.events.emit({ type: 'LOCKFILE', repoName: repo.name, message: `${repo.name}/${lock.name} changed · re-observing` });
      void this.scanner.scanOne(repo);
    }
  }
}
