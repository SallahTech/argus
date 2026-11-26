import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { buildGraph } from '../core/graph';
import { groupFindings, LEVEL_RANK } from '../core/group';
import { scanRepo } from '../core/pipeline';
import { AlertService } from './alert.service';
import { FindingEntity, RepositoryEntity } from './entities';
import { EventsService } from './events.service';

@Injectable()
export class ScanService {
  private readonly log = new Logger('Scan');
  private running = false;
  private readonly busy = new Set<string>();

  constructor(
    @InjectRepository(RepositoryEntity) private readonly repos: Repository<RepositoryEntity>,
    @InjectRepository(FindingEntity) private readonly findings: Repository<FindingEntity>,
    private readonly alerts: AlertService,
    private readonly events: EventsService,
  ) {}

  get isRunning() {
    return this.running || this.busy.size > 0;
  }

  /** Full rescan: new advisories from OSV and lockfile changes. Intel sweeps run more often (WatchService). */
  @Cron(process.env.SCAN_CRON ?? '0 * * * *')
  async scheduled() {
    await this.scanAll();
  }

  async scanAll(): Promise<{ repos: number; alerts: number }> {
    if (this.running) return { repos: 0, alerts: 0 };
    this.running = true;
    let alerts = 0;
    try {
      const all = await this.repos.find();
      for (const repo of all) alerts += await this.scanOne(repo);
      return { repos: all.length, alerts };
    } finally {
      this.running = false;
    }
  }

  /** Returns how many alerts were sent. */
  async scanOne(repo: RepositoryEntity): Promise<number> {
    if (this.busy.has(repo.id)) return 0;
    this.busy.add(repo.id);
    try {
      return await this.doScan(repo);
    } finally {
      this.busy.delete(repo.id);
    }
  }

  private async doScan(repo: RepositoryEntity): Promise<number> {
    const base = { repoName: repo.name };
    await this.events.emit({ ...base, type: 'SCAN_START', message: `Observing ${repo.name}` });
    let result;
    try {
      result = await scanRepo(repo.path, { name: repo.name, internetFacing: repo.internetFacing }, fetch, (step, detail) =>
        void this.events.emit({ ...base, type: 'SCAN_STEP', message: `${step.toUpperCase()} ${detail}` }),
      );
    } catch (e) {
      const message = (e as Error).message;
      this.log.error(`${repo.name}: ${message}`);
      await this.events.emit({ ...base, type: 'SCAN_ERROR', message });
      return 0;
    }

    const now = new Date().toISOString();
    const existing = await this.findings.find({ where: { repository: { id: repo.id } } });
    const byKey = new Map(existing.map((f) => [key(f.packageName, f.packageVersion, f.vulnId), f]));
    const seen = new Set<string>();
    let sent = 0;

    for (const r of result.findings) {
      const k = key(r.dependency.name, r.dependency.version, r.vulnerability.id);
      seen.add(k);
      const pkgKey = `${r.dependency.name}@${r.dependency.version}`;
      const isNew = !byKey.has(k);
      const f =
        byKey.get(k) ??
        this.findings.create({
          repository: repo,
          packageName: r.dependency.name,
          packageVersion: r.dependency.version,
          vulnId: r.vulnerability.id,
          alertedLevel: null,
          scoreHistory: [],
        });
      const wasOpen = f.status === 'open';
      const prevScore = f.score;
      const prevLevel = f.level;

      Object.assign(f, {
        cveId: r.vulnerability.cveIds[0] ?? null,
        summary: r.vulnerability.summary,
        severity: r.vulnerability.severity,
        score: r.score,
        level: r.level,
        reasons: r.reasons,
        path: r.dependency.path ?? [r.dependency.name],
        fixVersion: r.fixVersion,
        epss: r.vulnerability.epss?.score ?? null,
        epssPercentile: r.vulnerability.epss?.percentile ?? null,
        kevDateAdded: r.vulnerability.kev?.dateAdded ?? null,
        published: r.vulnerability.published ?? null,
        malicious: r.vulnerability.malicious,
        exposure: {
          direct: r.dependency.direct,
          dev: r.dependency.dev,
          reachable: r.dependency.reachable,
          importCount: r.dependency.importCount,
          via: r.dependency.via,
          loadedBy: r.dependency.loadedBy,
          buildTimeOnly: r.dependency.buildTimeOnly,
          buildTool: r.dependency.buildTool,
        },
        check: r.check ?? null,
        status: 'open',
      });
      const last = f.scoreHistory.at(-1);
      if (!last || last.score !== r.score) f.scoreHistory = [...f.scoreHistory, { at: now, score: r.score }];
      await this.findings.save(f);

      const id = f.cveId ?? f.vulnId;
      const ev = { ...base, packageKey: pkgKey, vulnId: f.vulnId, level: r.level };
      if (isNew || !wasOpen) {
        if (r.level !== 'IRRELEVANT')
          await this.events.emit({ ...ev, type: 'NEW_NUMBER', message: `${pkgKey} ${id} scored ${r.score}` });
      } else if (prevLevel && LEVEL_RANK[r.level] > LEVEL_RANK[prevLevel]) {
        await this.events.emit({ ...ev, type: 'ESCALATED', message: `${pkgKey} ${id} ${prevLevel} → ${r.level} (${prevScore} → ${r.score})` });
      } else if (prevScore !== r.score && r.level !== 'IRRELEVANT') {
        await this.events.emit({ ...ev, type: 'SCORE_CHANGED', message: `${pkgKey} ${id} ${prevScore} → ${r.score}` });
      }

      // alert on new RELEVANT/CRITICAL findings, and when one escalates
      const alerted = f.alertedLevel ? LEVEL_RANK[f.alertedLevel] : 0;
      if (r.level !== 'IRRELEVANT' && LEVEL_RANK[r.level] > alerted) {
        await this.alerts.send(f);
        f.alertedLevel = r.level;
        await this.findings.save(f);
        sent++;
      }
    }

    // anything not seen this time was upgraded or removed
    const gone = existing.filter((f) => f.status === 'open' && !seen.has(key(f.packageName, f.packageVersion, f.vulnId)));
    for (const f of gone) {
      f.status = 'resolved';
      await this.events.emit({
        ...base,
        type: 'RESOLVED',
        packageKey: `${f.packageName}@${f.packageVersion}`,
        vulnId: f.vulnId,
        message: `${f.packageName}@${f.packageVersion} ${f.cveId ?? f.vulnId} no longer present`,
      });
    }
    if (gone.length) await this.findings.save(gone);

    const groups = groupFindings(result.findings);
    repo.graph = buildGraph(result.dependencies, groups);
    repo.packageCount = result.dependencies.length;
    repo.reachableCount = result.dependencies.filter((d) => d.reachable && !d.dev).length;
    repo.lastScannedAt = new Date();
    await this.repos.save(repo);

    const attention = groups.filter((g) => g.level !== 'IRRELEVANT').length;
    await this.events.emit({
      ...base,
      type: 'SCAN_DONE',
      message: `${result.findings.length} vulnerabilities in ${groups.length} packages · ${attention} need attention`,
    });
    this.log.log(`${repo.name}: ${result.findings.length} findings, ${sent} alerts, ${gone.length} resolved`);
    return sent;
  }
}

const key = (name: string, version: string, vuln: string) => `${name}@${version}|${vuln}`;
