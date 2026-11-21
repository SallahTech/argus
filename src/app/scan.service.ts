import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { scanRepo } from '../core/pipeline';
import { ThreatLevel } from '../core/types';
import { AlertService } from './alert.service';
import { FindingEntity, RepositoryEntity } from './entities';

const RANK: Record<ThreatLevel, number> = { IRRELEVANT: 0, RELEVANT: 1, CRITICAL: 2 };

@Injectable()
export class ScanService {
  private readonly log = new Logger('Scan');
  private running = false;

  constructor(
    @InjectRepository(RepositoryEntity) private readonly repos: Repository<RepositoryEntity>,
    @InjectRepository(FindingEntity) private readonly findings: Repository<FindingEntity>,
    private readonly alerts: AlertService,
  ) {}

  @Cron(process.env.SCAN_CRON ?? '0 */6 * * *')
  async scheduled() {
    await this.scanAll();
  }

  async scanAll(): Promise<{ repos: number; alerts: number }> {
    if (this.running) return { repos: 0, alerts: 0 };
    this.running = true;
    let alerts = 0;
    try {
      const all = await this.repos.find();
      for (const repo of all) {
        try {
          alerts += await this.scanOne(repo);
        } catch (e) {
          this.log.error(`${repo.name}: ${(e as Error).message}`);
        }
      }
      return { repos: all.length, alerts };
    } finally {
      this.running = false;
    }
  }

  /** Returns how many alerts were sent. */
  async scanOne(repo: RepositoryEntity): Promise<number> {
    const result = await scanRepo(repo.path, { name: repo.name, internetFacing: repo.internetFacing });
    const now = new Date().toISOString();
    const existing = await this.findings.find({ where: { repository: { id: repo.id } } });
    const byKey = new Map(existing.map((f) => [key(f.packageName, f.packageVersion, f.vulnId), f]));
    const seen = new Set<string>();
    let sent = 0;

    for (const r of result.findings) {
      const k = key(r.dependency.name, r.dependency.version, r.vulnerability.id);
      seen.add(k);
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
      f.cveId = r.vulnerability.cveIds[0] ?? null;
      f.summary = r.vulnerability.summary;
      f.score = r.score;
      f.level = r.level;
      f.reasons = r.reasons;
      f.fixVersion = r.fixVersion;
      f.status = 'open';
      const last = f.scoreHistory.at(-1);
      if (!last || last.score !== r.score) f.scoreHistory = [...f.scoreHistory, { at: now, score: r.score }];

      // alert on new RELEVANT/CRITICAL findings, and when one escalates
      const alerted = f.alertedLevel ? RANK[f.alertedLevel] : 0;
      const shouldAlert = r.level !== 'IRRELEVANT' && RANK[r.level] > alerted;
      await this.findings.save(f);
      if (shouldAlert) {
        await this.alerts.send(f);
        f.alertedLevel = r.level;
        await this.findings.save(f);
        sent++;
      }
    }

    // anything not seen this time was upgraded or removed
    const gone = existing.filter((f) => f.status === 'open' && !seen.has(key(f.packageName, f.packageVersion, f.vulnId)));
    for (const f of gone) f.status = 'resolved';
    if (gone.length) await this.findings.save(gone);

    repo.packageCount = result.dependencies.length;
    repo.lastScannedAt = new Date();
    await this.repos.save(repo);
    this.log.log(`${repo.name}: ${result.findings.length} findings, ${sent} alerts, ${gone.length} resolved`);
    return sent;
  }
}

const key = (name: string, version: string, vuln: string) => `${name}@${version}|${vuln}`;
