import {
  BadRequestException,
  Body,
  Controller,
  Get,
  MessageEvent,
  NotFoundException,
  Param,
  Post,
  Query,
  Sse,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { createHash } from 'crypto';
import * as semver from 'semver';
import { map, Observable } from 'rxjs';
import { Repository } from 'typeorm';
import { LEVEL_RANK } from '../core/group';
import { Countermeasure, countermeasure } from '../core/countermeasure';
import { FeatureCheck, ThreatLevel } from '../core/types';
import { FindingEntity, RepositoryEntity } from './entities';
import { EventsService } from './events.service';
import { ScanService } from './scan.service';
import { WatchService } from './watch.service';
import { HistoryService } from './history.service';

/** A "number": all open vulnerabilities for one package@version in one repo. */
export interface NumberDto {
  id: string;
  caseNo: string;
  repo: string;
  repoId: string;
  name: string;
  version: string;
  score: number;
  level: ThreatLevel;
  path: string[];
  fixVersion: string | null;
  unfixed: number;
  firstSeenAt: string;
  findings: {
    vulnId: string;
    cveId: string | null;
    summary: string;
    severity: string;
    score: number;
    level: ThreatLevel;
    reasons: string[];
    fixVersion: string | null;
    epss: number | null;
    epssPercentile: number | null;
    kevDateAdded: string | null;
    published: string | null;
    malicious: boolean;
    check: FeatureCheck | null;
    scoreHistory: { at: string; score: number }[];
  }[];
  /** every finding is ruled out by a feature check: installed, but not exploitable here */
  notExploitable: boolean;
  /** lockfile format of the repo, so the fix uses the right package manager syntax */
  lockfileFormat: string | null;
  /** how to fix it, in the project's package manager; for transitive packages, via the direct dependency */
  countermeasure: Countermeasure | null;
  /** in package.json (true), or pulled in by something else */
  direct: boolean;
}

function numberId(repoId: string, pkgKey: string) {
  return createHash('sha1').update(`${repoId}|${pkgKey}`).digest('hex').slice(0, 12);
}
/** A short, stable case number derived from the id, e.g. CASE-40217. */
function caseNo(id: string) {
  return `CASE-${(BigInt('0x' + id) % 100000n).toString().padStart(5, '0')}`;
}

@Controller('api')
export class ApiController {
  constructor(
    @InjectRepository(RepositoryEntity) private readonly repos: Repository<RepositoryEntity>,
    @InjectRepository(FindingEntity) private readonly findings: Repository<FindingEntity>,
    private readonly scanner: ScanService,
    private readonly events: EventsService,
    private readonly watch: WatchService,
    private readonly history: HistoryService,
  ) {}

  // ---------- repos ----------

  @Post('repos')
  async addRepo(@Body() body: { name?: string; path?: string; internetFacing?: boolean }) {
    if (!body?.name || !body?.path) throw new BadRequestException('name and path are required');
    return this.repos.save(
      this.repos.create({ name: body.name, path: body.path, internetFacing: !!body.internetFacing }),
    );
  }

  @Get('repos')
  listRepos() {
    return this.repos.find({ order: { name: 'ASC' }, select: ['id', 'name', 'path', 'internetFacing', 'packageCount', 'reachableCount', 'lastScannedAt'] });
  }

  @Get('repos/:id/graph')
  async graph(@Param('id') id: string) {
    const repo = await this.repos.findOneBy({ id });
    if (!repo) throw new NotFoundException();
    return repo.graph ?? { nodes: [], edges: [], hidden: 0 };
  }

  /** Time machine for one repo: summary, per-CVE history and Machine view frames. ?since=YYYY-MM-DD&refresh=1 */
  @Get('repos/:id/history')
  async repoHistory(@Param('id') id: string, @Query('since') since?: string, @Query('refresh') refresh?: string) {
    const repo = await this.repos.findOneBy({ id });
    if (!repo) throw new NotFoundException();
    try {
      return await this.history.get(repo, { since, refresh: refresh === '1' });
    } catch (e) {
      throw new BadRequestException((e as Error).message);
    }
  }

  @Post('repos/:id/scan')
  async scanRepo(@Param('id') id: string) {
    const repo = await this.repos.findOneBy({ id });
    if (!repo) throw new NotFoundException();
    void this.scanner.scanOne(repo);
    return { started: true };
  }

  /** Pull fresh KEV + EPSS now and rescore, without a rescan. */
  @Post('sweep')
  async sweep() {
    return { moved: await this.watch.sweep() };
  }

  @Post('scan')
  scanAll() {
    void this.scanner.scanAll();
    return { started: true };
  }

  // ---------- overview ----------

  @Get('overview')
  async overview() {
    const repos = await this.repos.find({ order: { name: 'ASC' } });
    const numbers = await this.allNumbers();
    const count = (level: ThreatLevel, repoId?: string) =>
      numbers.filter((n) => n.level === level && (!repoId || n.repoId === repoId)).length;
    return {
      scanning: this.scanner.isRunning,
      watch: {
        intervalSec: this.watch.intervalMs / 1000,
        lastSweepAt: this.watch.lastSweepAt,
        nextSweepAt: this.watch.nextSweepAt,
      },
      totals: {
        packages: repos.reduce((s, r) => s + r.packageCount, 0),
        reachable: repos.reduce((s, r) => s + r.reachableCount, 0),
        vulnerabilities: numbers.reduce((s, n) => s + n.findings.length, 0),
        critical: count('CRITICAL'),
        relevant: count('RELEVANT'),
        irrelevant: count('IRRELEVANT'),
      },
      repos: repos.map((r) => ({
        id: r.id,
        name: r.name,
        internetFacing: r.internetFacing,
        packageCount: r.packageCount,
        reachableCount: r.reachableCount,
        lastScannedAt: r.lastScannedAt,
        critical: count('CRITICAL', r.id),
        relevant: count('RELEVANT', r.id),
        irrelevant: count('IRRELEVANT', r.id),
      })),
    };
  }

  // ---------- numbers ----------

  /** ?level=CRITICAL,RELEVANT (default) or ?level=all, optional ?repo=<id> */
  @Get('numbers')
  async numbers(@Query('level') level?: string, @Query('repo') repoId?: string) {
    const levels: ThreatLevel[] =
      level === 'all' ? ['CRITICAL', 'RELEVANT', 'IRRELEVANT'] : level ? (level.split(',') as ThreatLevel[]) : ['CRITICAL', 'RELEVANT'];
    return (await this.allNumbers()).filter((n) => levels.includes(n.level) && (!repoId || n.repoId === repoId));
  }

  /** The case file: the number plus its timeline. */
  @Get('numbers/:id')
  async caseFile(@Param('id') id: string) {
    const n = (await this.allNumbers()).find((x) => x.id === id);
    if (!n) throw new NotFoundException();
    const timeline: { at: string; kind: string; text: string; level?: ThreatLevel | null }[] = [];
    for (const f of n.findings) {
      const ref = f.cveId ?? f.vulnId;
      if (f.published) timeline.push({ at: f.published, kind: 'DISCLOSED', text: `${ref} published` });
      if (f.kevDateAdded) timeline.push({ at: f.kevDateAdded, kind: 'EXPLOITED', text: `${ref} added to CISA KEV`, level: 'CRITICAL' });
    }
    timeline.push({ at: n.firstSeenAt, kind: 'OBSERVED', text: `Argus first saw ${n.name}@${n.version} in ${n.repo}` });
    for (const e of await this.events.forNumber(n.repo, `${n.name}@${n.version}`)) {
      if (e.type === 'NEW_NUMBER' && Math.abs(new Date(e.at).getTime() - new Date(n.firstSeenAt).getTime()) < 60_000) continue;
      timeline.push({ at: new Date(e.at).toISOString(), kind: e.type, text: e.message, level: e.level });
    }
    timeline.sort((a, b) => new Date(a.at).getTime() - new Date(b.at).getTime());
    return { ...n, timeline };
  }

  // ---------- live feed ----------

  @Get('events')
  recent(@Query('limit') limit?: string) {
    return this.events.recent(Math.min(200, Number(limit) || 60));
  }

  @Sse('events/stream')
  stream(): Observable<MessageEvent> {
    return this.events.live().pipe(map((e) => ({ data: e })));
  }

  // ---------- helpers ----------

  private async allNumbers(): Promise<NumberDto[]> {
    const open = await this.findings.find({ where: { status: 'open' } });
    const groups = new Map<string, NumberDto>();
    for (const f of open) {
      const pkgKey = `${f.packageName}@${f.packageVersion}`;
      const id = numberId(f.repository.id, pkgKey);
      let n = groups.get(id);
      if (!n) {
        n = {
          id,
          caseNo: caseNo(id),
          repo: f.repository.name,
          repoId: f.repository.id,
          name: f.packageName,
          version: f.packageVersion,
          score: 0,
          level: 'IRRELEVANT',
          path: f.path,
          fixVersion: null,
          unfixed: 0,
          firstSeenAt: new Date(f.firstSeenAt).toISOString(),
          findings: [],
          notExploitable: true,
          lockfileFormat: f.repository.lockfileFormat ?? null,
          countermeasure: null,
          direct: f.exposure?.direct ?? f.path.length <= 1,
        };
        groups.set(id, n);
      }
      n.findings.push({
        vulnId: f.vulnId,
        cveId: f.cveId,
        summary: f.summary,
        severity: f.severity,
        score: f.score,
        level: f.level,
        reasons: f.reasons,
        fixVersion: f.fixVersion,
        epss: f.epss,
        epssPercentile: f.epssPercentile,
        kevDateAdded: f.kevDateAdded,
        published: f.published,
        malicious: f.malicious,
        check: f.check ?? null,
        scoreHistory: f.scoreHistory,
      });
      if (f.check?.status !== 'unused') n.notExploitable = false;
      if (f.score > n.score) n.score = f.score;
      if (LEVEL_RANK[f.level] > LEVEL_RANK[n.level]) n.level = f.level;
      if (new Date(f.firstSeenAt).toISOString() < n.firstSeenAt) n.firstSeenAt = new Date(f.firstSeenAt).toISOString();
      if (f.fixVersion) {
        if (!n.fixVersion || (semver.valid(f.fixVersion) && semver.gt(f.fixVersion, n.fixVersion))) n.fixVersion = f.fixVersion;
      } else if (!f.malicious) n.unfixed++;
    }
    const out = [...groups.values()];
    for (const n of out) {
      n.findings.sort((a, b) => b.score - a.score);
      n.countermeasure = countermeasure(n.name, n.fixVersion, n.path, n.lockfileFormat, n.direct);
    }
    return out.sort((a, b) => b.score - a.score || b.findings.length - a.findings.length);
  }
}
