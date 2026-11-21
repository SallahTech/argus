import { BadRequestException, Body, Controller, Get, NotFoundException, Param, Post, Query } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { ThreatLevel } from '../core/types';
import { FindingEntity, RepositoryEntity } from './entities';
import { ScanService } from './scan.service';

@Controller()
export class ApiController {
  constructor(
    @InjectRepository(RepositoryEntity) private readonly repos: Repository<RepositoryEntity>,
    @InjectRepository(FindingEntity) private readonly findings: Repository<FindingEntity>,
    private readonly scanner: ScanService,
  ) {}

  @Post('repos')
  async addRepo(@Body() body: { name?: string; path?: string; internetFacing?: boolean }) {
    if (!body?.name || !body?.path) throw new BadRequestException('name and path are required');
    return this.repos.save(
      this.repos.create({ name: body.name, path: body.path, internetFacing: !!body.internetFacing }),
    );
  }

  @Get('repos')
  listRepos() {
    return this.repos.find({ order: { name: 'ASC' } });
  }

  @Post('repos/:id/scan')
  async scanRepo(@Param('id') id: string) {
    const repo = await this.repos.findOneBy({ id });
    if (!repo) throw new NotFoundException();
    return { alerts: await this.scanner.scanOne(repo) };
  }

  @Post('scan')
  scanAll() {
    return this.scanner.scanAll();
  }

  /** The open "numbers", worst first. ?level=CRITICAL,RELEVANT (default) or ?level=all */
  @Get('numbers')
  numbers(@Query('level') level?: string) {
    const levels: ThreatLevel[] =
      level === 'all'
        ? ['CRITICAL', 'RELEVANT', 'IRRELEVANT']
        : ((level?.split(',') as ThreatLevel[]) ?? ['CRITICAL', 'RELEVANT']);
    return this.findings.find({
      where: { status: 'open', level: In(levels.length ? levels : ['CRITICAL', 'RELEVANT']) },
      order: { score: 'DESC' },
    });
  }
}
