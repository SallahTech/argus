import 'reflect-metadata';
import { Injectable, Logger, Module, OnApplicationBootstrap } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { ScheduleModule } from '@nestjs/schedule';
import { InjectRepository, TypeOrmModule } from '@nestjs/typeorm';
import { existsSync, readFileSync } from 'fs';
import { homedir } from 'os';
import { join, resolve } from 'path';
import { Repository } from 'typeorm';
import { AlertService } from './app/alert.service';
import { ApiController } from './app/api.controller';
import { EventEntity, FindingEntity, RepositoryEntity, USE_POSTGRES } from './app/entities';
import { EventsService } from './app/events.service';
import { ScanService } from './app/scan.service';
import { WatchService } from './app/watch.service';

const ENTITIES = [RepositoryEntity, FindingEntity, EventEntity];
const ROOT = resolve(__dirname, '..');

interface ArgusConfig {
  repos: { name: string; path: string; internetFacing?: boolean }[];
}

/** Registers repos from argus.config.json and starts the first scan on boot. */
@Injectable()
class Bootstrapper implements OnApplicationBootstrap {
  private readonly log = new Logger('Argus');
  constructor(
    @InjectRepository(RepositoryEntity) private readonly repos: Repository<RepositoryEntity>,
    private readonly scanner: ScanService,
  ) {}

  async onApplicationBootstrap() {
    const file = process.env.ARGUS_CONFIG ?? join(ROOT, 'argus.config.json');
    if (existsSync(file)) {
      const cfg: ArgusConfig = JSON.parse(readFileSync(file, 'utf8'));
      for (const r of cfg.repos ?? []) {
        const path = r.path.replace(/^~(?=$|\/)/, homedir());
        const existing = await this.repos.findOneBy({ name: r.name });
        await this.repos.save({ ...(existing ?? {}), name: r.name, path, internetFacing: !!r.internetFacing });
      }
      this.log.log(`watching ${cfg.repos?.length ?? 0} repos from ${file}`);
    }
    if (process.env.SCAN_ON_BOOT !== 'false') setTimeout(() => void this.scanner.scanAll(), 1500);
  }
}

@Module({
  imports: [
    ScheduleModule.forRoot(),
    TypeOrmModule.forRoot(
      USE_POSTGRES
        ? { type: 'postgres', url: process.env.DATABASE_URL, entities: ENTITIES, synchronize: true }
        : // no Docker needed: a local SQLite file (pure JS driver)
          { type: 'sqljs', location: process.env.ARGUS_DB ?? join(ROOT, 'argus.sqlite'), autoSave: true, entities: ENTITIES, synchronize: true },
    ),
    TypeOrmModule.forFeature(ENTITIES),
  ],
  controllers: [ApiController],
  providers: [ScanService, WatchService, AlertService, EventsService, Bootstrapper],
})
class AppModule {}

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  const web = join(ROOT, 'web', 'dist');
  if (existsSync(web)) app.useStaticAssets(web);
  const port = Number(process.env.PORT ?? 3000);
  await app.listen(port);
  new Logger('Argus').log(`Machine view at http://localhost:${port}`);
}
bootstrap();
