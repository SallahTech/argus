import 'reflect-metadata';
import { Module } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { ScheduleModule } from '@nestjs/schedule';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AlertService } from './app/alert.service';
import { ApiController } from './app/api.controller';
import { FindingEntity, RepositoryEntity } from './app/entities';
import { ScanService } from './app/scan.service';

@Module({
  imports: [
    ScheduleModule.forRoot(),
    TypeOrmModule.forRoot({
      type: 'postgres',
      url: process.env.DATABASE_URL ?? 'postgres://argus:argus@localhost:5432/argus',
      entities: [RepositoryEntity, FindingEntity],
      synchronize: true, // MVP only: switch to migrations before real use
    }),
    TypeOrmModule.forFeature([RepositoryEntity, FindingEntity]),
  ],
  controllers: [ApiController],
  providers: [ScanService, AlertService],
})
class AppModule {}

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
