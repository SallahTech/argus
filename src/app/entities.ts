import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  ManyToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { ThreatGraph } from '../core/graph';
import { Dependency, Severity, ThreatLevel } from '../core/types';

/** What the scorer needs to know about a dependency, kept so intel sweeps can rescore without a rescan. */
export type ExposureSnapshot = Pick<Dependency, 'direct' | 'dev' | 'reachable' | 'importCount' | 'via' | 'loadedBy'>;

/** Postgres in Docker, SQLite file locally. Keep column types portable. */
export const USE_POSTGRES = !!process.env.DATABASE_URL;
const DATE = USE_POSTGRES ? 'timestamptz' : 'datetime';

@Entity('repositories')
export class RepositoryEntity {
  @PrimaryGeneratedColumn('uuid') id!: string;
  @Column({ unique: true }) name!: string;
  /** path to a local checkout */
  @Column() path!: string;
  @Column({ default: false }) internetFacing!: boolean;
  @Column({ type: 'int', default: 0 }) packageCount!: number;
  @Column({ type: 'int', default: 0 }) reachableCount!: number;
  @Column({ type: DATE, nullable: true }) lastScannedAt!: Date | null;
  @Column({ type: 'simple-json', nullable: true }) graph!: ThreatGraph | null;
  @CreateDateColumn() createdAt!: Date;
}

/** One vulnerability affecting one package version in one repo. Grouped into "numbers" by the API. */
@Entity('findings')
@Index(['repository', 'packageName', 'packageVersion', 'vulnId'], { unique: true })
export class FindingEntity {
  @PrimaryGeneratedColumn('uuid') id!: string;
  @ManyToOne(() => RepositoryEntity, { onDelete: 'CASCADE', eager: true }) repository!: RepositoryEntity;
  @Column() packageName!: string;
  @Column() packageVersion!: string;
  @Column() vulnId!: string;
  @Column({ type: 'varchar', nullable: true }) cveId!: string | null;
  @Column({ type: 'text', default: '' }) summary!: string;
  @Column({ type: 'varchar', default: 'UNKNOWN' }) severity!: Severity;
  @Column({ type: 'int' }) score!: number;
  @Column({ type: 'varchar' }) level!: ThreatLevel;
  @Column({ type: 'simple-json' }) reasons!: string[];
  @Column({ type: 'simple-json' }) path!: string[];
  @Column({ type: 'varchar', nullable: true }) fixVersion!: string | null;
  @Column({ type: 'float', nullable: true }) epss!: number | null;
  @Column({ type: 'float', nullable: true }) epssPercentile!: number | null;
  @Column({ type: 'varchar', nullable: true }) kevDateAdded!: string | null;
  @Column({ type: 'varchar', nullable: true }) published!: string | null;
  @Column({ default: false }) malicious!: boolean;
  @Column({ type: 'simple-json', nullable: true }) exposure!: ExposureSnapshot | null;
  @Column({ type: 'varchar', default: 'open' }) status!: 'open' | 'resolved';
  /** highest level we already sent an alert for, so we only re-alert on escalation */
  @Column({ type: 'varchar', nullable: true }) alertedLevel!: ThreatLevel | null;
  @Column({ type: 'simple-json' }) scoreHistory!: { at: string; score: number }[];
  @CreateDateColumn() firstSeenAt!: Date;
  @UpdateDateColumn() updatedAt!: Date;
}

export type EventType =
  | 'SCAN_START'
  | 'SCAN_STEP'
  | 'SCAN_DONE'
  | 'SCAN_ERROR'
  | 'NEW_NUMBER'
  | 'ESCALATED'
  | 'SCORE_CHANGED'
  | 'RESOLVED'
  | 'INTEL'
  | 'LOCKFILE';

/** The live feed. Everything the system notices becomes an event. */
@Entity('events')
export class EventEntity {
  @PrimaryGeneratedColumn('increment') id!: number;
  @CreateDateColumn() at!: Date;
  @Column({ type: 'varchar' }) type!: EventType;
  @Column({ type: 'varchar', nullable: true }) level!: ThreatLevel | null;
  @Column({ type: 'varchar', nullable: true }) repoName!: string | null;
  /** name@version, links the event to a number */
  @Column({ type: 'varchar', nullable: true }) packageKey!: string | null;
  @Column({ type: 'varchar', nullable: true }) vulnId!: string | null;
  @Column({ type: 'text' }) message!: string;
}
