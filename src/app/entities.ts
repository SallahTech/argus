import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  ManyToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { ThreatLevel } from '../core/types';

@Entity('repositories')
export class RepositoryEntity {
  @PrimaryGeneratedColumn('uuid') id!: string;
  @Column({ unique: true }) name!: string;
  /** path to a local checkout (mounted into the container at /repos) */
  @Column() path!: string;
  @Column({ default: false }) internetFacing!: boolean;
  @Column({ type: 'int', default: 0 }) packageCount!: number;
  @Column({ type: 'timestamptz', nullable: true }) lastScannedAt!: Date | null;
  @CreateDateColumn() createdAt!: Date;
}

/** A "number": one vulnerability affecting one package version in one repo. */
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
  @Column({ type: 'int' }) score!: number;
  @Column({ type: 'varchar' }) level!: ThreatLevel;
  @Column({ type: 'jsonb', default: [] }) reasons!: string[];
  @Column({ type: 'varchar', nullable: true }) fixVersion!: string | null;
  @Column({ type: 'varchar', default: 'open' }) status!: 'open' | 'resolved';
  /** highest level we already sent an alert for, so we only re-alert on escalation */
  @Column({ type: 'varchar', nullable: true }) alertedLevel!: ThreatLevel | null;
  @Column({ type: 'jsonb', default: [] }) scoreHistory!: { at: string; score: number }[];
  @CreateDateColumn() firstSeenAt!: Date;
  @UpdateDateColumn() updatedAt!: Date;
}
