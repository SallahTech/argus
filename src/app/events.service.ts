import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Observable, Subject } from 'rxjs';
import { Repository } from 'typeorm';
import { EventEntity } from './entities';

@Injectable()
export class EventsService {
  private readonly stream = new Subject<EventEntity>();

  constructor(@InjectRepository(EventEntity) private readonly events: Repository<EventEntity>) {}

  async emit(e: Omit<Partial<EventEntity>, 'id' | 'at'> & Pick<EventEntity, 'type' | 'message'>): Promise<EventEntity> {
    const saved = await this.events.save(
      this.events.create({ level: null, repoName: null, packageKey: null, vulnId: null, ...e }),
    );
    this.stream.next(saved);
    return saved;
  }

  live(): Observable<EventEntity> {
    return this.stream.asObservable();
  }

  recent(limit = 60): Promise<EventEntity[]> {
    return this.events.find({ order: { id: 'DESC' }, take: limit });
  }

  forNumber(repoName: string, packageKey: string): Promise<EventEntity[]> {
    return this.events.find({ where: { repoName, packageKey }, order: { id: 'ASC' } });
  }
}
