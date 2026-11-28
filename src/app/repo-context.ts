import { detectPlatform } from '../core/platform';
import { RepoContext } from '../core/types';
import { RepositoryEntity } from './entities';

/** What the scorer knows about a repo: name, exposure, and the OS it is deployed on. */
export function repoContext(repo: RepositoryEntity): RepoContext {
  const detected = repo.platform ? { platform: repo.platform, source: 'argus.config.json' } : detectPlatform(repo.path);
  return {
    name: repo.name,
    internetFacing: repo.internetFacing,
    platform: detected?.platform,
    platformSource: detected?.source,
  };
}
