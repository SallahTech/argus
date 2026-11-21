# Argus

**A threat-intel machine for your dependencies.** Your audit tool tells you about 40 vulnerabilities. Argus tells you which one will actually hurt you, and why.

It correlates four signals that normally live in separate tools:

| Signal | Source | Question it answers |
|---|---|---|
| Severity | [OSV.dev](https://osv.dev) (GitHub + npm advisories) | How bad is it? |
| Exploited in the wild | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Is someone using it right now? |
| Exploit probability | [FIRST EPSS](https://www.first.org/epss/) | How likely is it in the next 30 days? |
| Exposure | your lockfile + your source code | Do you ship it, and do you even call it? |

```
score = 100 × severity × exploitability × exposure
```

- **CRITICAL** (70+): alert now
- **RELEVANT** (40–69): alert and schedule a fix
- **IRRELEVANT** (<40): tracked, but kept quiet

Malicious packages (OSV `MAL-` entries, i.e. supply-chain attacks) always score 100.
Every score comes with its reasons, so each alert explains itself.

## Quick start (CLI, no database)

```bash
npm install && npm run build
node dist/cli.js ../path/to/your-app --internet-facing
node dist/cli.js ../path/to/your-app --all     # include IRRELEVANT
node dist/cli.js ../path/to/your-app --json    # machine-readable
```

The CLI exits with code `1` when it finds something CRITICAL, so you can put it in CI.

## Always-on mode (API + scheduled scans + Telegram)

```bash
cp .env.example .env          # add TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID
mkdir repos && git clone <your-repo> repos/my-app
docker compose up -d

curl -X POST localhost:3000/repos -H 'content-type: application/json' \
  -d '{"name":"my-app","path":"/repos/my-app","internetFacing":true}'
curl -X POST localhost:3000/scan
curl localhost:3000/numbers
```

It rescans every 6 hours (`SCAN_CRON`). It alerts once when a finding first becomes RELEVANT or CRITICAL, and again only if it escalates. A finding marks itself resolved when it disappears (you upgraded). The score history for every finding is kept.

| Endpoint | |
|---|---|
| `POST /repos` | register a repo `{name, path, internetFacing}` |
| `GET /repos` | list watched repos |
| `POST /scan`, `POST /repos/:id/scan` | scan now |
| `GET /numbers?level=CRITICAL,RELEVANT\|all` | open findings, worst first |

## Layout

```
src/core/     pure engine, shared by the CLI and the API (no framework code)
  lockfile.ts      package-lock v2/v3 -> flat dependency list
  reachability.ts  which direct deps your source actually imports
  feeds.ts         OSV, CISA KEV and EPSS clients
  scoring.ts       the scoring model and its reasons
  pipeline.ts      inventory -> feeds -> enrich -> score
src/app/      NestJS: Postgres entities, cron scanner, Telegram alerts, REST API
test/         unit tests + a mocked end-to-end pipeline test
```

## Roadmap

- [x] Phase 1–3: inventory, vulnerability feeds, scoring, alerts
- [ ] **Chatter layer:** public PoC repos on GitHub, plus Hacker News, r/netsec and Mastodon infosec, triaged by an LLM. A spike bumps the score.
- [ ] **Time machine:** replay historical feeds to measure how many hours or days before KEV listing Argus would have raised each alert
- [ ] **Case files:** an LLM-written plain-English brief per finding, plus an auto-opened upgrade PR
- [ ] **GitHub Action:** comment the threat assessment on every PR
- [ ] **Dashboard:** live map of open numbers across repos (React + Ant Design)
- [ ] Function-level reachability (is the vulnerable *function* called, not just the package)
- [ ] pnpm / yarn lockfiles, BullMQ workers once there are many collectors
