import { Injectable, Logger } from '@nestjs/common';
import { FindingEntity } from './entities';

@Injectable()
export class AlertService {
  private readonly log = new Logger('Alert');
  private readonly token = process.env.TELEGRAM_BOT_TOKEN;
  private readonly chatId = process.env.TELEGRAM_CHAT_ID;

  format(f: FindingEntity): string {
    const icon = f.level === 'CRITICAL' ? '🔴' : '🟡';
    return [
      `${icon} <b>${f.level}</b> · score ${f.score}`,
      `<b>${f.packageName}@${f.packageVersion}</b> in <code>${f.repository.name}</code>`,
      `${f.cveId ?? f.vulnId}: ${escape(f.summary)}`,
      `<i>why:</i> ${escape(f.reasons.join(' · '))}`,
      `<i>fix:</i> ${f.fixVersion ? `upgrade to ${f.fixVersion}` : 'no fix yet'}`,
      `https://osv.dev/vulnerability/${f.vulnId}`,
    ].join('\n');
  }

  async send(f: FindingEntity): Promise<void> {
    const text = this.format(f);
    if (!this.token || !this.chatId) {
      this.log.warn(`(telegram not configured)\n${text.replace(/<[^>]+>/g, '')}`);
      return;
    }
    const res = await fetch(`https://api.telegram.org/bot${this.token}/sendMessage`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ chat_id: this.chatId, text, parse_mode: 'HTML', disable_web_page_preview: true }),
    });
    if (!res.ok) this.log.error(`telegram ${res.status}: ${await res.text()}`);
  }
}

function escape(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
