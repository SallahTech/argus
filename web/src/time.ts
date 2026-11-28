/**
 * One time format everywhere: local time, 24h, ISO dates (2026-11-25 22:28).
 * The time zone is labelled once, in the header clock.
 */
const pad = (n: number) => String(n).padStart(2, '0');

/** e.g. "GMT+2" or "EET", whatever the browser calls the local zone */
export const tzLabel = (() => {
  try {
    return new Intl.DateTimeFormat(undefined, { timeZoneName: 'short' }).formatToParts(new Date()).find((p) => p.type === 'timeZoneName')?.value ?? 'local';
  } catch {
    return 'local';
  }
})();

export const fmtDate = (d: Date | string) => {
  const x = new Date(d);
  return `${x.getFullYear()}-${pad(x.getMonth() + 1)}-${pad(x.getDate())}`;
};
export const fmtTime = (d: Date | string, seconds = true) => {
  const x = new Date(d);
  return `${pad(x.getHours())}:${pad(x.getMinutes())}${seconds ? `:${pad(x.getSeconds())}` : ''}`;
};
export const fmtDateTime = (d: Date | string) => `${fmtDate(d)} ${fmtTime(d, false)}`;
