/** Shared, locale-aware formatting helpers. */

const DATE_TIME = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
});

/** Format an ISO timestamp as a readable local date-time, tolerant of bad input. */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : DATE_TIME.format(date);
}

/** Short id suffix for compact display, e.g. the last segment of a UUID. */
export function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}
