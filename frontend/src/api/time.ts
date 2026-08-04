const explicitTimezone = /(?:Z|[+-]\d{2}:?\d{2})$/i

// SQLite datetime('now') values are UTC but do not carry a timezone suffix.
// Treat those values as UTC while preserving timestamps that already include
// an explicit offset.
export function parseServerTimestamp(value: string): number {
  const normalized = value.trim().replace(' ', 'T')
  return Date.parse(explicitTimezone.test(normalized) ? normalized : `${normalized}Z`)
}

export function serverTimestampAgeMs(value: string, now = Date.now()): number | null {
  const timestamp = parseServerTimestamp(value)
  return Number.isNaN(timestamp) ? null : Math.max(0, now - timestamp)
}
