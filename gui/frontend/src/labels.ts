import type {report} from '../wailsjs/go/models'

/** Severity codes from most to least severe (same order as the backend). */
export const SEVERITIES = ['error', 'high', 'medium', 'low', 'info'] as const

export type LabelGroup = 'severity' | 'role' | 'level' | 'resolver_source' | 'text'

/** Display name of a backend code; falls back to the code itself. */
export function label(labels: report.Labels | null, group: LabelGroup, code: string | undefined): string {
  if (!code) return ''
  return labels?.[group]?.[code] ?? code
}

/** Last path element, for compact location display. */
export function baseName(path: string): string {
  const i = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'))
  return i >= 0 ? path.slice(i + 1) : path
}
