/**
 * Standardized Severity System for PacketAnalyzer-Pro
 * Defines uniform colors, badges, and labels across all views.
 */

export const SEVERITY_CONFIG = {
  critical: {
    level: 4,
    label: 'CRITICAL',
    color: '#ef4444',
    bg: 'rgba(239, 68, 68, 0.15)',
    border: 'rgba(239, 68, 68, 0.35)',
    glow: '0 0 12px rgba(239, 68, 68, 0.4)',
    badgeClass: 'badge-critical',
  },
  high: {
    level: 3,
    label: 'HIGH',
    color: '#f97316',
    bg: 'rgba(249, 115, 22, 0.15)',
    border: 'rgba(249, 115, 22, 0.35)',
    glow: '0 0 10px rgba(249, 115, 22, 0.35)',
    badgeClass: 'badge-high',
  },
  medium: {
    level: 2,
    label: 'MEDIUM',
    color: '#eab308',
    bg: 'rgba(234, 179, 8, 0.15)',
    border: 'rgba(234, 179, 8, 0.35)',
    glow: '0 0 8px rgba(234, 179, 8, 0.3)',
    badgeClass: 'badge-medium',
  },
  low: {
    level: 1,
    label: 'LOW',
    color: '#3b82f6',
    bg: 'rgba(59, 130, 246, 0.15)',
    border: 'rgba(59, 130, 246, 0.35)',
    glow: 'none',
    badgeClass: 'badge-low',
  },
  info: {
    level: 0,
    label: 'INFO',
    color: '#10b981',
    bg: 'rgba(16, 185, 129, 0.15)',
    border: 'rgba(16, 185, 129, 0.35)',
    glow: 'none',
    badgeClass: 'badge-info',
  },
};

/**
 * Normalize an arbitrary severity value (string, integer, or undefined) to canonical config
 */
export function normalizeSeverity(severity) {
  if (severity === undefined || severity === null) return SEVERITY_CONFIG.info;

  if (typeof severity === 'number') {
    if (severity >= 4) return SEVERITY_CONFIG.critical;
    if (severity === 3) return SEVERITY_CONFIG.high;
    if (severity === 2) return SEVERITY_CONFIG.medium;
    if (severity === 1) return SEVERITY_CONFIG.low;
    return SEVERITY_CONFIG.info;
  }

  const s = String(severity).toLowerCase().trim();
  if (s.includes('crit') || s === 'severe' || s === '4') return SEVERITY_CONFIG.critical;
  if (s.includes('high') || s === 'warn' || s === '3') return SEVERITY_CONFIG.high;
  if (s.includes('med') || s === 'warning' || s === '2') return SEVERITY_CONFIG.medium;
  if (s.includes('low') || s === 'notice' || s === '1') return SEVERITY_CONFIG.low;
  return SEVERITY_CONFIG.info;
}

/**
 * Returns JSX style badge object for styling
 */
export function getSeverityStyle(severity) {
  const cfg = normalizeSeverity(severity);
  return {
    color: cfg.color,
    backgroundColor: cfg.bg,
    border: `1px solid ${cfg.border}`,
  };
}
