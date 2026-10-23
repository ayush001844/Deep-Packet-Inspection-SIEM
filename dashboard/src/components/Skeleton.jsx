import React from 'react';

/**
 * Primitive Skeleton component with animated shimmering gradient
 */
export function Skeleton({ width = '100%', height = '16px', borderRadius = 'var(--radius-sm)', className = '', style = {} }) {
  return (
    <div
      className={`skeleton-shimmer ${className}`}
      style={{
        width,
        height,
        borderRadius,
        ...style,
      }}
    />
  );
}

/**
 * Skeleton representation of a StatCard
 */
export function SkeletonCard() {
  return (
    <div className="stat-card skeleton-container">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <Skeleton width="45%" height="14px" />
        <Skeleton width="32px" height="32px" borderRadius="50%" />
      </div>
      <Skeleton width="65%" height="28px" style={{ marginBottom: 10 }} />
      <Skeleton width="40%" height="12px" />
    </div>
  );
}

/**
 * Skeleton representation of a Chart Card
 */
export function SkeletonChart({ height = 240, title = true }) {
  return (
    <div className="card skeleton-container" style={{ minHeight: height + 60 }}>
      {title && (
        <div className="card-header" style={{ marginBottom: 16 }}>
          <Skeleton width="35%" height="18px" />
          <Skeleton width="20%" height="14px" />
        </div>
      )}
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: '12px', height, padding: '16px 8px' }}>
        <Skeleton width="10%" height="40%" borderRadius="4px" />
        <Skeleton width="15%" height="65%" borderRadius="4px" />
        <Skeleton width="12%" height="85%" borderRadius="4px" />
        <Skeleton width="18%" height="50%" borderRadius="4px" />
        <Skeleton width="14%" height="90%" borderRadius="4px" />
        <Skeleton width="16%" height="70%" borderRadius="4px" />
        <Skeleton width="15%" height="60%" borderRadius="4px" />
      </div>
    </div>
  );
}

/**
 * Skeleton representation of a Table
 */
export function SkeletonTable({ rows = 5, cols = 5 }) {
  return (
    <div className="table-responsive skeleton-container">
      <table className="table">
        <thead>
          <tr>
            {Array.from({ length: cols }).map((_, i) => (
              <th key={i}>
                <Skeleton width="70%" height="14px" />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: rows }).map((_, r) => (
            <tr key={r}>
              {Array.from({ length: cols }).map((_, c) => (
                <td key={c}>
                  <Skeleton width={c === 0 ? '50%' : '80%'} height="14px" />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * Skeleton representation of a List/Feed
 */
export function SkeletonList({ items = 4 }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
      {Array.from({ length: items }).map((_, i) => (
        <div
          key={i}
          className="skeleton-container"
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '12px 14px',
            background: 'var(--bg-card)',
            border: '1px solid var(--border-default)',
            borderRadius: 'var(--radius-md)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', width: '70%' }}>
            <Skeleton width="28px" height="28px" borderRadius="6px" />
            <div style={{ width: '80%' }}>
              <Skeleton width="60%" height="14px" style={{ marginBottom: 6 }} />
              <Skeleton width="40%" height="11px" />
            </div>
          </div>
          <Skeleton width="60px" height="22px" borderRadius="12px" />
        </div>
      ))}
    </div>
  );
}

export default Skeleton;
