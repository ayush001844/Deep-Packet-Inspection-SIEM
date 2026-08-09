export default function StatCard({ title, value, change, icon: Icon, color = "var(--accent)", bg = "var(--accent-glow)", className = "" }) {
  return (
    <div className={`stat-card ${className}`} style={{ '--stat-accent': color, '--stat-accent-bg': bg }}>
      <div className="stat-card-label">{title}</div>
      <div className="stat-card-value count-in">{value}</div>
      {change && (
        <div className="stat-card-change">
          {change}
        </div>
      )}
      {Icon && (
        <div className="stat-card-icon fade-in">
          <Icon size={20} />
        </div>
      )}
    </div>
  );
}
