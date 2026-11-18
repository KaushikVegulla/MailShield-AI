const LABELS = {
  phishing: 'PHISHING',
  suspicious: 'SUSPICIOUS',
  likely_legitimate: 'LIKELY LEGITIMATE',
}

export default function VerdictCard({ verdict }) {
  if (!verdict) return null
  const { score, verdict: kind, components, weights_used } = verdict
  const rows = [
    ['Rules (headers + URLs)', components.rules],
    ['ML classifier', components.ml],
    ['Anomaly signals', components.anomaly],
  ]
  return (
    <section className={`card verdict verdict-${kind}`}>
      <div className="verdict-main">
        <div className="verdict-score">{score}</div>
        <div>
          <div className="verdict-label">{LABELS[kind] || kind}</div>
          <div className="verdict-sub">Risk score / 100 · hybrid rules .50 / ML .35 / anomaly .15</div>
          {verdict.rule_floor_applied && (
            <div className="verdict-sub">Safety floor applied: rule evidence alone was overwhelming.</div>
          )}
        </div>
      </div>
      <div className="component-bars">
        {rows.map(([label, comp]) => (
          <div key={label} className="component-row">
            <span className="component-name">{label}</span>
            <div className="bar">
              <div
                className="bar-fill"
                style={{ width: `${comp.score ?? 0}%` }}
                title={comp.score === null ? 'unavailable' : String(comp.score)}
              />
            </div>
            <span className="component-value">
              {comp.score === null ? 'n/a' : comp.score}
              <span className="component-weight"> ×{(weights_used?.[label.startsWith('Rules') ? 'rules' : label.startsWith('ML') ? 'ml' : 'anomaly'] ?? comp.weight)}</span>
            </span>
          </div>
        ))}
      </div>
      {components.ml?.score === null && (
        <p className="note">ML model not loaded on this backend — score computed from rules and anomaly, weights renormalised.</p>
      )}
    </section>
  )
}
