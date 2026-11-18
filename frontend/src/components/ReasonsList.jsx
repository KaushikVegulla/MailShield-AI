export default function ReasonsList({ verdict, ml }) {
  if (!verdict) return null
  return (
    <section className="card">
      <h2>Why this verdict</h2>
      {ml?.model_available && (
        <p className="muted">
          ML model: {ml.model_name} · phishing probability {Math.round(ml.phishing_probability * 100)}%
        </p>
      )}
      {verdict.reasons.length === 0 && (
        <p>No risk signals fired. Headers authenticate cleanly, links are clean, and no social-engineering language was detected.</p>
      )}
      <ul className="reasons">
        {verdict.reasons.map((reason, i) => (
          <li key={i}>
            <span className={`source source-${reason.source}`}>{reason.source}</span>
            <span>{reason.detail}</span>
            {reason.points ? <span className="points">+{reason.points}</span> : null}
          </li>
        ))}
      </ul>
    </section>
  )
}
