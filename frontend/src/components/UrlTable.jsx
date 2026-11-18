export default function UrlTable({ urlAnalysis }) {
  if (!urlAnalysis) return null
  return (
    <section className="card">
      <h2>URL analysis <span className="muted">({urlAnalysis.suspicious_count} of {urlAnalysis.url_count} suspicious)</span></h2>
      {urlAnalysis.urls.length === 0 && <p className="muted">No URLs found in this email.</p>}
      {urlAnalysis.urls.map((url) => (
        <div key={url.url} className={`url-row ${url.suspicious ? 'url-bad' : 'url-ok'}`}>
          <div className="url-head">
            <span className="mono url-text">{url.url}</span>
            <span className="points">{url.points ? `${url.points} pts` : 'clean'}</span>
          </div>
          {url.display_text && <div className="muted">Shown as: {url.display_text}</div>}
          {url.flags.map((flag) => (
            <div key={flag.name} className="flag-line">
              <span className={`status status-${flag.status}`}>{flag.name}</span> {flag.detail}
            </div>
          ))}
        </div>
      ))}
    </section>
  )
}
