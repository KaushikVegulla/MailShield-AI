export default function HeaderTable({ forensics, parsed }) {
  if (!forensics) return null
  return (
    <section className="card">
      <h2>Header forensics</h2>
      <div className="auth-row">
        <span className={`chip chip-${forensics.auth.spf === 'pass' ? 'pass' : 'fail'}`}>SPF: {forensics.auth.spf}</span>
        <span className={`chip chip-${forensics.auth.dkim === 'pass' ? 'pass' : 'fail'}`}>DKIM: {forensics.auth.dkim}</span>
        <span className={`chip chip-${forensics.auth.dmarc === 'pass' ? 'pass' : 'fail'}`}>DMARC: {forensics.auth.dmarc}</span>
        {forensics.spoofed_sender_suspected && <span className="chip chip-fail">Spoofed sender suspected</span>}
        {parsed?.originating_ip && <span className="chip">Origin IP: {parsed.originating_ip}</span>}
      </div>
      <table className="table">
        <tbody>
          {forensics.checks.map((check) => (
            <tr key={check.name}>
              <td className="mono">{check.name}</td>
              <td><span className={`status status-${check.status}`}>{check.status}</span></td>
              <td>{check.detail}</td>
              <td className="points">{check.points ? `+${check.points}` : ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}
