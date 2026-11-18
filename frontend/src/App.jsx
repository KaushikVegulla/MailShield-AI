import { useEffect, useRef, useState } from 'react'
import { API_BASE, analyzeFile, analyzeRaw, checkHealth, downloadReportFile, downloadReportRaw, loadSample } from './api.js'
import VerdictCard from './components/VerdictCard.jsx'
import HeaderTable from './components/HeaderTable.jsx'
import UrlTable from './components/UrlTable.jsx'
import ReasonsList from './components/ReasonsList.jsx'

const SAMPLES = [
  { file: 'phishing_paypal.eml', label: 'Sample: PayPal phishing' },
  { file: 'phishing_bank.eml', label: 'Sample: Bank KYC phishing' },
  { file: 'legit_college.eml', label: 'Sample: CUTM exam mail (legit)' },
  { file: 'legit_newsletter.eml', label: 'Sample: GitHub digest (legit)' },
]

function saveBlob(blob, name) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  URL.revokeObjectURL(url)
}

export default function App() {
  const [raw, setRaw] = useState('')
  const [file, setFile] = useState(null)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [healthy, setHealthy] = useState(null)
  const [elapsed, setElapsed] = useState(null)
  const fileRef = useRef(null)

  useEffect(() => {
    checkHealth().then(setHealthy)
  }, [])

  async function runAnalyze() {
    setBusy(true)
    setError(null)
    const started = performance.now()
    try {
      const data = file ? await analyzeFile(file) : await analyzeRaw(raw)
      setElapsed(Math.round(performance.now() - started))
      setResult(data)
      setHistory((prev) => [
        {
          subject: data.parsed.subject || '(no subject)',
          score: data.verdict.score,
          verdict: data.verdict.verdict,
          data,
        },
        ...prev,
      ].slice(0, 8))
    } catch (err) {
      setError(err.message || 'Analysis failed — is the backend running?')
    } finally {
      setBusy(false)
    }
  }

  async function runReport() {
    setBusy(true)
    setError(null)
    try {
      const blob = file ? await downloadReportFile(file) : await downloadReportRaw(raw)
      saveBlob(blob, 'mailshield-forensic-report.pdf')
    } catch (err) {
      setError(err.message || 'Report failed')
    } finally {
      setBusy(false)
    }
  }

  async function pickSample(name) {
    setError(null)
    setFile(null)
    if (fileRef.current) fileRef.current.value = ''
    try {
      setRaw(await loadSample(name))
    } catch {
      setError('Could not load the sample file.')
    }
  }

  const parsed = result?.parsed

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">🛡 MailShield AI</div>
        <div className="topbar-right">
          <span className="muted api-url">{API_BASE}</span>
          <span className={`pill ${healthy === null ? '' : healthy ? 'pill-live' : 'pill-down'}`}>
            {healthy === null ? 'checking…' : healthy ? '● LIVE' : '● backend offline'}
          </span>
        </div>
      </header>

      <main className="layout">
        <section className="card input-panel">
          <h2>Analyse an email</h2>
          <div className="sample-row">
            {SAMPLES.map((s) => (
              <button key={s.file} className="btn btn-ghost" onClick={() => pickSample(s.file)}>{s.label}</button>
            ))}
          </div>
          <textarea
            value={raw}
            onChange={(e) => { setRaw(e.target.value); setFile(null) }}
            placeholder="Paste the full raw email here (headers + body), or upload a .eml file below…"
            rows={16}
          />
          <label className="file-label">
            Or upload a .eml file
            <input
              ref={fileRef}
              type="file"
              accept=".eml,message/rfc822"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
            />
          </label>
          {file && <div className="muted">Selected file: {file.name} (this will be analysed instead of the pasted text)</div>}
          <div className="actions">
            <button className="btn btn-primary" disabled={busy || (!raw.trim() && !file)} onClick={runAnalyze}>
              {busy ? 'Analysing…' : 'Analyse email'}
            </button>
            <button className="btn" disabled={busy || (!raw.trim() && !file)} onClick={runReport}>
              Download forensic PDF
            </button>
          </div>
          {elapsed !== null && result && <div className="muted">Analysed in {elapsed} ms</div>}
          {error && <div className="error">{error}</div>}

          {history.length > 0 && (
            <div className="history">
              <h3>Recent analyses</h3>
              {history.map((item, i) => (
                <button key={i} className="history-item" onClick={() => setResult(item.data)}>
                  <span className={`dot dot-${item.verdict}`} />
                  <span className="history-subject">{item.subject}</span>
                  <span className="points">{item.score}</span>
                </button>
              ))}
            </div>
          )}
        </section>

        <div className="results">
          {!result && (
            <section className="card empty">
              <p>Load a sample or paste an email, then hit <b>Analyse email</b>.</p>
              <p className="muted">You will get a hybrid verdict (rules .50 / ML .35 / anomaly .15) with header forensics, URL evidence and every reason listed.</p>
            </section>
          )}
          {result && (
            <>
              <VerdictCard verdict={result.verdict} />
              <section className="card">
                <h2>Email</h2>
                <table className="table">
                  <tbody>
                    <tr><td className="mono">Subject</td><td>{parsed.subject || '-'}</td></tr>
                    <tr><td className="mono">From</td><td>{parsed.from?.raw || '-'}</td></tr>
                    <tr><td className="mono">Reply-To</td><td>{parsed.reply_to?.raw || '-'}</td></tr>
                    <tr><td className="mono">Date</td><td>{parsed.date || '-'}</td></tr>
                    <tr><td className="mono">Attachments</td><td>{parsed.attachments?.length ? parsed.attachments.map((a) => a.filename).join(', ') : 'none'}</td></tr>
                  </tbody>
                </table>
              </section>
              <ReasonsList verdict={result.verdict} ml={result.ml_prediction} />
              <HeaderTable forensics={result.header_forensics} parsed={parsed} />
              <UrlTable urlAnalysis={result.url_analysis} />
            </>
          )}
        </div>
      </main>

      <footer className="footer muted">
        MailShield AI · SIH26106 — AI-Powered Email Threat Detection and Forensic Analysis System · FastAPI + React
      </footer>
    </div>
  )
}
