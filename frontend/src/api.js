const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export { API_BASE }

export async function checkHealth() {
  try {
    const res = await fetch(`${API_BASE}/health`)
    if (!res.ok) return false
    const data = await res.json()
    return data.status === 'ok'
  } catch {
    return false
  }
}

export async function analyzeRaw(raw) {
  const res = await fetch(`${API_BASE}/analyze/email`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ raw }),
  })
  if (!res.ok) throw new Error(`Analysis failed (${res.status})`)
  return res.json()
}

export async function analyzeFile(file) {
  const form = new FormData()
  form.append('file', file)
  const res = await fetch(`${API_BASE}/analyze/eml`, { method: 'POST', body: form })
  if (!res.ok) throw new Error(`Analysis failed (${res.status})`)
  return res.json()
}

export async function downloadReportRaw(raw) {
  const res = await fetch(`${API_BASE}/report/email`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ raw }),
  })
  if (!res.ok) throw new Error(`Report failed (${res.status})`)
  return res.blob()
}

export async function downloadReportFile(file) {
  const form = new FormData()
  form.append('file', file)
  const res = await fetch(`${API_BASE}/report/eml`, { method: 'POST', body: form })
  if (!res.ok) throw new Error(`Report failed (${res.status})`)
  return res.blob()
}

export async function loadSample(name) {
  const res = await fetch(`/samples/${name}`)
  if (!res.ok) throw new Error(`Sample not found (${res.status})`)
  return res.text()
}
