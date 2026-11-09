const API_BASE = '/api/v1';

export async function scanTarget(url, consent) {
  const response = await fetch(`${API_BASE}/scan`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ url, consent }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Scan failed with status ${response.status}`);
  }

  return response.json();
}

export async function fetchReports() {
  const response = await fetch(`${API_BASE}/reports`);
  if (!response.ok) {
    throw new Error('Failed to fetch scan history');
  }
  return response.json();
}

export async function fetchReportById(id) {
  const response = await fetch(`${API_BASE}/reports/${id}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch report #${id}`);
  }
  return response.json();
}
