import { useState, useEffect, useCallback, useRef } from 'react';

// Use relative paths so Vite proxy forwards to backend (port 8000)
const API_BASE = '';
const WS_BASE = `ws://${window.location.hostname}:8000`;

/* ── Auth helpers ───────────────────────────────────────────── */
function getAuthHeaders() {
  const token = localStorage.getItem('token');
  const headers = { 'Content-Type': 'application/json' };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

function handle401(res) {
  if (res.status === 401) {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    localStorage.removeItem('role');
    window.location.href = '/';
  }
}

/* ── REST API Hook ───────────────────────────────────────────── */
export function useApi(endpoint, options = {}) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const { interval = 0, enabled = true } = options;

  const fetchData = useCallback(async () => {
    if (!enabled) return;
    try {
      const res = await fetch(`${API_BASE}${endpoint}`, {
        headers: getAuthHeaders(),
      });
      handle401(res);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      setData(json);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [endpoint, enabled]);

  useEffect(() => {
    fetchData();
    if (interval > 0) {
      const id = setInterval(fetchData, interval);
      return () => clearInterval(id);
    }
  }, [fetchData, interval]);

  return { data, loading, error, refetch: fetchData };
}

export async function apiPost(endpoint, body = {}) {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(body),
  });
  handle401(res);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

export async function apiUpload(endpoint, file) {
  const token = localStorage.getItem('token');
  const headers = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  const form = new FormData();
  form.append('file', file);
  const res = await fetch(`${API_BASE}${endpoint}`, {
    method: 'POST',
    headers,
    body: form,
  });
  handle401(res);
  return res.json();
}

/* ── WebSocket Hook ──────────────────────────────────────────── */
export function useWebSocket(path = '/ws/packets') {
  const [packets, setPackets] = useState([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);
  const maxPackets = 500;

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const ws = new WebSocket(`${WS_BASE}${path}`);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => {
      setConnected(false);
      // Auto-reconnect after 3 seconds
      setTimeout(connect, 3000);
    };
    ws.onerror = () => ws.close();

    ws.onmessage = (event) => {
      try {
        const pkt = JSON.parse(event.data);
        setPackets(prev => {
          const next = [pkt, ...prev];
          return next.length > maxPackets ? next.slice(0, maxPackets) : next;
        });
      } catch {}
    };
  }, [path]);

  const disconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
  }, []);

  const clearPackets = useCallback(() => setPackets([]), []);

  useEffect(() => {
    return () => disconnect();
  }, [disconnect]);

  return { packets, connected, connect, disconnect, clearPackets };
}
