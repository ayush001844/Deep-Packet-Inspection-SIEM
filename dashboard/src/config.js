// API base URL — set VITE_API_BASE_URL in Vercel environment variables
// for production (e.g. https://your-backend.railway.app).
// Falls back to empty string (Vite dev proxy) for local development.
export const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

// WebSocket base — set VITE_WS_BASE_URL in Vercel for wss://your-backend
export const WS_BASE = import.meta.env.VITE_WS_BASE_URL
  || `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.hostname}:8000`;
