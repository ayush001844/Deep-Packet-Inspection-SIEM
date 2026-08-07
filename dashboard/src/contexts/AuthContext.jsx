import React, { createContext, useContext, useState, useEffect } from 'react';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check for saved token
    const token = localStorage.getItem('token');
    const username = localStorage.getItem('username');
    const role = localStorage.getItem('role');
    if (token && username) {
      setUser({ token, username, role: role || 'analyst' });
    }
    setLoading(false);
  }, []);

  const login = async (username, password) => {
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: 'Invalid credentials' }));
        throw new Error(err.detail || 'Invalid credentials');
      }

      const data = await res.json();
      localStorage.setItem('token', data.access_token);
      localStorage.setItem('username', data.username);
      localStorage.setItem('role', data.role || 'analyst');
      setUser({ token: data.access_token, username: data.username, role: data.role || 'analyst' });
      return { success: true };
    } catch (err) {
      return { success: false, error: err.message };
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    localStorage.removeItem('role');
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {!loading && children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
