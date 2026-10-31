import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.jsx';
import './styles.css';

// If anything ever throws while rendering, show a friendly recovery screen instead of a blank page.
class Boundary extends React.Component {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(err) { console.error(err); }
  render() {
    if (!this.state.failed) return this.props.children;
    return <div className="boundary"><h2>Something went wrong</h2><p>Your data is safe. Reload to continue.</p><button className="btn primary" onClick={() => { try { localStorage.removeItem('findit_token'); localStorage.removeItem('findit_user'); } catch {} location.reload(); }}>Reload CampusOS</button></div>;
  }
}
createRoot(document.getElementById('root')).render(<React.StrictMode><Boundary><App /></Boundary></React.StrictMode>);
