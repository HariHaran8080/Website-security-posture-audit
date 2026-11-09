import React, { useState, useEffect } from 'react';
import { Globe, Lock, ShieldCheck, Server, AlertCircle, ArrowRight, Terminal, Radio } from 'lucide-react';

const SCAN_STEPS = [
  "Initializing target connection & handshake...",
  "Evaluating HTTP security headers (CSP, HSTS, XFO)...",
  "Validating TLS certificate validity & cipher protocols...",
  "Inspecting cookie flags (HttpOnly, Secure, SameSite)...",
  "Probing exposed paths & checking CORS misconfigurations...",
  "Scanning perimeter network ports & service banners...",
  "Calculating OWASP Top 10 mappings & letter grade..."
];

export default function AuditForm({ onStartScan, isLoading, openConsentModal, consentGiven, setConsentGiven }) {
  const [url, setUrl] = useState('');
  const [validationError, setValidationError] = useState('');
  const [activeStepIndex, setActiveStepIndex] = useState(0);

  useEffect(() => {
    let interval;
    if (isLoading) {
      setActiveStepIndex(0);
      interval = setInterval(() => {
        setActiveStepIndex(prev => (prev + 1) % SCAN_STEPS.length);
      }, 1400);
    }
    return () => clearInterval(interval);
  }, [isLoading]);

  const handleSubmit = (e) => {
    e.preventDefault();
    setValidationError('');

    let trimmed = url.trim();
    if (!trimmed) {
      setValidationError('Please enter a target domain or URL.');
      return;
    }

    if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
      trimmed = 'https://' + trimmed;
    }

    if (!consentGiven) {
      setValidationError('Authorization required: Confirm you have permission to audit this target.');
      return;
    }

    onStartScan(trimmed, consentGiven);
  };

  const handlePreset = (presetUrl) => {
    setUrl(presetUrl);
    setValidationError('');
  };

  if (isLoading) {
    return (
      <div className="cyber-card radar-scanner-box" style={{ maxWidth: '640px', margin: '4rem auto' }}>
        <div className="radar-circle">
          <div className="radar-sweep" />
          <div className="radar-ping" />
          <Radio size={28} color="#00f2fe" />
        </div>

        <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.4rem', color: '#fff' }}>
          Auditing Website Security Posture
        </h3>
        <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--cyber-cyan)', marginBottom: '1.5rem' }}>
          Target: {url}
        </p>

        <div style={{
          background: 'rgba(6, 9, 17, 0.8)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '10px',
          padding: '0.85rem 1.25rem',
          width: '100%',
          maxWidth: '480px',
          textAlign: 'left'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
            <Terminal size={14} color="#38bdf8" />
            <span style={{ fontSize: '0.725rem', fontFamily: 'var(--font-mono)', color: 'var(--text-subtle)', textTransform: 'uppercase' }}>
              TELEMETRY LOG
            </span>
          </div>
          <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.825rem', color: '#cbd5e1' }}>
            &gt; {SCAN_STEPS[activeStepIndex]}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: '780px', margin: '0 auto', padding: '1rem 0 3rem' }}>
      <div className="hero-header">
        <div className="hero-pill">
          <Lock size={12} />
          <span>PASSIVE SECURITY RECONNAISSANCE</span>
        </div>
        <h2 className="hero-title">
          Website Security Posture Auditor
        </h2>
        <p className="hero-subtitle">
          Verify defensive HTTP configurations, TLS handshakes, cookie attributes, 
          sensitive path exposures, and perimeter ports mapped against OWASP Top 10.
        </p>
      </div>

      <div className="cyber-card" style={{ padding: '2rem' }}>
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '1.25rem' }}>
            <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.5rem' }}>
              Target Website Domain or URL
            </label>
            
            <div className="command-bar" style={{ borderColor: validationError ? '#f43f5e' : undefined }}>
              <Globe size={18} color="var(--text-subtle)" style={{ marginLeft: '0.25rem' }} />
              <input
                type="text"
                className="command-input"
                placeholder="e.g. https://yourdomain.com or http://localhost:3000"
                value={url}
                onChange={(e) => {
                  setUrl(e.target.value);
                  setValidationError('');
                }}
                disabled={isLoading}
              />
              <button 
                type="submit" 
                className="btn btn-cyber-primary"
                disabled={!consentGiven}
                style={{ padding: '0.55rem 1.15rem' }}
              >
                <span>Audit Target</span>
                <ArrowRight size={15} />
              </button>
            </div>

            {validationError && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: '#f87171', fontSize: '0.8rem', marginTop: '0.5rem' }}>
                <AlertCircle size={14} />
                <span>{validationError}</span>
              </div>
            )}
          </div>

          {/* Quick Target Presets */}
          <div className="preset-group">
            <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-subtle)' }}>
              QUICK TARGETS:
            </span>
            <button
              type="button"
              className="preset-chip"
              onClick={() => handlePreset('http://localhost:3000')}
            >
              <Server size={12} style={{ display: 'inline', marginRight: '5px' }} />
              OWASP Juice Shop (localhost:3000)
            </button>
            <button
              type="button"
              className="preset-chip"
              onClick={() => handlePreset('https://example.com')}
            >
              example.com
            </button>
          </div>

          {/* Legal / Ethical Consent Guard */}
          <div className="consent-container">
            <input
              type="checkbox"
              id="consent-check"
              className="custom-checkbox"
              checked={consentGiven}
              onChange={(e) => setConsentGiven(e.target.checked)}
            />
            <label htmlFor="consent-check" style={{ fontSize: '0.85rem', color: '#cbd5e1', cursor: 'pointer', lineHeight: '1.45' }}>
              <strong style={{ color: '#fff' }}>Authorization Confirmation:</strong> I certify that I own this target infrastructure 
              or hold explicit written authorization from the owner to conduct defensive security posture assessments.{' '}
              <button
                type="button"
                onClick={openConsentModal}
                style={{ background: 'none', border: 'none', color: 'var(--cyber-cyan)', cursor: 'pointer', textDecoration: 'underline', fontSize: '0.85rem', padding: 0 }}
              >
                View Ethical Policy
              </button>
            </label>
          </div>
        </form>
      </div>
    </div>
  );
}
