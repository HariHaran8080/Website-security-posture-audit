import React, { useEffect, useState } from 'react';

const CHECKS = [
  { id: 'headers', label: 'HTTP security headers (CSP, HSTS, XFO, XCTO)' },
  { id: 'tls', label: 'TLS certificate validity, expiry & protocol version' },
  { id: 'cookies', label: 'Cookie hygiene flags (Secure, HttpOnly, SameSite)' },
  { id: 'files', label: 'Sensitive file exposures (/.git, /.env, /backup.zip)' },
  { id: 'cors', label: 'CORS policy reflection & credential permissions' },
  { id: 'ports', label: 'Perimeter TCP port availability & service banners' },
];

export default function ScanningLoader({ targetUrl }) {
  const [activeStep, setActiveStep] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setActiveStep(prev => (prev < CHECKS.length - 1 ? prev + 1 : prev));
    }, 900);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="py-20">
      <div className="content-wrapper max-w-xl mx-auto">
        <div className="bg-surface border border-line p-8 sm:p-10 shadow-sm">
          {/* Top mono info */}
          <div className="font-mono text-xs uppercase tracking-wider text-subtle mb-2">
            Active Audit In Progress
          </div>
          
          <h2 className="font-heading font-semibold text-2xl text-ink mb-1 break-all">
            {targetUrl}
          </h2>
          <p className="text-sm text-muted mb-8">
            Running non-intrusive configuration checks and mapping findings to OWASP Top 10.
          </p>

          {/* Progress List */}
          <div className="space-y-4 border-t border-line pt-6">
            {CHECKS.map((check, idx) => {
              const isDone = idx < activeStep;
              const isCurrent = idx === activeStep;
              return (
                <div key={check.id} className="flex items-center gap-3.5 text-sm">
                  {/* Status Indicator */}
                  <div className="w-5 h-5 flex items-center justify-center flex-shrink-0 font-mono text-xs">
                    {isDone ? (
                      <span className="text-low font-bold">✓</span>
                    ) : isCurrent ? (
                      <span className="w-2.5 h-2.5 bg-accent inline-block animate-pulse" />
                    ) : (
                      <span className="w-2 h-2 bg-line inline-block" />
                    )}
                  </div>

                  <span className={`font-mono text-xs sm:text-sm ${
                    isDone ? 'text-ink' : isCurrent ? 'text-ink font-semibold' : 'text-subtle'
                  }`}>
                    {check.label}
                  </span>
                </div>
              );
            })}
          </div>

          <div className="mt-8 pt-4 border-t border-line text-xs font-mono text-subtle text-center">
            Rate-limited · Non-intrusive · Read-only
          </div>
        </div>
      </div>
    </div>
  );
}

