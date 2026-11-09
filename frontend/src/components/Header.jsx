import React from 'react';

export default function Header({ currentView, setView }) {
  const scrollToScan = (e) => {
    e.preventDefault();
    if (currentView !== 'form') {
      setView('form');
      setTimeout(() => {
        const el = document.getElementById('scan-form-section');
        if (el) el.scrollIntoView({ behavior: 'smooth' });
      }, 50);
    } else {
      const el = document.getElementById('scan-form-section');
      if (el) el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleNavClick = (id) => (e) => {
    e.preventDefault();
    if (currentView !== 'form') {
      setView('form');
      setTimeout(() => {
        const el = document.getElementById(id);
        if (el) el.scrollIntoView({ behavior: 'smooth' });
      }, 50);
    } else {
      const el = document.getElementById(id);
      if (el) el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <header className="w-full bg-paper sticky top-0 z-50">
      {/* 6px stripe bar at the very top (ink 0-10px, amber 10-20px) */}
      <div className="stripe-bar-top" aria-hidden="true" />

      {/* Main Navigation Bar */}
      <div className="border-b border-line min-h-[72px] bg-paper">
        <div className="content-wrapper flex flex-wrap items-center justify-between gap-y-4 py-3 min-h-[72px]">
          {/* Left: Hexagon Logo + Brand */}
          <button
            type="button"
            onClick={() => setView('form')}
            className="flex items-center gap-3 text-left bg-transparent border-0 p-0 cursor-pointer"
          >
            {/* Inline SVG: Dark hexagon with three short horizontal amber stripes inside */}
            <svg
              width="36"
              height="36"
              viewBox="0 0 36 36"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
              className="flex-shrink-0"
              aria-hidden="true"
            >
              <polygon
                points="18,3 32,10.5 32,25.5 18,33 4,25.5 4,10.5"
                fill="#0F1720"
              />
              <rect x="11" y="12" width="14" height="2.5" fill="#F5B301" rx="0.5" />
              <rect x="11" y="17" width="14" height="2.5" fill="#F5B301" rx="0.5" />
              <rect x="11" y="22" width="14" height="2.5" fill="#F5B301" rx="0.5" />
            </svg>

            <div>
              <div className="font-heading font-bold text-xl leading-none text-ink tracking-tight">
                WASP
              </div>
              <div className="text-xs text-muted font-sans mt-0.5">
                Website Security Posture Auditor
              </div>
            </div>
          </button>

          {/* Right: Anchor links + Run audit button */}
          <nav aria-label="Main Navigation" className="flex flex-wrap items-center gap-x-6 gap-y-2">
            <a
              href="#checks"
              onClick={handleNavClick('checks')}
              className="min-h-[44px] flex items-center text-sm font-medium text-ink hover:underline transition-all"
            >
              Checks
            </a>
            <a
              href="#how-it-works"
              onClick={handleNavClick('how-it-works')}
              className="min-h-[44px] flex items-center text-sm font-medium text-ink hover:underline transition-all"
            >
              How it works
            </a>
            <a
              href="#sample-report"
              onClick={handleNavClick('sample-report')}
              className="min-h-[44px] flex items-center text-sm font-medium text-ink hover:underline transition-all"
            >
              Sample report
            </a>
            <a
              href="#ethical-use"
              onClick={handleNavClick('ethical-use')}
              className="min-h-[44px] flex items-center text-sm font-medium text-ink hover:underline transition-all"
            >
              Ethical use
            </a>

            {/* Link to reports history if available */}
            <button
              type="button"
              onClick={() => setView('history')}
              className={`min-h-[44px] flex items-center text-sm font-medium ${
                currentView === 'history' ? 'text-ink underline' : 'text-subtle hover:text-ink hover:underline'
              } transition-all`}
            >
              Past reports
            </button>

            {/* Solid ink button */}
            <button
              type="button"
              onClick={scrollToScan}
              className="min-h-[44px] px-5 py-2.5 bg-ink text-surface font-sans font-medium text-sm rounded hover:bg-muted transition-colors"
            >
              Run an audit
            </button>
          </nav>
        </div>
      </div>
    </header>
  );
}
