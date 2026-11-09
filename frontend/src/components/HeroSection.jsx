import React, { useState } from 'react';

export default function HeroSection({ onStartScan, isLoading, consentGiven, setConsentGiven }) {
  const [url, setUrl] = useState('');
  const [validationError, setValidationError] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    setValidationError('');

    let trimmed = url.trim();
    if (!trimmed) {
      setValidationError('Please enter a target URL or domain.');
      return;
    }

    if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
      trimmed = 'https://' + trimmed;
    }

    if (!consentGiven) {
      setValidationError('You must confirm ownership or authorized permission before auditing.');
      return;
    }

    onStartScan(trimmed, consentGiven);
  };

  const handleJuiceShopClick = () => {
    setUrl('http://localhost:3000');
    setValidationError('');
  };

  return (
    <section id="scan-form-section" className="py-12 md:py-16">
      <div className="content-wrapper">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-14 items-start">
          
          {/* Left Column: Eyebrow, H1, description, scan form */}
          <div className="lg:col-span-7">
            {/* Small mono uppercase eyebrow */}
            <div className="font-mono text-xs uppercase tracking-widest text-subtle mb-3">
              Website security posture audit
            </div>

            {/* H1 with 7px amber underline under "attacker" */}
            <h1 className="font-heading font-semibold text-ink text-[clamp(40px,5.2vw,60px)] leading-[1.08] tracking-tight mb-5">
              See your website the way an{' '}
              <span className="amber-underline">attacker</span> does.
            </h1>

            {/* Intro paragraph */}
            <p className="text-muted text-[17px] leading-[1.6] mb-8 max-w-xl">
              Enter a site you own. WASP audits its security headers, TLS, cookies, exposed files, 
              CORS policy and open ports, then grades the result from A to F with the exact fix for every issue.
            </p>

            {/* The Scan Form */}
            <form onSubmit={handleSubmit} className="mb-6">
              <label 
                htmlFor="target-url-input" 
                className="block text-sm font-medium text-ink mb-2"
              >
                Website URL or domain to audit
              </label>

              <div className="flex flex-col sm:flex-row gap-3">
                <input
                  id="target-url-input"
                  type="text"
                  placeholder="https://example.com"
                  value={url}
                  onChange={(e) => {
                    setUrl(e.target.value);
                    setValidationError('');
                  }}
                  disabled={isLoading}
                  className="flex-1 bg-surface border-[1.5px] border-ink h-[52px] px-4 font-mono text-[15px] text-ink placeholder:text-subtle rounded-none"
                />

                <button
                  type="submit"
                  disabled={!consentGiven || isLoading}
                  className={`h-[52px] px-7 font-sans font-semibold text-ink bg-accent transition-all duration-150 min-h-[44px] flex items-center justify-center whitespace-nowrap rounded-none ${
                    !consentGiven || isLoading
                      ? 'opacity-45 cursor-not-allowed'
                      : 'hover:bg-[#e0a400] cursor-pointer'
                  }`}
                >
                  {isLoading ? 'Auditing...' : 'Audit this site'}
                </button>
              </div>

              {validationError && (
                <p className="text-critical text-sm font-medium mt-2" role="alert">
                  {validationError}
                </p>
              )}

              {/* Consent Checkbox */}
              <div className="mt-4 flex items-start gap-3">
                <input
                  id="consent-checkbox"
                  type="checkbox"
                  checked={consentGiven}
                  onChange={(e) => setConsentGiven(e.target.checked)}
                  disabled={isLoading}
                  className="mt-1 h-4 w-4 rounded-none border-[1.5px] border-ink text-ink accent-ink cursor-pointer"
                />
                <label 
                  htmlFor="consent-checkbox" 
                  className="text-sm text-ink leading-snug cursor-pointer select-none"
                >
                  I own this website, or I have written permission from its owner to test it.
                </label>
              </div>

              {/* Helper text linking to ethics */}
              <p className="text-xs text-subtle mt-2">
                The scan stays locked until you confirm.{' '}
                <a 
                  href="#ethical-use" 
                  className="text-ink underline hover:text-muted"
                >
                  Read the ethical use policy.
                </a>
              </p>
            </form>

            {/* Note and Quick Presets */}
            <div className="pt-4 border-t border-line text-sm text-subtle flex flex-wrap items-center gap-2">
              <span>Quick sample targets:</span>
              <button
                type="button"
                onClick={() => { setUrl('https://example.com'); setValidationError(''); }}
                className="font-mono text-xs text-ink bg-paper px-2 py-1 border border-line hover:border-ink cursor-pointer"
              >
                https://example.com
              </button>
              <button
                type="button"
                onClick={() => { setUrl('http://testphp.vulnweb.com'); setValidationError(''); }}
                className="font-mono text-xs text-ink bg-paper px-2 py-1 border border-line hover:border-ink cursor-pointer"
              >
                http://testphp.vulnweb.com
              </button>
            </div>
          </div>

          {/* Right Column: Sample Report Card */}
          <div className="lg:col-span-5" id="sample-report">
            <div className="bg-surface border border-line rounded-[16px] shadow-sm p-6 sm:p-7">
              {/* Header: Target + Sample data label */}
              <div className="flex items-center justify-between pb-4 border-b border-line mb-6">
                <div>
                  <div className="text-xs font-mono text-subtle uppercase tracking-wider">
                    Target
                  </div>
                  <div className="font-mono font-medium text-ink text-sm sm:text-base">
                    demo-shop.example
                  </div>
                </div>
                <div className="text-xs font-mono px-2 py-1 bg-paper text-subtle border border-line">
                  Sample data
                </div>
              </div>

              {/* Ink Square + Score */}
              <div className="flex items-center gap-5 mb-6">
                <div className="w-[108px] h-[108px] bg-ink flex flex-col items-center justify-center flex-shrink-0 text-surface">
                  <span className="font-heading font-bold text-4xl leading-none text-surface">
                    C
                  </span>
                  <span className="text-[11px] font-mono text-line uppercase mt-1">
                    Grade
                  </span>
                </div>

                <div>
                  <div className="font-heading font-bold text-2xl text-ink leading-tight">
                    62 / 100
                  </div>
                  <div className="text-sm text-muted mt-1">
                    8 findings across 6 checks
                  </div>
                  <div className="text-xs font-mono text-subtle mt-1">
                    Defensive baseline needs remediation
                  </div>
                </div>
              </div>

              {/* Segmented Severity Bar with Legend */}
              <div className="mb-6">
                <div className="h-3 w-full flex gap-[2px] bg-paper p-[2px] border border-line mb-2.5">
                  <div style={{ width: '12.5%' }} className="bg-critical" title="1 Critical" />
                  <div style={{ width: '25%' }} className="bg-high" title="2 High" />
                  <div style={{ width: '37.5%' }} className="bg-medium" title="3 Medium" />
                  <div style={{ width: '25%' }} className="bg-low" title="2 Low" />
                </div>

                <div className="flex flex-wrap items-center justify-between text-xs font-mono text-muted gap-y-1">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 bg-critical inline-block" />
                    <span>Critical 1</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 bg-high inline-block" />
                    <span>High 2</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 bg-medium inline-block" />
                    <span>Medium 3</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 bg-low inline-block" />
                    <span>Low 2</span>
                  </div>
                </div>
              </div>

              {/* Four finding rows */}
              <div className="space-y-3 mb-5">
                {/* Row 1 */}
                <div className="py-2 border-b border-line flex items-center justify-between gap-3 text-sm">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className="chip chip-critical flex-shrink-0">Critical</span>
                    <span className="text-ink font-medium truncate">/.env file publicly accessible</span>
                  </div>
                  <span className="text-xs font-mono text-subtle flex-shrink-0">A05:2021</span>
                </div>

                {/* Row 2 */}
                <div className="py-2 border-b border-line flex items-center justify-between gap-3 text-sm">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className="chip chip-high flex-shrink-0">High</span>
                    <span className="text-ink font-medium truncate">Strict-Transport-Security missing</span>
                  </div>
                  <span className="text-xs font-mono text-subtle flex-shrink-0">A02:2021</span>
                </div>

                {/* Row 3 */}
                <div className="py-2 border-b border-line flex items-center justify-between gap-3 text-sm">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className="chip chip-medium flex-shrink-0">Medium</span>
                    <span className="text-ink font-medium truncate">Session cookie lacks HttpOnly flag</span>
                  </div>
                  <span className="text-xs font-mono text-subtle flex-shrink-0">A07:2021</span>
                </div>

                {/* Row 4 */}
                <div className="py-2 flex items-center justify-between gap-3 text-sm">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className="chip chip-low flex-shrink-0">Low</span>
                    <span className="text-ink font-medium truncate">Referrer-Policy header omitted</span>
                  </div>
                  <span className="text-xs font-mono text-subtle flex-shrink-0">A05:2021</span>
                </div>
              </div>

              {/* Footer Line */}
              <div className="text-xs text-subtle border-t border-line pt-3 font-mono">
                Showing the top 4 of 8 findings, ordered by severity.
              </div>
            </div>
          </div>

        </div>
      </div>
    </section>
  );
}

