import React, { useState } from 'react';

export default function HowItWorksSection() {
  const [copied, setCopied] = useState(false);
  const sampleSnippet = `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`;

  const handleCopy = () => {
    navigator.clipboard.writeText(sampleSnippet);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <>
      {/* 1) "How it works" on a white band with top and bottom borders */}
      <section id="how-it-works" className="py-24 bg-surface border-y border-line">
        <div className="content-wrapper">
          <div className="max-w-2xl mb-16">
            <div className="font-mono text-xs uppercase tracking-widest text-subtle mb-3">
              Process
            </div>
            <h2 className="font-heading font-semibold text-3xl sm:text-4xl text-ink tracking-tight mb-4">
              How it works
            </h2>
            <p className="text-muted text-[17px] leading-[1.6]">
              A three-step passive assessment pipeline built for rapid, reliable security feedback.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-12">
            {/* Column 1 */}
            <div>
              <div className="font-heading font-bold text-5xl text-ink leading-none mb-3">
                1
              </div>
              <div className="w-8 h-1 bg-accent mb-5" aria-hidden="true" />
              <h3 className="font-heading font-bold text-xl text-ink mb-2.5">
                Confirm you may scan
              </h3>
              <p className="text-muted text-[15px] leading-relaxed">
                The scanner refuses to run without explicit confirmation. Every audit requires certification 
                that you own the target infrastructure or hold written authorization.
              </p>
            </div>

            {/* Column 2 */}
            <div>
              <div className="font-heading font-bold text-5xl text-ink leading-none mb-3">
                2
              </div>
              <div className="w-8 h-1 bg-accent mb-5" aria-hidden="true" />
              <h3 className="font-heading font-bold text-xl text-ink mb-2.5">
                Run non-intrusive checks
              </h3>
              <p className="text-muted text-[15px] leading-relaxed">
                Audits are strictly rate-limited, read-only, and detection-focused. WASP never attempts 
                exploitation, payload injection, or service-degrading stress tests.
              </p>
            </div>

            {/* Column 3 */}
            <div>
              <div className="font-heading font-bold text-5xl text-ink leading-none mb-3">
                3
              </div>
              <div className="w-8 h-1 bg-accent mb-5" aria-hidden="true" />
              <h3 className="font-heading font-bold text-xl text-ink mb-2.5">
                Read the report, then fix
              </h3>
              <p className="text-muted text-[15px] leading-relaxed">
                Receive an A to F grade, findings categorized by severity, and a copy-paste fix for every gap. 
                Reports are saved to local SQLite for tracking remediation progress.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* 2) "Findings that teach" on a dark ink background (#0F1720) with a #16212E card */}
      <section className="py-24 bg-ink text-surface">
        <div className="content-wrapper">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
            
            {/* Left Column */}
            <div className="lg:col-span-5">
              <div className="font-mono text-xs uppercase tracking-widest text-[#8A9BA8] mb-3">
                Actionable Intelligence
              </div>
              <h2 className="font-heading font-semibold text-3xl sm:text-4xl text-surface tracking-tight mb-5 leading-tight">
                Every finding explains the attack and the fix.
              </h2>
              <p className="text-[#C5D1DE] text-[16px] leading-[1.65] mb-6">
                Vulnerability scanners that dump raw error codes leave developers guessing. 
                WASP maps every detected issue directly to the <strong>OWASP Top 10 (2021)</strong> framework, 
                explaining exactly how a real-world attacker would abuse the misconfiguration and providing 
                tested, copy-paste server configurations to close the window immediately.
              </p>
              <div className="font-mono text-xs text-[#8A9BA8] border-l-2 border-accent pl-3">
                Mapped to OWASP Top 10 (2021) Standards
              </div>
            </div>

            {/* Right Column: #16212E Card */}
            <div className="lg:col-span-7">
              <div className="bg-[#16212E] border border-[#25364A] p-6 sm:p-8">
                {/* Header row with Chips */}
                <div className="flex flex-wrap items-center gap-2.5 mb-4">
                  <span className="chip chip-medium">Medium</span>
                  <span className="chip bg-[#0F1720] text-[#C5D1DE] border border-[#2B3E54]">
                    A05:2021 Security Misconfiguration
                  </span>
                </div>

                <h3 className="font-heading font-bold text-xl text-surface mb-6 leading-snug">
                  Strict-Transport-Security header is missing
                </h3>

                {/* How an attacker abuses it */}
                <div className="mb-6">
                  <div className="text-xs font-mono uppercase tracking-wider text-[#8A9BA8] mb-2 font-semibold">
                    How an attacker abuses it
                  </div>
                  <p className="text-sm text-[#C5D1DE] leading-relaxed bg-[#0F1720] p-4 border border-[#25364A]">
                    When users access the site over untrusted Wi-Fi, an active Man-in-the-Middle attacker can intercept 
                    the initial HTTP request and perform SSL stripping, keeping the user on plain HTTP to steal session 
                    cookies and credentials in cleartext.
                  </p>
                </div>

                {/* Fix (nginx) */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-mono uppercase tracking-wider text-[#8A9BA8] font-semibold">
                      Fix (nginx)
                    </span>
                    <button
                      type="button"
                      onClick={handleCopy}
                      className="text-xs font-mono text-[#F5B301] hover:underline cursor-pointer min-h-[30px]"
                    >
                      {copied ? 'Copied to clipboard' : 'Copy fix'}
                    </button>
                  </div>
                  <div className="bg-[#0A1017] p-4 border border-[#25364A] overflow-x-auto">
                    <code className="font-mono text-xs text-[#E3E0D8] whitespace-pre">
                      {sampleSnippet}
                    </code>
                  </div>
                </div>
              </div>
            </div>

          </div>
        </div>
      </section>
    </>
  );
}

