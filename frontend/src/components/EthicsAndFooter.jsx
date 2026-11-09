import React from 'react';

export default function EthicsAndFooter() {
  return (
    <>
      {/* Ethical use section */}
      <section id="ethical-use" className="py-24 border-t border-line bg-paper">
        <div className="content-wrapper">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-12">
            
            {/* Left Column: Heading & Legal Risk Note */}
            <div className="lg:col-span-5">
              <div className="font-mono text-xs uppercase tracking-widest text-subtle mb-3">
                Rules of Engagement
              </div>
              <h2 className="font-heading font-semibold text-3xl sm:text-4xl text-ink tracking-tight mb-5">
                Scan only what you own.
              </h2>
              <p className="text-muted text-[16px] leading-[1.65]">
                Scanning or probing third-party systems without documented, written authorization 
                is illegal under the United States Computer Fraud and Abuse Act (CFAA 18 U.S.C. § 1030) 
                and equivalent cyber laws internationally. WASP enforces consent locks before any network 
                handshakes occur and records explicit confirmation timestamps in local storage.
              </p>
            </div>

            {/* Right Column: Safe Places to Practice list */}
            <div className="lg:col-span-7">
              <div className="border-t border-ink pt-2">
                <div className="font-mono text-xs uppercase tracking-wider text-subtle mb-4 font-semibold">
                  Safe places to practice
                </div>

                <div className="space-y-0">
                  {/* Row 1: Juice Shop */}
                  <div className="py-4 border-b border-line">
                    <div className="flex flex-col sm:flex-row sm:items-baseline justify-between gap-1 mb-1">
                      <span className="font-heading font-bold text-ink text-lg">
                        OWASP Juice Shop
                      </span>
                      <span className="font-mono text-xs text-subtle">
                        docker run -p 3000:3000 bkimminich/juice-shop
                      </span>
                    </div>
                    <p className="text-sm text-muted">
                      An intentionally insecure web application built by OWASP for penetration testers and auditors to hone defensive skills legally.
                    </p>
                  </div>

                  {/* Row 2: DVWA */}
                  <div className="py-4 border-b border-line">
                    <div className="flex flex-col sm:flex-row sm:items-baseline justify-between gap-1 mb-1">
                      <span className="font-heading font-bold text-ink text-lg">
                        Damn Vulnerable Web Application (DVWA)
                      </span>
                      <span className="font-mono text-xs text-subtle">
                        github.com/digininja/DVWA
                      </span>
                    </div>
                    <p className="text-sm text-muted">
                      A classic PHP/MySQL environment designed to test security configuration auditing tools across varying difficulty levels.
                    </p>
                  </div>

                  {/* Row 3: Your own sites */}
                  <div className="py-4 border-b border-line">
                    <div className="flex flex-col sm:flex-row sm:items-baseline justify-between gap-1 mb-1">
                      <span className="font-heading font-bold text-ink text-lg">
                        Your own websites and staging domains
                      </span>
                      <span className="font-mono text-xs text-subtle">
                        Production & Pre-flight Environments
                      </span>
                    </div>
                    <p className="text-sm text-muted">
                      Your own portfolios, staging servers, and local sandbox applications where you hold direct administrative ownership.
                    </p>
                  </div>
                </div>
              </div>
            </div>

          </div>
        </div>
      </section>

      {/* Professional Black Footer */}
      <footer className="bg-black text-white border-t border-[#1E2632] py-14">
        <div className="content-wrapper">
          <div className="grid grid-cols-1 md:grid-cols-12 gap-10 pb-10 border-b border-[#1E2632]">
            
            {/* Column 1: Brand & Description */}
            <div className="md:col-span-5 flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-3 mb-3">
                  <svg
                    width="32"
                    height="32"
                    viewBox="0 0 36 36"
                    fill="none"
                    xmlns="http://www.w3.org/2000/svg"
                    className="flex-shrink-0"
                    aria-hidden="true"
                  >
                    <polygon
                      points="18,3 32,10.5 32,25.5 18,33 4,25.5 4,10.5"
                      fill="#FFFFFF"
                    />
                    <rect x="11" y="12" width="14" height="2.5" fill="#F5B301" rx="0.5" />
                    <rect x="11" y="17" width="14" height="2.5" fill="#F5B301" rx="0.5" />
                    <rect x="11" y="22" width="14" height="2.5" fill="#F5B301" rx="0.5" />
                  </svg>
                  <div>
                    <span className="font-heading font-bold text-xl tracking-tight text-white inline-block">
                      WASP
                    </span>
                    <span className="ml-2 font-mono text-[11px] text-[#F5B301] uppercase tracking-wider">
                      POSTURE AUDITOR
                    </span>
                  </div>
                </div>

                <p className="text-sm text-[#94A3B8] leading-relaxed max-w-sm">
                  Automated website security posture auditor evaluating HTTP headers, TLS handshakes, cookie hygiene, exposed secrets, CORS policies, and perimeter ports.
                </p>
              </div>

              <div className="mt-6 text-xs text-[#64748B] font-mono">
                ENGINEERED WITH REACT · FASTAPI · SQLITE
              </div>
            </div>

            {/* Column 2: Navigation Shortcuts */}
            <div className="md:col-span-3">
              <div className="font-mono text-xs uppercase tracking-wider text-[#94A3B8] mb-4 font-semibold">
                Navigation
              </div>
              <ul className="space-y-2.5 text-sm">
                <li>
                  <a href="#checks" className="text-[#CBD5E1] hover:text-white hover:underline transition-colors min-h-[36px] inline-flex items-center">
                    Security Checks
                  </a>
                </li>
                <li>
                  <a href="#how-it-works" className="text-[#CBD5E1] hover:text-white hover:underline transition-colors min-h-[36px] inline-flex items-center">
                    Audit Methodology
                  </a>
                </li>
                <li>
                  <a href="#sample-report" className="text-[#CBD5E1] hover:text-white hover:underline transition-colors min-h-[36px] inline-flex items-center">
                    Sample Report
                  </a>
                </li>
                <li>
                  <a href="#ethical-use" className="text-[#CBD5E1] hover:text-white hover:underline transition-colors min-h-[36px] inline-flex items-center">
                    Rules of Engagement
                  </a>
                </li>
              </ul>
            </div>

            {/* Column 3: Professional Connect & Profiles */}
            <div className="md:col-span-4 flex flex-col justify-between">
              <div>
                <div className="font-mono text-xs uppercase tracking-wider text-[#94A3B8] mb-4 font-semibold">
                  Developer Profiles
                </div>
                
                <div className="space-y-3">
                  {/* GitHub Profile */}
                  <a
                    href="https://github.com/Hariharan8080"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center justify-between p-3 bg-[#0F1720] border border-[#1E2632] hover:border-[#F5B301] text-white transition-all group min-h-[44px]"
                  >
                    <div className="flex items-center gap-3">
                      <svg
                        width="20"
                        height="20"
                        viewBox="0 0 24 24"
                        fill="currentColor"
                        className="text-[#94A3B8] group-hover:text-white transition-colors flex-shrink-0"
                        aria-hidden="true"
                      >
                        <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
                      </svg>
                      <div>
                        <div className="text-sm font-medium text-white group-hover:text-[#F5B301] transition-colors leading-none">
                          GitHub
                        </div>
                        <div className="font-mono text-xs text-[#94A3B8] mt-1">
                          @Hariharan8080
                        </div>
                      </div>
                    </div>
                    <span className="font-mono text-xs text-[#64748B] group-hover:text-white transition-colors">
                      ↗
                    </span>
                  </a>

                  {/* LinkedIn Profile */}
                  <a
                    href="https://www.linkedin.com/in/hariharan044/"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center justify-between p-3 bg-[#0F1720] border border-[#1E2632] hover:border-[#F5B301] text-white transition-all group min-h-[44px]"
                  >
                    <div className="flex items-center gap-3">
                      <svg
                        width="20"
                        height="20"
                        viewBox="0 0 24 24"
                        fill="currentColor"
                        className="text-[#94A3B8] group-hover:text-white transition-colors flex-shrink-0"
                        aria-hidden="true"
                      >
                        <path d="M19 3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14m-.5 15.5v-5.3a3.26 3.26 0 0 0-3.26-3.26c-.85 0-1.84.52-2.28 1.3v-1.11h-2.79v8.37h2.79v-4.93c0-.77.62-1.4 1.39-1.4a1.4 1.4 0 0 1 1.4 1.4v4.93h2.75M6.46 10.9v8.37H9.2V10.9H6.46M7.83 6.45a1.6 1.6 0 0 0-1.6 1.6 1.6 1.6 0 0 0 1.6 1.6 1.6 1.6 0 0 0 1.6-1.6 1.6 1.6 0 0 0-1.6-1.6z" />
                      </svg>
                      <div>
                        <div className="text-sm font-medium text-white group-hover:text-[#F5B301] transition-colors leading-none">
                          LinkedIn
                        </div>
                        <div className="font-mono text-xs text-[#94A3B8] mt-1">
                          in/hariharan044
                        </div>
                      </div>
                    </div>
                    <span className="font-mono text-xs text-[#64748B] group-hover:text-white transition-colors">
                      ↗
                    </span>
                  </a>
                </div>
              </div>

              <div className="mt-4 text-xs text-[#64748B]">
                Open to security research & defensive engineering collaborations.
              </div>
            </div>

          </div>

          {/* Sub-footer Bar */}
          <div className="pt-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs font-mono text-[#94A3B8]">
            <div>
              © 2026 WASP · Created by <span className="text-white font-semibold">Hariharan T</span>
            </div>

            <div className="text-center sm:text-right text-[#64748B]">
              FOR AUTHORIZED DEFENSIVE POSTURE ASSESSMENTS ONLY
            </div>
          </div>
        </div>
      </footer>
    </>
  );
}

