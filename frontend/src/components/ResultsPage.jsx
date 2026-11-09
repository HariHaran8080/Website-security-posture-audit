import React, { useState } from 'react';

export default function ResultsPage({ report, onBackToForm }) {
  const [expandedId, setExpandedId] = useState(null);
  const [copiedId, setCopiedId] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState('ALL');

  if (!report) return null;

  const { target_url, grade, numerical_score, total_issues, severity_summary, owasp_summary, findings, scanned_at } = report;

  const toggleExpand = (id) => {
    setExpandedId(prev => (prev === id ? null : id));
  };

  const handleCopy = (id, text) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Severity grouping order
  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];

  // Filtered findings
  const filtered = findings.filter(f => {
    if (filterSeverity === 'ALL') return true;
    if (filterSeverity === 'PASS') return f.status === 'pass';
    return f.severity?.toLowerCase() === filterSeverity.toLowerCase() && f.status !== 'pass';
  });

  // Calculate severity bar percentages
  const critCount = severity_summary?.critical || 0;
  const highCount = severity_summary?.high || 0;
  const medCount = severity_summary?.medium || 0;
  const lowCount = severity_summary?.low || 0;
  const totalBarCount = Math.max(1, critCount + highCount + medCount + lowCount);

  return (
    <div className="py-12 md:py-16">
      <div className="content-wrapper">
        
        {/* Navigation / Back link */}
        <div className="flex flex-wrap items-center justify-between gap-4 mb-8 pb-4 border-b border-line">
          <button
            type="button"
            onClick={onBackToForm}
            className="min-h-[44px] flex items-center gap-2 text-sm font-medium text-ink hover:underline cursor-pointer"
          >
            ← Run another audit
          </button>

          <div className="flex items-center gap-3 text-xs font-mono text-subtle">
            <span>Target:</span>
            <span className="font-semibold text-ink">{target_url}</span>
            <span>·</span>
            <span>{new Date(scanned_at).toLocaleString()}</span>
          </div>
        </div>

        {/* Top Summary Card */}
        <div className="bg-surface border border-line p-6 sm:p-8 mb-10">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-6 border-b border-line mb-6">
            <div className="flex items-center gap-6">
              {/* 108px Ink Square with Grade */}
              <div className="w-[108px] h-[108px] bg-ink flex flex-col items-center justify-center flex-shrink-0 text-surface">
                <span className="font-heading font-bold text-4xl leading-none text-surface">
                  {grade}
                </span>
                <span className="text-[11px] font-mono text-line uppercase mt-1">
                  Grade
                </span>
              </div>

              <div>
                <div className="text-xs font-mono uppercase tracking-wider text-subtle mb-1">
                  Posture Score
                </div>
                <div className="font-heading font-bold text-3xl sm:text-4xl text-ink leading-tight">
                  {numerical_score} <span className="text-xl text-subtle font-normal">/ 100</span>
                </div>
                <div className="text-sm text-muted mt-1 font-sans">
                  {total_issues} security issues identified across evaluated attack surfaces
                </div>
              </div>
            </div>

            {/* Target Details */}
            <div className="text-left md:text-right font-mono text-xs text-subtle">
              <div>HOST: <span className="text-ink">{target_url}</span></div>
              <div className="mt-1">STATUS: <span className="text-ink">AUDIT COMPLETED</span></div>
            </div>
          </div>

          {/* Segmented Severity Bar with Legend */}
          <div>
            <div className="text-xs font-mono uppercase tracking-wider text-subtle mb-2">
              Issues by Severity
            </div>
            <div className="h-3 w-full flex gap-[2px] bg-paper p-[2px] border border-line mb-3">
              {critCount > 0 && (
                <div style={{ width: `${(critCount / totalBarCount) * 100}%` }} className="bg-critical" title={`${critCount} Critical`} />
              )}
              {highCount > 0 && (
                <div style={{ width: `${(highCount / totalBarCount) * 100}%` }} className="bg-high" title={`${highCount} High`} />
              )}
              {medCount > 0 && (
                <div style={{ width: `${(medCount / totalBarCount) * 100}%` }} className="bg-medium" title={`${medCount} Medium`} />
              )}
              {lowCount > 0 && (
                <div style={{ width: `${(lowCount / totalBarCount) * 100}%` }} className="bg-low" title={`${lowCount} Low`} />
              )}
              {totalBarCount === 0 && (
                <div style={{ width: '100%' }} className="bg-low" title="All checks passed" />
              )}
            </div>

            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs font-mono text-muted">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 bg-critical inline-block" />
                <span>Critical {critCount}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 bg-high inline-block" />
                <span>High {highCount}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 bg-medium inline-block" />
                <span>Medium {medCount}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 bg-low inline-block" />
                <span>Low {lowCount}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Filter controls */}
        <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
          <h2 className="font-heading font-semibold text-2xl text-ink">
            Audit Findings ({filtered.length})
          </h2>

          <div className="flex flex-wrap gap-2 text-xs font-mono">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'PASS'].map((f) => (
              <button
                key={f}
                type="button"
                onClick={() => setFilterSeverity(f)}
                className={`min-h-[36px] px-3 py-1 border border-line cursor-pointer transition-colors ${
                  filterSeverity === f ? 'bg-ink text-surface border-ink' : 'bg-surface text-ink hover:bg-paper'
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        {/* Findings List (Expandable rows) */}
        <div className="border-t border-ink">
          {filtered.map((item) => {
            const isExpanded = expandedId === item.id;
            const isPass = item.status === 'pass';
            const chipClass = isPass ? 'chip-pass' : `chip-${item.severity?.toLowerCase()}`;

            return (
              <div
                key={item.id}
                className="border-b border-line bg-surface transition-colors"
              >
                {/* Row Header */}
                <button
                  type="button"
                  onClick={() => toggleExpand(item.id)}
                  className="w-full text-left p-4 sm:p-5 flex items-center justify-between gap-4 cursor-pointer hover:bg-paper transition-colors"
                  aria-expanded={isExpanded}
                >
                  <div className="flex flex-wrap items-center gap-3 min-w-0">
                    <span className={`chip ${chipClass} flex-shrink-0`}>
                      {isPass ? 'PASS' : item.severity}
                    </span>

                    <span className="font-heading font-semibold text-ink text-base">
                      {item.title}
                    </span>

                    <span className="text-xs font-mono text-subtle">
                      [{item.category}]
                    </span>
                  </div>

                  <div className="flex items-center gap-3 flex-shrink-0">
                    <span className="text-xs font-mono text-subtle hidden sm:inline">
                      {item.owasp_category?.split(' ')[0]}
                    </span>
                    <span className="text-sm font-mono text-ink">
                      {isExpanded ? '−' : '+'}
                    </span>
                  </div>
                </button>

                {/* Expanded Sections */}
                {isExpanded && (
                  <div className="px-4 pb-6 sm:px-5 sm:pb-6 pt-2 border-t border-line bg-[#FAF9F5] space-y-5">
                    {/* Section 1: What we found */}
                    <div>
                      <div className="text-xs font-mono uppercase tracking-wider text-subtle mb-1 font-semibold">
                        What we found
                      </div>
                      <p className="text-sm text-ink leading-relaxed">
                        {item.details}
                      </p>
                    </div>

                    {/* Section 2: How an attacker abuses it */}
                    {item.attacker_abuse && (
                      <div>
                        <div className="text-xs font-mono uppercase tracking-wider text-subtle mb-1 font-semibold">
                          How an attacker abuses it
                        </div>
                        <p className="text-sm text-muted leading-relaxed bg-surface p-3.5 border border-line">
                          {item.attacker_abuse}
                        </p>
                      </div>
                    )}

                    {/* Section 3: Fix */}
                    {item.fix && (
                      <div>
                        <div className="flex items-center justify-between mb-1.5">
                          <span className="text-xs font-mono uppercase tracking-wider text-subtle font-semibold">
                            Fix
                          </span>
                          <button
                            type="button"
                            onClick={() => handleCopy(item.id, item.fix)}
                            className="text-xs font-mono text-ink underline hover:text-muted cursor-pointer min-h-[30px]"
                          >
                            {copiedId === item.id ? 'Copied to clipboard' : 'Copy fix'}
                          </button>
                        </div>
                        <div className="bg-surface p-3.5 border border-line overflow-x-auto">
                          <code className="font-mono text-xs text-ink whitespace-pre">
                            {item.fix}
                          </code>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>

      </div>
    </div>
  );
}
