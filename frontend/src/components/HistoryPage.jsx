import React, { useEffect, useState } from 'react';
import { fetchReports, fetchReportById } from '../services/api';

export default function HistoryPage({ onSelectReport, onBackToForm }) {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadReports();
  }, []);

  const loadReports = async () => {
    try {
      setLoading(true);
      const data = await fetchReports();
      setReports(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleView = async (id) => {
    try {
      const fullReport = await fetchReportById(id);
      onSelectReport(fullReport);
    } catch (err) {
      alert(`Could not load report #${id}: ${err.message}`);
    }
  };

  return (
    <div className="py-12 md:py-16">
      <div className="content-wrapper">
        
        {/* Header bar */}
        <div className="flex flex-wrap items-center justify-between gap-4 mb-10 pb-4 border-b border-line">
          <div>
            <div className="font-mono text-xs uppercase tracking-widest text-subtle mb-1">
              Audit Archives
            </div>
            <h1 className="font-heading font-semibold text-3xl text-ink tracking-tight">
              Past Reports
            </h1>
          </div>

          <button
            type="button"
            onClick={onBackToForm}
            className="min-h-[44px] px-5 py-2.5 bg-ink text-surface font-sans font-medium text-sm hover:bg-muted transition-colors cursor-pointer"
          >
            Run new audit
          </button>
        </div>

        {loading && (
          <div className="bg-surface border border-line p-10 text-center text-subtle font-mono text-sm">
            Loading stored audit reports from SQLite...
          </div>
        )}

        {error && (
          <div className="bg-surface border border-critical p-6 text-critical text-sm font-medium">
            Error loading past reports: {error}
          </div>
        )}

        {!loading && reports.length === 0 && (
          <div className="bg-surface border border-line p-12 text-center">
            <h3 className="font-heading font-bold text-xl text-ink mb-2">
              No audit reports stored yet
            </h3>
            <p className="text-muted text-sm mb-6 max-w-md mx-auto">
              Run your first posture scan against a local lab or authorized domain to store reports.
            </p>
            <button
              type="button"
              onClick={onBackToForm}
              className="min-h-[44px] px-6 py-2.5 bg-accent text-ink font-semibold text-sm hover:bg-[#e0a400] transition-colors cursor-pointer"
            >
              Start an audit
            </button>
          </div>
        )}

        {/* Clean Report List */}
        <div className="space-y-4">
          {reports.map((report) => (
            <div
              key={report.id}
              className="bg-surface border border-line p-5 sm:p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-6 hover:border-ink transition-colors"
            >
              {/* Left: Grade square + Target & details */}
              <div className="flex items-center gap-5">
                {/* Grade Square */}
                <div className="w-16 h-16 bg-ink text-surface flex flex-col items-center justify-center flex-shrink-0">
                  <span className="font-heading font-bold text-2xl leading-none text-surface">
                    {report.grade}
                  </span>
                  <span className="text-[10px] font-mono text-line uppercase">
                    Grade
                  </span>
                </div>

                {/* Target URL & Stats */}
                <div>
                  <div className="font-mono text-base font-semibold text-ink break-all">
                    {report.target_url}
                  </div>
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs font-mono text-subtle mt-1.5">
                    <span>Score: <strong className="text-ink">{report.numerical_score}</strong>/100</span>
                    <span>·</span>
                    <span>{report.total_issues} issues detected</span>
                    <span>·</span>
                    <span>{new Date(report.scanned_at).toLocaleDateString()}</span>
                  </div>
                </div>
              </div>

              {/* Right: Action button */}
              <button
                type="button"
                onClick={() => handleView(report.id)}
                className="min-h-[44px] px-4 py-2 bg-paper border border-line text-ink font-sans font-medium text-sm hover:bg-line transition-colors self-start sm:self-center cursor-pointer"
              >
                Open report →
              </button>
            </div>
          ))}
        </div>

      </div>
    </div>
  );
}
