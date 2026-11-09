import React, { useState } from 'react';
import Header from './components/Header';
import HeroSection from './components/HeroSection';
import ChecksSection from './components/ChecksSection';
import HowItWorksSection from './components/HowItWorksSection';
import EthicsAndFooter from './components/EthicsAndFooter';
import ResultsPage from './components/ResultsPage';
import HistoryPage from './components/HistoryPage';
import ScanningLoader from './components/ScanningLoader';
import { scanTarget } from './services/api';

export default function App() {
  const [currentView, setView] = useState('form'); // 'form' | 'results' | 'history'
  const [currentReport, setCurrentReport] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [activeScanUrl, setActiveScanUrl] = useState('');
  const [consentGiven, setConsentGiven] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const handleStartScan = async (url, consent) => {
    setIsLoading(true);
    setActiveScanUrl(url);
    setErrorMessage('');
    try {
      const report = await scanTarget(url, consent);
      setCurrentReport(report);
      setView('results');
    } catch (err) {
      setErrorMessage(err.message || 'An error occurred during security posture scan.');
    } finally {
      setIsLoading(false);
      setActiveScanUrl('');
    }
  };

  const handleSelectReport = (report) => {
    setCurrentReport(report);
    setView('results');
  };

  return (
    <div className="min-h-screen flex flex-col bg-paper text-ink font-sans antialiased">
      {/* Header with Top 6px diagonal stripe bar */}
      <Header currentView={currentView} setView={setView} />

      {/* Main Content Area */}
      <main className="flex-1">
        {/* Error Notification Bar */}
        {errorMessage && (
          <div className="content-wrapper mt-6">
            <div 
              role="alert"
              className="bg-surface border-l-4 border-critical p-4 text-sm flex items-center justify-between gap-4 border border-line"
            >
              <div className="text-critical font-medium">
                <strong>Audit Error:</strong> {errorMessage}
              </div>
              <button
                type="button"
                onClick={() => setErrorMessage('')}
                className="text-muted hover:text-ink font-mono text-sm cursor-pointer p-1 min-h-[44px] min-w-[44px] flex items-center justify-center"
                aria-label="Dismiss error notification"
              >
                ✕
              </button>
            </div>
          </div>
        )}

        {/* Loading State during audit execution */}
        {isLoading && (
          <ScanningLoader targetUrl={activeScanUrl} />
        )}

        {/* View 1: Main Landing / Audit Form View */}
        {!isLoading && currentView === 'form' && (
          <>
            <HeroSection
              onStartScan={handleStartScan}
              isLoading={isLoading}
              consentGiven={consentGiven}
              setConsentGiven={setConsentGiven}
            />
            <ChecksSection />
            <HowItWorksSection />
            <EthicsAndFooter />
          </>
        )}

        {/* View 2: Detailed Results View */}
        {!isLoading && currentView === 'results' && (
          <>
            <ResultsPage
              report={currentReport}
              onBackToForm={() => setView('form')}
            />
            <EthicsAndFooter />
          </>
        )}

        {/* View 3: Reports History View */}
        {!isLoading && currentView === 'history' && (
          <>
            <HistoryPage
              onSelectReport={handleSelectReport}
              onBackToForm={() => setView('form')}
            />
            <EthicsAndFooter />
          </>
        )}
      </main>
    </div>
  );
}
