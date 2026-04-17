import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import React from 'react';
import { Route, Routes } from 'react-router';
import { Footer } from './components/footer/footer';
import { Header } from './components/header/header';
import { Overview } from './pages/overview/Overview';
import { Applications } from './pages/applications/Applications';
import { AppDetail } from './pages/app-detail/AppDetail';
import { ScanDetail } from './pages/scan-detail/ScanDetail';
import { NewScan } from './pages/new-scan/NewScan';
import { Settings } from './pages/settings/Settings';
import { Metrics } from './pages/metrics/Metrics';
import { NotFound } from './pages/not-found/not-found';

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 10_000 } },
});

export const App = (): React.ReactElement => (
  <QueryClientProvider client={queryClient}>
    <Header />
    <main id="mainSection" className="usa-section">
      <Routes>
        <Route path="/"                           element={<Overview />} />
        <Route path="/applications"               element={<Applications />} />
        <Route path="/applications/:name"         element={<AppDetail />} />
        <Route path="/scans/:id"                  element={<ScanDetail />} />
        <Route path="/new-scan"                   element={<NewScan />} />
        <Route path="/metrics"                    element={<Metrics />} />
        <Route path="/settings"                   element={<Settings />} />
        <Route path="*"                           element={<NotFound />} />
      </Routes>
    </main>
    <Footer />
  </QueryClientProvider>
);

