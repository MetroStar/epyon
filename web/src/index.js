// Module entry. Everything exported here is also placed on `window`: the legacy
// script (main.js) and the inline onclick="fn()" handlers in rendered HTML look
// these functions up as globals. Remove names from here once nothing global needs them.
import * as m0 from './lib/format.js';
import * as m1 from './lib/scans.js';
import * as m2 from './components/badges.js';
import * as m3 from './components/layout.js';
import * as m4 from './components/charts.js';
import * as m5 from './components/feedback.js';
import * as m6 from './lib/cache.js';
import * as m7 from './lib/api.js';
import * as m8 from './pages/poam.js';
import * as m9 from './core/router.js';
import * as m10 from './pages/settings.js';
import * as m11 from './pages/performance.js';
import * as m12 from './pages/stig-history.js';
import * as m13 from './pages/new-scan.js';
import * as m14 from './pages/self-diagnostic.js';
import * as m15 from './state/registries.js';
import * as m16 from './pages/jira-review.js';
import * as m17 from './pages/stig.js';
import * as m18 from './pages/metrics.js';
import * as m19 from './pages/overview.js';
import * as m20 from './pages/applications.js';
import * as m21 from './components/scan/model-security.js';
import * as m22 from './components/scan/network-enrichment.js';
import * as m23 from './components/scan/evidence.js';
import * as m24 from './pages/scan-detail.js';
import * as m25 from './components/scan/suppressed.js';
import * as m26 from './components/scan/sbom.js';
import * as m27 from './components/scan/api-endpoints.js';
import * as m28 from './components/scan/findings.js';
import * as m29 from './components/summaries.js';
import * as m30 from './components/scorecard.js';
import * as m31 from './components/app-actions.js';
import * as m32 from './components/drawers/stig.js';
import * as m33 from './components/drawers/finding.js';
import * as m34 from './components/drawers/signals.js';

Object.assign(window, m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34);
