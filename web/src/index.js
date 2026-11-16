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

Object.assign(window, m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12);
