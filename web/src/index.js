// Module entry. Everything exported here is also placed on `window`: the legacy
// script (main.js) and the inline onclick="fn()" handlers in rendered HTML look
// these functions up as globals. Remove names from here once nothing global needs them.
import * as m0 from './lib/format.js';
import * as m1 from './lib/scans.js';
import * as m2 from './components/badges.js';
import * as m3 from './components/layout.js';
import * as m4 from './components/charts.js';
import * as m5 from './components/feedback.js';

Object.assign(window, m0, m1, m2, m3, m4, m5);
