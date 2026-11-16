// Shared, never-reassigned collections used by the STIG pages and the Jira modals.
// Exposed on `window` (see index.js) so the legacy drawer code reads the same objects.
export const _stigRegistry = new Map();   // populated by renderStigViewer
export const _stigJiraSel = new Set();    // STIG controls ticked for a Jira ticket

// Detail-drawer registries: the rendered sections register an item and put its id in an
// onclick; the drawers (still in main.js) look it up. Cleared on every navigation.
export const _findingsRegistry = new Map();
let _findingNextId = 0;
export function _registerFinding(f) {
  const id = _findingNextId++;
  _findingsRegistry.set(id, f);
  return id;
}
export function _resetFindingsRegistry() {
  _findingsRegistry.clear();
  _findingNextId = 0;
}
export const _depsRegistry = new Map();   // populated by sbomRender
export const _apiRegistry = new Map();    // populated by apiRender
