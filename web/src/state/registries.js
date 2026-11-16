// Shared, never-reassigned collections used by the STIG pages and the Jira modals.
// Exposed on `window` (see index.js) so the legacy drawer code reads the same objects.
export const _stigRegistry = new Map();   // populated by renderStigViewer
export const _stigJiraSel = new Set();    // STIG controls ticked for a Jira ticket
