// ── state.js — global app state ──────────────────────────────────────
const state = {
  user:           null,
  currentProject: null,
  projects:       [],
  wstgProgress:   {},
  psProgress:     {},
  customVulns:    [],
  targets:        [],
  methodologies:       [],   // full library
  activeMethodologies:  [],   // active in current project (with progress embedded)
  methodProgress: {}, // { [methodId]: { [testIdx]: {status,note,target_id} } }
  activeMethodProgress: {}, // { [methodId]: {name,total,done,fail,tests} } — for dashboard
  pciControls:    null, // PCI-DSS catalog, fetched once from /compliance/frameworks/pci-dss and cached here
  members:        [],
  activityFeed:   [],
  onlineUsers:    [],
  currentView:    'dashboard',
  wstgFilter:     'all',
  psFilter:       'all',
};

window.state = state;