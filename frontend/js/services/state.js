// ── state.js — global app state ──────────────────────────────────────
const state = {
  user:           null,
  currentProject: null,
  projects:       [],
  wstgProgress:   {},
  psProgress:     {},
  customVulns:    [],
  targets:        [],
  members:        [],
  activityFeed:   [],
  onlineUsers:    [],
  currentView:    'dashboard',
  wstgFilter:     'all',
  psFilter:       'all',
};

window.state = state;