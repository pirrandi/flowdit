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
  members:        [],
  activityFeed:   [],
  onlineUsers:    [],
  currentView:    'dashboard',
  wstgFilter:     'all',
  psFilter:       'all',
  navAiBadge:     null, // 'running' | 'waiting_approval' | null — sobrevive a renders del sidenav, ver setNavAiBadge() en page.js
};

window.state = state;