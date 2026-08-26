// Thin wrapper around the GitHub REST API — same bare `fetch` pattern
// services/ai/groq.js already uses, no new HTTP client dependency.
// v1 only ever creates an issue (one-way push); see GITHUB_INTEGRATION.md.

const API_BASE = 'https://api.github.com';

async function createIssue(repo, pat, { title, body }) {
  const res = await fetch(`${API_BASE}/repos/${repo}/issues`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${pat}`,
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ title, body }),
  });

  if (!res.ok) {
    const detail = await res.text();
    console.error('GitHub API error:', res.status, detail);
    if (res.status === 401) throw new Error('GitHub token is invalid or expired');
    if (res.status === 404) throw new Error(`Repository "${repo}" not found, or the token can't access it`);
    if (res.status === 410) throw new Error('Issues are disabled on this repository');
    throw new Error('GitHub API request failed');
  }

  const data = await res.json();
  return { id: String(data.number), url: data.html_url };
}

module.exports = { createIssue };
