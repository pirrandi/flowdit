// Inbox de propuestas de Claude Code (ver services/mcp/proposals.js).
// Sesión normal de usuario: un portal nunca llega acá (requireUser), y
// aprobar/rechazar es trabajo técnico, así que alcanza con ser writer.
const router = require('express').Router({ mergeParams: true });
const { param, query, validationResult } = require('express-validator');
const { requireAuth, requireUser } = require('../middleware/auth');
const { requireProjectAccess, requireWriter } = require('../middleware/project');
const proposals = require('../services/mcp/proposals');

router.use(requireAuth, requireUser, requireProjectAccess);

function sendProposalError(err, res, next) {
  if (err instanceof proposals.ProposalError) return res.status(err.status).json({ error: err.message });
  next(err);
}

// GET /projects/:projectId/mcp-proposals?status=pending
router.get('/', [
  query('status').optional().isIn(['pending', 'approved', 'rejected']),
], async (req, res, next) => {
  if (!validationResult(req).isEmpty()) return res.status(400).json({ error: 'Invalid status' });
  try {
    res.json(await proposals.listProposals(req.params.projectId, req.query.status || 'pending'));
  } catch (err) { next(err); }
});

// POST /projects/:projectId/mcp-proposals/:proposalId/approve
router.post('/:proposalId/approve', requireWriter, [param('proposalId').isUUID()], async (req, res, next) => {
  if (!validationResult(req).isEmpty()) return res.status(404).json({ error: 'Proposal not found' });
  try {
    res.json(await proposals.approveProposal({ projectId: req.params.projectId, proposalId: req.params.proposalId, user: req.user }));
  } catch (err) { sendProposalError(err, res, next); }
});

// POST /projects/:projectId/mcp-proposals/:proposalId/reject
router.post('/:proposalId/reject', requireWriter, [param('proposalId').isUUID()], async (req, res, next) => {
  if (!validationResult(req).isEmpty()) return res.status(404).json({ error: 'Proposal not found' });
  try {
    res.json(await proposals.rejectProposal({ projectId: req.params.projectId, proposalId: req.params.proposalId, user: req.user }));
  } catch (err) { sendProposalError(err, res, next); }
});

module.exports = router;
