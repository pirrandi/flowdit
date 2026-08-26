const router = require('express').Router();
const { requireAuth } = require('../middleware/auth');
const { PCI_DSS_CONTROLS } = require('../db/compliance-frameworks');

router.use(requireAuth);

// GET /api/compliance/frameworks/pci-dss — static reference catalog
router.get('/frameworks/pci-dss', (req, res) => {
  res.json(PCI_DSS_CONTROLS);
});

module.exports = router;
