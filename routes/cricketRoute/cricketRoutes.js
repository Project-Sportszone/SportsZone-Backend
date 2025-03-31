const express = require('express');
const router = express.Router();
const matchScoringController = require('../controllers/matchScoringController');
const { authMiddleware } = require('../middleware/authMiddleware');

// Match creation and basic operations
router.post('/matches', authMiddleware, matchScoringController.createMatch);
router.get('/matches', matchScoringController.getAllMatches);
router.get('/matches/:id', matchScoringController.getMatchById);

// Match progression routes
router.put('/matches/:id/toss', authMiddleware, matchScoringController.updateToss);
router.post('/matches/:id/start', authMiddleware, matchScoringController.startMatch);
router.post('/matches/:id/start-second-innings', authMiddleware, matchScoringController.startSecondInnings);
router.post('/matches/:id/end', authMiddleware, matchScoringController.endMatch);

// Scoring operations
router.put('/matches/:id/score', authMiddleware, matchScoringController.updateScore);

// Scorer management
router.post('/matches/:id/scorers', authMiddleware, matchScoringController.addScorer);
router.delete('/matches/:id/scorers/:scorerId', authMiddleware, matchScoringController.removeScorer);

// Match interruption handling
router.post('/matches/:id/dls', authMiddleware, matchScoringController.applyDLS);
router.post('/matches/:id/resume', authMiddleware, matchScoringController.resumeMatch);

module.exports = router;