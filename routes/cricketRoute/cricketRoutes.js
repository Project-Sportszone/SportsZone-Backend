const express = require("express");
const router = express.Router();
const matchScoringController = require("../../controller/cricketAPIController/cricmatch");
const authMiddleware = require("../../middleware/auth_middleware");

// Match progression routes
router.put(
  "/matches/:id/toss",
  authMiddleware,
  matchScoringController.updateToss
);
router.post(
  "/matches/:id/start",
  authMiddleware,
  matchScoringController.startMatch
);
router.post(
  "/matches/:id/start-second-innings",
  authMiddleware,
  matchScoringController.startSecondInnings // X  // Incomplete logic
);
router.post(
  "/matches/:id/end",
  authMiddleware,
  matchScoringController.endMatch // X // Incomplete logic
);

// Scoring operations
router.put(
  "/matches/:id/score",
  authMiddleware,
  matchScoringController.updateScore // X   // Incomplete logic
);

// Scorer management
router.post(
  "/matches/:id/scorers/:memberId",
  authMiddleware,
  matchScoringController.addScorer
);
router.delete(
  "/matches/:id/scorers/:scorerId",
  authMiddleware,
  matchScoringController.removeScorer
);

// Match interruption handling
router.post(
  "/matches/:id/dls",
  authMiddleware,
  matchScoringController.applyDLS // X   // Incomplete logic
);
router.post(
  "/matches/:id/resume",
  authMiddleware,
  matchScoringController.resumeMatch
);

module.exports = router;
