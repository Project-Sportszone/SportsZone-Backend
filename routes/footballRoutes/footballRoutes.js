const express = require("express");
const router = express.Router();
const authMiddleware = require("../../middleware/auth_middleware");
const footballMatchController = require("../../controller/footballAPIController/footballmatch");

// Middleware to check authentication can be added here if needed

// Update match status
router.put(
  "/:id/status",
  authMiddleware,
  footballMatchController.updateMatchStatus
);

// Add scorer to match
router.post(
  "/:id/scorers/:memberId",
  authMiddleware,
  footballMatchController.addScorer
);

// Remove scorer from match
router.delete(
  "/:id/scorers/:scorerId",
  authMiddleware,
  footballMatchController.removeScorer
);

// Update match event (goal, card, substitution)
router.put(
  "/:id/event",
  authMiddleware,
  footballMatchController.updateMatchEvent
);

// End match
router.put("/:id/end", authMiddleware, footballMatchController.endMatch);

module.exports = router;
