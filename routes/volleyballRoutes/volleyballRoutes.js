const express = require("express");
const router = express.Router();
const authMiddleware = require("../../middleware/auth_middleware");
const volleyballMatchController = require("../../controller/volleyballAPIController/volleyballmatch");

// Middleware to check authentication can be added here if needed

// Update match status
router.put(
  "/:id/status",
  authMiddleware,
  volleyballMatchController.updateMatchStatus
);

// Add scorer to match
router.post(
  "/:id/scorers/:memberId",
  authMiddleware,
  volleyballMatchController.addScorer
);

// Remove scorer from match
router.delete(
  "/:id/scorers/:scorerId",
  authMiddleware,
  volleyballMatchController.removeScorer
);

// Update set score
router.put(
  "/:id/set-score",
  authMiddleware,
  volleyballMatchController.updateSetScore
);

// End match
router.put("/:id/end", authMiddleware, volleyballMatchController.endMatch);

module.exports = router;
