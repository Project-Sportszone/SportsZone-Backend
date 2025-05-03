const express = require("express");
const router = express.Router();
const badmintonMatchController = require("../../controller/badmintonAPIController/badmintonmatch");

// Middleware to check authentication can be added here if needed

// Update match status
router.put("/:id/status", badmintonMatchController.updateMatchStatus);

// Add scorer to match
router.post("/:id/scorers/:memberId", badmintonMatchController.addScorer);

// Remove scorer from match
router.delete("/:id/scorers/:scorerId", badmintonMatchController.removeScorer);

// Update game score
router.put("/:id/game-score", badmintonMatchController.updateGameScore);

// End match
router.put("/:id/end", badmintonMatchController.endMatch);

module.exports = router;
