const express = require("express");
const router = express.Router();
const authMiddleware = require("../../middleware/auth_middleware");

// Import the controller for match operations
const matchController = require("../../controller/cricketAPIController/matchController");

// Get all teams (accessible with authentication)
router.get("/all-teams", authMiddleware, matchController.getAllTeams); // X

// Create a new match
router.post("/", authMiddleware, matchController.createMatch);

// Get all matches
router.get("/", authMiddleware, matchController.getAllMatches);

// Get specific match by ID
router.get("/:id", authMiddleware, matchController.getMatchById);

// Update match score
router.put(
  "/:id/:teamId/score",
  authMiddleware,
  matchController.updateMatchScore // X  // Incomplete logic
);

// Update match status (e.g., scheduled, in-progress, completed)
router.put("/:id/status", authMiddleware, matchController.updateMatchStatus);

// Delete a match (only by creator)
router.delete("/:id", authMiddleware, matchController.deleteMatch);

module.exports = router;
