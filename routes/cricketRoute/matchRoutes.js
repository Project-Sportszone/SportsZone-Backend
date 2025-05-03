const express = require("express");
const router = express.Router();
const authMiddleware = require("../../middleware/auth_middleware");
const axios = require("axios");

// Import the controller for match operations
const matchController = require("../../controller/cricketAPIController/matchController");



// Get all matches
router.get("/matches", authMiddleware, matchController.getAllMatches);

// Get specific match by ID
router.get("/matches/:id", authMiddleware, matchController.getMatchById);

// Update match score
// router.put("/matches/:id/score", authMiddleware, matchController.updateMatchScore);

// Update match status (e.g., scheduled, in-progress, completed)
router.put("/matches/:id/status", authMiddleware, matchController.updateMatchStatus);

// Delete a match (only by creator)
router.delete("/matches/:id", authMiddleware, matchController.deleteMatch);

module.exports = router;