const express = require("express");
const router = express.Router();
const matchController = require("../../controller/badmintonAPIController/matchController");

// Middleware to check authentication can be added here if needed

// Create a new match
router.post("/", matchController.createMatch);

// Get all teams (forwarded)
router.get("/teams", matchController.getAllTeams);

// Get all matches with filters
router.get("/", matchController.getAllMatches);

// Get match by ID
router.get("/:id", matchController.getMatchById);

// Update match status
router.put("/:id/status", matchController.updateMatchStatus);

// Delete match
router.delete("/:id", matchController.deleteMatch);

module.exports = router;
