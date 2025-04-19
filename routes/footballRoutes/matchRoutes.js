const express = require("express");
const router = express.Router();
const authMiddleware = require("../../middleware/auth_middleware");
const matchController = require("../../controller/footballAPIController/matchController");

// Middleware to check authentication can be added here if needed

// Create a new match
router.post("/", authMiddleware, matchController.createMatch);

// Get all teams (forwarded)
router.get("/teams", authMiddleware, matchController.getAllTeams);

// Get all matches with filters
router.get("/", authMiddleware, matchController.getAllMatches);

// Get match by ID
router.get("/:id", authMiddleware, matchController.getMatchById);

// Update match status
router.put("/:id/status", authMiddleware, matchController.updateMatchStatus);

// Delete match
router.delete("/:id", authMiddleware, matchController.deleteMatch);

module.exports = router;
