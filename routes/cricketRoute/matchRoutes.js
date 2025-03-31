const express = require("express");
const router = express.Router();
const authMiddleware = require("../../middleware/auth_middleware");
const axios = require("axios");

// Import the controller for match operations
const matchController = require("../../controller/cricketAPIController/matchController");

// Get all teams (accessible with authentication)
router.get("/all-teams", authMiddleware, matchController.getAllTeams);

// Create a new match
router.post("/matches", authMiddleware, async (req, res) => {
  try {
    const { format, dateTime, location, team2Id } = req.body;

    // Validate required fields
    if (!format || !dateTime || !location || !team2Id) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields: format, dateTime, location, team2Id"
      });
    }

    // Get user ID from auth middleware
    const userId = req.user.id;

    // Fetch teams data to validate team2Id
    try {
      const teamsResponse = await axios.get("http://localhost:3000/api/cricket/all-teams", {
        headers: {
          Authorization: req.headers.authorization
        }
      });
      
      const teams = teamsResponse.data;
      
      // Check if team2Id exists (using _id from your API)
      const team2Exists = teams.some(team => team._id === team2Id);
      if (!team2Exists) {
        return res.status(400).json({
          success: false,
          message: "Invalid team2Id. Team does not exist."
        });
      }

      // Get user's team (team1) - Assuming the user's team is the first one in the list for this example
      // In a real implementation, you would need logic to determine which team belongs to the user
      const userTeam = teams[0];
      
      // Create the match
      const newMatch = {
        id: Date.now().toString(), // Simple ID generation
        format,
        dateTime,
        location,
        team1: {
          id: userTeam._id,
          name: userTeam.name,
          logo: userTeam.logo
        },
        team2: {
          id: team2Id,
          name: teams.find(team => team._id === team2Id).name,
          logo: teams.find(team => team._id === team2Id).logo
        },
        status: "scheduled",
        createdBy: userId,
        createdAt: new Date().toISOString(),
        scores: {
          team1: { runs: 0, wickets: 0, overs: 0 },
          team2: { runs: 0, wickets: 0, overs: 0 }
        }
      };

      // Save match to database
      const savedMatch = await matchController.createMatch(newMatch);

      res.status(201).json({
        success: true,
        message: "Match created successfully",
        match: savedMatch
      });
      
    } catch (error) {
      console.error("Error fetching teams:", error);
      return res.status(500).json({
        success: false,
        message: "Error validating teams"
      });
    }
  } catch (error) {
    console.error("Error creating match:", error);
    res.status(500).json({
      success: false,
      message: "Failed to create match"
    });
  }
});

// Get all matches
router.get("/matches", authMiddleware, matchController.getAllMatches);

// Get specific match by ID
router.get("/matches/:id", authMiddleware, matchController.getMatchById);

// Update match score
router.put("/matches/:id/score", authMiddleware, matchController.updateMatchScore);

// Update match status (e.g., scheduled, in-progress, completed)
router.put("/matches/:id/status", authMiddleware, matchController.updateMatchStatus);

// Delete a match (only by creator)
router.delete("/matches/:id", authMiddleware, matchController.deleteMatch);

module.exports = router;