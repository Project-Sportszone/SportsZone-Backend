const axios = require("axios");

// This would typically use a database model
// For this example, we'll use an in-memory array for matches
let matches = [];

const matchController = {
  // Get all teams - Now fetching from the API endpoint
  getAllTeams: async (req, res) => {
    try {
      // Forward the request to the actual API endpoint
      const response = await axios.get("http://localhost:3000/api/cricket/all-teams", {
        headers: {
          Authorization: req.headers.authorization
        }
      });
      
      // Return the teams from the API
      res.status(200).json(response.data);
    } catch (error) {
      console.error("Error fetching teams:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch teams"
      });
    }
  },

  // Create a new match
  createMatch: async (matchData) => {
    // In a real app, this would save to a database
    matches.push(matchData);
    return matchData;
  },

  // Get all matches
  getAllMatches: async (req, res) => {
    try {
      // Apply filters if provided
      let filteredMatches = [...matches];
      
      if (req.query.team) {
        const teamId = req.query.team;
        filteredMatches = filteredMatches.filter(
          match => match.team1Id === teamId || match.team2Id === teamId
        );
      }
      
      if (req.query.status) {
        filteredMatches = filteredMatches.filter(
          match => match.status === req.query.status
        );
      }
      
      if (req.query.format) {
        filteredMatches = filteredMatches.filter(
          match => match.format === req.query.format
        );
      }
      
      res.status(200).json({
        success: true,
        count: filteredMatches.length,
        matches: filteredMatches
      });
    } catch (error) {
      console.error("Error fetching matches:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch matches"
      });
    }
  },

  // Get match by ID
  getMatchById: async (req, res) => {
    try {
      const matchId = req.params.id;
      const match = matches.find(m => m.id === matchId);
      
      if (!match) {
        return res.status(404).json({
          success: false,
          message: "Match not found"
        });
      }
      
      res.status(200).json({
        success: true,
        match
      });
    } catch (error) {
      console.error("Error fetching match:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch match"
      });
    }
  },

  // Update match score
  updateMatchScore: async (req, res) => {
    try {
      const matchId = req.params.id;
      const { teamId, runs, wickets, overs } = req.body;
      
      // Validate request
      if (!teamId || (runs === undefined && wickets === undefined && overs === undefined)) {
        return res.status(400).json({
          success: false,
          message: "Invalid score update data"
        });
      }
      
      // Find the match
      const matchIndex = matches.findIndex(m => m.id === matchId);
      if (matchIndex === -1) {
        return res.status(404).json({
          success: false,
          message: "Match not found"
        });
      }
      
      const match = matches[matchIndex];
      
      // Check if user has permission to update (match creator or team owner)
      if (match.createdBy !== req.user.id) {
        return res.status(403).json({
          success: false,
          message: "Unauthorized to update this match score"
        });
      }
      
      // Check which team to update
      const teamKey = match.team1Id === teamId ? "team1" : 
                     match.team2Id === teamId ? "team2" : null;
      
      if (!teamKey) {
        return res.status(400).json({
          success: false,
          message: "Invalid team ID for this match"
        });
      }
      
      // Update score
      if (runs !== undefined) match.scores[teamKey].runs = runs;
      if (wickets !== undefined) match.scores[teamKey].wickets = wickets;
      if (overs !== undefined) match.scores[teamKey].overs = overs;
      
      // Save updated match
      matches[matchIndex] = match;
      
      res.status(200).json({
        success: true,
        message: "Match score updated successfully",
        match
      });
    } catch (error) {
      console.error("Error updating match score:", error);
      res.status(500).json({
        success: false,
        message: "Failed to update match score"
      });
    }
  },

  // Update match status
  updateMatchStatus: async (req, res) => {
    try {
      const matchId = req.params.id;
      const { status } = req.body;
      
      // Validate status
      const validStatuses = ["scheduled", "in-progress", "completed", "abandoned"];
      if (!status || !validStatuses.includes(status)) {
        return res.status(400).json({
          success: false,
          message: `Invalid status. Must be one of: ${validStatuses.join(", ")}`
        });
      }
      
      // Find the match
      const matchIndex = matches.findIndex(m => m.id === matchId);
      if (matchIndex === -1) {
        return res.status(404).json({
          success: false,
          message: "Match not found"
        });
      }
      
      const match = matches[matchIndex];
      
      // Check if user has permission (match creator)
      if (match.createdBy !== req.user.id) {
        return res.status(403).json({
          success: false,
          message: "Unauthorized to update this match status"
        });
      }
      
      // Update status
      match.status = status;
      
      // Save updated match
      matches[matchIndex] = match;
      
      res.status(200).json({
        success: true,
        message: "Match status updated successfully",
        match
      });
    } catch (error) {
      console.error("Error updating match status:", error);
      res.status(500).json({
        success: false,
        message: "Failed to update match status"
      });
    }
  },

  // Delete match
  deleteMatch: async (req, res) => {
    try {
      const matchId = req.params.id;
      
      // Find the match
      const matchIndex = matches.findIndex(m => m.id === matchId);
      if (matchIndex === -1) {
        return res.status(404).json({
          success: false,
          message: "Match not found"
        });
      }
      
      const match = matches[matchIndex];
      
      // Check if user has permission (match creator)
      if (match.createdBy !== req.user.id) {
        return res.status(403).json({
          success: false,
          message: "Unauthorized to delete this match"
        });
      }
      
      // Delete match
      matches.splice(matchIndex, 1);
      
      res.status(200).json({
        success: true,
        message: "Match deleted successfully"
      });
    } catch (error) {
      console.error("Error deleting match:", error);
      res.status(500).json({
        success: false,
        message: "Failed to delete match"
      });
    }
  }
};

module.exports = matchController;