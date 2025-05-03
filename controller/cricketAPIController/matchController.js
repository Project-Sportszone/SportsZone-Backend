const axios = require("axios");
const {Match} = require("../../models/cricketModel/match"); // Assuming you have a Match model

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
  // createMatch: async (matchData) => {
  //   try {
  //     // Create a new match document in the database
  //     const newMatch = new Match(matchData);
  //     const savedMatch = await newMatch.save();
  //     return savedMatch;
  //   } catch (error) {
  //     console.error("Error creating match:", error);
  //     throw new Error("Failed to create match");
  //   }
  // },

  // Get all matches
  getAllMatches: async (req, res) => {
    try {
      // Build the query based on filters
      const query = {};
      
      if (req.query.team) {
        const teamId = req.query.team;
        query.$or = [{ team1Id: teamId }, { team2Id: teamId }];
      }
      
      if (req.query.status) {
        query.status = req.query.status;
      }
      
      if (req.query.format) {
        query.format = req.query.format;
      }
      
      // Execute query on the database
      const matches = await Match.find(query);
      
      res.status(200).json({
        success: true,
        count: matches.length,
        matches
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
      const match = await Match.findById(matchId)
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
      const match = await Match.findById(matchId);
      if (!match) {
        return res.status(404).json({
          success: false,
          message: "Match not found"
        });
      }
      
      // Check if user has permission to update (match creator or team owner)
      if (match.createdBy.toString() !== req.user.id) {
        return res.status(403).json({
          success: false,
          message: "Unauthorized to update this match score"
        });
      }
      
      // Check which team to update
      const teamKey = match.team1Id.toString() === teamId ? "team1" : 
                     match.team2Id.toString() === teamId ? "team2" : null;
      
      if (!teamKey) {
        return res.status(400).json({
          success: false,
          message: "Invalid team ID for this match"
        });
      }
      
      // Create update object
      const updateData = {};
      
      if (runs !== undefined) updateData[`scores.${teamKey}.runs`] = runs;
      if (wickets !== undefined) updateData[`scores.${teamKey}.wickets`] = wickets;
      if (overs !== undefined) updateData[`scores.${teamKey}.overs`] = overs;
      
      // Update match in database
      const updatedMatch = await Match.findByIdAndUpdate(
        matchId,
        { $set: updateData },
        { new: true, runValidators: true }
      );
      
      res.status(200).json({
        success: true,
        message: "Match score updated successfully",
        match: updatedMatch
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
      const validStatuses = ["upcoming","toss","innings_break","delayed","rain_interrupted","completed", "abandoned","live",];
      if (!status || !validStatuses.includes(status)) {
        return res.status(400).json({
          success: false,
          message: `Invalid status. Must be one of: ${validStatuses.join(", ")}`
        });
      }
      // Find the match
      const match = await Match.findById(matchId);;
      if (!match) {
        return res.status(404).json({
          success: false,
          message: "Match not found"
        });
      }
      // Check if user has permission (match creator)
      if (match.createdBy.toString() !== req.user.userId) {
        return res.status(403).json({
          success: false,
          message: "Unauthorized to update this match status"
        });
      }
      
      // Update status in database
      const updatedMatch = await Match.findByIdAndUpdate(
        matchId,
        { status },
        { new: true, runValidators: true }
      );
      
      res.status(200).json({
        success: true,
        message: "Match status updated successfully",
        match: updatedMatch
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
      const match = await Match.findById(matchId);
      if (!match) {
        return res.status(404).json({
          success: false,
          message: "Match not found"
        });
      }
      
      // Check if user has permission (match creator)
      if (match.createdBy.toString() !== req.user.id) {
        return res.status(403).json({
          success: false,
          message: "Unauthorized to delete this match"
        });
      }
      
      // Delete match from database
      await Match.findByIdAndDelete(matchId);
      
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