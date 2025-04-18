const axios = require("axios");
const { Match, MatchConstants } = require("../../models/cricketModel/match");
const Team = require("../../models/cricketModel/teams");
const User = require("../../models/userModel/userModel");

// This would typically use a database model
// For this example, we'll use an in-memory array for matches
let matches = [];

const matchController = {
  createMatch: async (req, res) => {
    try {
      const {
        title,
        format,
        venue,
        matchDate,
        team1Id,
        team2Id,
        scorers,
        maxOvers,
      } = req.body;

      // Validate required fields
      if (!title || !format || !venue || !matchDate || !team1Id || !team2Id) {
        return res.status(400).json({
          success: false,
          message: "Missing required fields",
        });
      }

      // Validate format
      if (!Object.values(MatchConstants.MATCH_FORMAT).includes(format)) {
        return res.status(400).json({
          success: false,
          message: "Invalid match format",
        });
      }

      // Fetch team details
      const team1 = await Team.findById(team1Id)
        .populate("members.user", "name email")
        .populate("captain", "name email")
        .populate("viceCaptain", "name email");

      const team2 = await Team.findById(team2Id)
        .populate("members.user", "name email")
        .populate("captain", "name email")
        .populate("viceCaptain", "name email");

      if (!team1 || !team2) {
        return res.status(404).json({
          success: false,
          message: "One or both teams not found",
        });
      }

      // Check if user has permission to create a match for team1
      const isTeam1Admin = team1.members.some(
        (member) =>
          member.user._id.toString() === req.user.userId.toString() &&
          member.role === "admin"
      );
      const isTeam1Owner =
        team1.owner.toString() === req.user.userId.toString();

      if (!isTeam1Admin && !isTeam1Owner) {
        return res.status(403).json({
          success: false,
          message:
            "You don't have permission to create a match for the first team",
        });
      }

      // Set match players based on team members
      const team1Players = team1.members.map((member) => ({
        player: member.user._id,
        name: member.user.name,
        isCaptain:
          team1.captain &&
          team1.captain._id.toString() === member.user._id.toString(),
        isWicketkeeper: false, // Default, would be set manually later
      }));

      const team2Players = team2.members.map((member) => ({
        player: member.user._id,
        name: member.user.name,
        isCaptain:
          team2.captain &&
          team2.captain._id.toString() === member.user._id.toString(),
        isWicketkeeper: false, // Default, would be set manually later
      }));

      // Determine default max overs based on format
      let defaultMaxOvers;
      switch (format) {
        case MatchConstants.MATCH_FORMAT.T20:
          defaultMaxOvers = 20;
          break;
        case MatchConstants.MATCH_FORMAT.ODI:
          defaultMaxOvers = 50;
          break;
        case MatchConstants.MATCH_FORMAT.TEST:
          defaultMaxOvers = null; // No limit for Test
          break;
        default:
          defaultMaxOvers = 20;
      }

      // Process scorers
      let scorersList = [];
      if (scorers && Array.isArray(scorers)) {
        // Verify each scorer exists
        for (const scorerId of scorers) {
          const scorer = await User.findById(scorerId).select("name");
          if (scorer) {
            scorersList.push({
              user: scorer._id,
              name: scorer.name,
            });
          }
        }
      }

      // Include creator as a scorer by default if not already added
      if (
        !scorersList.some(
          (scorer) => scorer.user.toString() === req.user.userId.toString()
        )
      ) {
        const creator = await User.findById(req.user.userId).select("name");
        if (creator) {
          scorersList.push({
            user: creator._id,
            name: creator.name,
          });
        }
      }

      // Create innings structure
      const initialInnings = {
        number: 1,
        battingTeam: team1._id,
        bowlingTeam: team2._id,
        runs: 0,
        wickets: 0,
        overs: 0,
        balls: 0,
        extras: {
          wides: 0,
          noBalls: 0,
          byes: 0,
          legByes: 0,
          penalty: 0,
        },
        totalExtras: 0,
        maxOvers: maxOvers || defaultMaxOvers,
        battingStats: [],
        bowlingStats: [],
        fallOfWickets: [],
      };

      // Create the match
      const match = new Match({
        title,
        format,
        venue,
        matchDate: new Date(matchDate),
        status: MatchConstants.MATCH_STATUS.UPCOMING,
        team1: {
          id: team1._id,
          name: team1.name,
          logo: team1.logo,
          players: team1Players,
        },
        team2: {
          id: team2._id,
          name: team2.name,
          logo: team2.logo,
          players: team2Players,
        },
        currentInnings: 1,
        innings: [initialInnings],
        scorers: scorersList,
        battingTeam: team1._id,
        bowlingTeam: team2._id,
        createdBy: req.user.userId,
        commentary: [
          {
            over: 0,
            ball: 0,
            innings: 1,
            text: `Match created: ${team1.name} vs ${team2.name} at ${venue}`,
            type: "start",
            time: new Date(),
          },
        ],
      });

      await match.save();

      res.status(201).json({
        success: true,
        message: "Match created successfully",
        match,
      });
    } catch (error) {
      console.error("Error creating match:", error);
      res.status(500).json({
        success: false,
        message: "Failed to create match",
        error: error.message,
      });
    }
  },
  // Get all teams - Now fetching from the API endpoint
  getAllTeams: async (req, res) => {
    try {
      // Forward the request to the actual API endpoint
      const response = await axios.get(
        "http://localhost:3000/api/cricket/teams/all-teams",
        {
          headers: {
            Authorization: req.headers.authorization,
          },
        }
      );

      // Return the teams from the API
      res.status(200).json(response.data);
    } catch (error) {
      console.error("Error fetching teams:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch teams",
      });
    }
  },

  // Get all matches with filter
  getAllMatches: async (req, res) => {
    try {
      const { status, format, team, date, upcoming } = req.query;

      // Build query
      const query = {};

      if (status) {
        query.status = status;
      }

      if (format) {
        query.format = format;
      }

      if (team) {
        query.$or = [{ "team1.id": team }, { "team2.id": team }];
      }

      if (date) {
        const startDate = new Date(date);
        startDate.setHours(0, 0, 0, 0);

        const endDate = new Date(date);
        endDate.setHours(23, 59, 59, 999);

        query.matchDate = {
          $gte: startDate,
          $lte: endDate,
        };
      }

      if (upcoming === "true") {
        query.matchDate = {
          $gte: new Date(),
        };
        query.status = {
          $in: [
            MatchConstants.MATCH_STATUS.UPCOMING,
            MatchConstants.MATCH_STATUS.TOSS,
          ],
        };
      }

      // Get matches with selected fields for list view
      const matches = await Match.find(query)
        .select(
          "title status format venue matchDate team1.name team1.logo team2.name team2.logo innings.runs innings.wickets innings.overs innings.balls currentInnings result toss"
        )
        .sort({ matchDate: -1 });

      res.status(200).json({
        success: true,
        count: matches.length,
        matches,
      });
    } catch (error) {
      console.error("Error fetching matches:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch matches",
        error: error.message,
      });
    }
  },

  // Get match by ID
  getMatchById: async (req, res) => {
    try {
      const matchId = req.params.id;

      const match = await Match.findById(matchId)
        .populate("createdBy", "name")
        .populate("scorers.user", "name")
        .populate("toss.winner", "name")
        .populate("battingTeam", "name")
        .populate("bowlingTeam", "name")
        .populate("result.winner", "name");

      if (!match) {
        return res.status(404).json({
          success: false,
          message: "Match not found",
        });
      }

      // Check if the user is a scorer for the match
      const isScorer = match.scorers.some(
        (scorer) => scorer.user._id.toString() === req.user.userId.toString()
      );

      // Include the isScorer flag in the response
      res.status(200).json({
        success: true,
        match,
        isScorer,
      });
    } catch (error) {
      console.error("Error fetching match:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch match",
        error: error.message,
      });
    }
  },

  // Update match score
  updateMatchScore: async (req, res) => {
    try {
      const { id, teamId } = req.params;
      const { runs, wickets, overs } = req.body;

      // Validate request
      if (
        !teamId ||
        (runs === undefined && wickets === undefined && overs === undefined)
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid score update data",
        });
      }

      // Find the match in MongoDB
      const match = await Match.findById(id);
      if (!match) {
        return res.status(404).json({
          success: false,
          message: "Match not found",
        });
      }

      // Check if match is live or not
      if (match.status !== "live") {
        return res.status(404).json({
          success: false,
          message: "Match is not live",
        });
      }

      // Ensure user is authenticated
      if (!req.user || !req.user.userId) {
        return res
          .status(401)
          .json({ success: false, message: "User authentication required" });
      }

      // Check if user has permission to update (match creator or team owner)
      if (String(match.createdBy) !== String(req.user.userId)) {
        return res.status(403).json({
          success: false,
          message: "Unauthorized to update this match score",
        });
      }

      // Determine which team's score to update
      let teamKey = null;
      if (String(match.team1.id) === String(teamId)) teamKey = "team1";
      if (String(match.team2.id) === String(teamId)) teamKey = "team2";

      if (!teamKey) {
        return res.status(400).json({
          success: false,
          message: "Invalid team ID for this match",
        });
      }

      // Update match score
      if (runs !== undefined) match.innings[0].runs = runs;
      if (wickets !== undefined) match.innings[0].wickets = wickets;
      if (overs !== undefined) match.innings[0].overs = overs;

      // Save updated match
      await match.save();

      res.status(200).json({
        success: true,
        message: "Match score updated successfully",
        match,
      });
    } catch (error) {
      console.error("Error updating match score:", error);
      res.status(500).json({
        success: false,
        message: "Failed to update match score",
      });
    }
  },

  // Update match status
  updateMatchStatus: async (req, res) => {
    try {
      const { id: matchId } = req.params;
      const { status } = req.body;

      // Validate status
      const validStatuses = ["innings_break", "delayed", "abandoned"];
      if (!status || !validStatuses.includes(status)) {
        return res.status(400).json({
          success: false,
          message: `Invalid status. Must be one of: ${validStatuses.join(
            ", "
          )}`,
        });
      }

      // Find match in MongoDB
      const match = await Match.findById(matchId);
      if (!match) {
        return res
          .status(404)
          .json({ success: false, message: "Match not found" });
      }

      // Ensure user is authenticated
      if (!req.user || !req.user.userId) {
        return res
          .status(401)
          .json({ success: false, message: "User authentication required" });
      }

      // Check if user is match creator (Convert both to string before comparison)
      if (String(match.createdBy) !== String(req.user.userId)) {
        return res.status(403).json({
          success: false,
          message: "Unauthorized to update this match status",
        });
      }

      // Update match status
      match.status = status;
      await match.save();

      res.status(200).json({
        success: true,
        message: "Match status updated successfully",
        match,
      });
    } catch (error) {
      console.error("Error updating match status:", error);
      res
        .status(500)
        .json({ success: false, message: "Failed to update match status" });
    }
  },

  // Delete match
  deleteMatch: async (req, res) => {
    try {
      const matchId = req.params.id;

      // Find the match (with await)
      const match = await Match.findById(matchId);
      if (!match) {
        return res.status(404).json({
          success: false,
          message: "Match not found",
        });
      }

      // Check if the user has permission (match creator)
      if (String(match.createdBy) !== String(req.user.userId)) {
        return res.status(403).json({
          success: false,
          message: "Unauthorized to delete this match",
        });
      }

      // Delete the match
      await Match.findByIdAndDelete(matchId);

      res.status(200).json({
        success: true,
        message: "Match deleted successfully",
      });
    } catch (error) {
      console.error("Error deleting match:", error);
      res.status(500).json({
        success: false,
        message: "Failed to delete match",
      });
    }
  },
};

module.exports = matchController;
