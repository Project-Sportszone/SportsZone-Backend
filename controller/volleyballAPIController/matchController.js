const axios = require("axios");
const { Match, MatchConstants } = require("../../models/volleyballModel/match");
const Team = require("../../models/volleyballModel/teams");
const User = require("../../models/userModel/userModel");

const matchController = {
  createMatch: async (req, res) => {
    try {
      const { title, format, venue, matchDate, team1Id, team2Id, scorers } =
        req.body;

      if (!title || !format || !venue || !matchDate || !team1Id || !team2Id) {
        return res.status(400).json({
          success: false,
          message: "Missing required fields",
        });
      }

      if (!Object.values(MatchConstants.MATCH_FORMAT).includes(format)) {
        return res.status(400).json({
          success: false,
          message: "Invalid match format",
        });
      }

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

      const team1Players = team1.members.map((member) => ({
        player: member.user._id,
        name: member.user.name,
        position: member.position || null,
      }));

      const team2Players = team2.members.map((member) => ({
        player: member.user._id,
        name: member.user.name,
        position: member.position || null,
      }));

      let scorersList = [];
      if (scorers && Array.isArray(scorers)) {
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
        scorers: scorersList,
        createdBy: req.user.userId,
        commentary: [
          {
            time: new Date(),
            text: `Match created: ${team1.name} vs ${team2.name} at ${venue}`,
            type: "start",
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

  getAllTeams: async (req, res) => {
    try {
      const response = await axios.get(
        "http://localhost:3000/api/volleyball/teams/all-teams",
        {
          headers: {
            Authorization: req.headers.authorization,
          },
        }
      );

      res.status(200).json(response.data);
    } catch (error) {
      console.error("Error fetching teams:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch teams",
      });
    }
  },

  getAllMatches: async (req, res) => {
    try {
      const { status, format, team, date, upcoming } = req.query;

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
            MatchConstants.MATCH_STATUS.LIVE,
          ],
        };
      }

      const matches = await Match.find(query)
        .select(
          "title status format venue matchDate team1.name team1.logo team2.name team2.logo commentary result"
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

  getMatchById: async (req, res) => {
    try {
      const matchId = req.params.id;

      const match = await Match.findById(matchId)
        .populate("createdBy", "name")
        .populate("scorers.user", "name")
        .populate("team1.id", "name")
        .populate("team2.id", "name")
        .populate("result.winner", "name");

      if (!match) {
        return res.status(404).json({
          success: false,
          message: "Match not found",
        });
      }

      const isScorer = match.scorers.some(
        (scorer) => scorer.user._id.toString() === req.user.userId.toString()
      );

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

  updateMatchStatus: async (req, res) => {
    try {
      const { id: matchId } = req.params;
      const { status } = req.body;

      if (!Object.values(MatchConstants.MATCH_STATUS).includes(status)) {
        return res.status(400).json({
          success: false,
          message: "Invalid match status",
        });
      }

      const match = await Match.findById(matchId);
      if (!match) {
        return res.status(404).json({
          success: false,
          message: "Match not found",
        });
      }

      const isScorer = match.scorers.some(
        (scorer) => scorer.user.toString() === req.user.userId.toString()
      );

      if (!isScorer) {
        return res.status(403).json({
          success: false,
          message: "Only designated scorers can update the match status",
        });
      }

      match.status = status;
      await match.save();

      res.status(200).json({
        success: true,
        message: "Match status updated successfully",
        match,
      });
    } catch (error) {
      console.error("Error updating match status:", error);
      res.status(500).json({
        success: false,
        message: "Failed to update match status",
        error: error.message,
      });
    }
  },

  deleteMatch: async (req, res) => {
    try {
      const matchId = req.params.id;

      const match = await Match.findById(matchId);
      if (!match) {
        return res.status(404).json({
          success: false,
          message: "Match not found",
        });
      }

      if (match.createdBy.toString() !== req.user.userId.toString()) {
        return res.status(403).json({
          success: false,
          message: "Unauthorized to delete this match",
        });
      }

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
