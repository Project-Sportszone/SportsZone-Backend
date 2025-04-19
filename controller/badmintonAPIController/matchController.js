const axios = require("axios");
const { Match, MatchConstants } = require("../../models/badmintonModel/match");
const Team = require("../../models/badmintonModel/teams");
const User = require("../../models/userModel/userModel");

const matchController = {
  createMatch: async (req, res) => {
    try {
      const { title, format, venue, matchDate, player1Id, player2Id, scorers } =
        req.body;

      if (
        !title ||
        !format ||
        !venue ||
        !matchDate ||
        !player1Id ||
        !player2Id
      ) {
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

      const player1 = await Team.findById(player1Id)
        .populate("members.user", "name email")
        .populate("captain", "name email")
        .populate("viceCaptain", "name email");

      const player2 = await Team.findById(player2Id)
        .populate("members.user", "name email")
        .populate("captain", "name email")
        .populate("viceCaptain", "name email");

      if (!player1 || !player2) {
        return res.status(404).json({
          success: false,
          message: "One or both players/teams not found",
        });
      }

      // Check if user has permission to create a match for player1
      const isPlayer1Admin = player1.members.some(
        (member) =>
          member.user._id.toString() === req.user.userId.toString() &&
          member.role === "admin"
      );
      const isPlayer1Owner =
        player1.owner.toString() === req.user.userId.toString();

      if (!isPlayer1Admin && !isPlayer1Owner) {
        return res.status(403).json({
          success: false,
          message:
            "You don't have permission to create a match for the first player/team",
        });
      }

      const player1Members = player1.members.map((member) => ({
        player: member.user._id,
        name: member.user.name,
        position: member.position || null,
      }));

      const player2Members = player2.members.map((member) => ({
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
        player1: {
          id: player1._id,
          name: player1.name,
          logo: player1.logo,
          members: player1Members,
        },
        player2: {
          id: player2._id,
          name: player2.name,
          logo: player2.logo,
          members: player2Members,
        },
        scorers: scorersList,
        createdBy: req.user.userId,
        commentary: [
          {
            time: new Date(),
            text: `Match created: ${player1.name} vs ${player2.name} at ${venue}`,
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
        "http://localhost:3000/api/badminton/teams/all-teams",
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
      const { status, format, player, date, upcoming } = req.query;

      const query = {};

      if (status) {
        query.status = status;
      }

      if (format) {
        query.format = format;
      }

      if (player) {
        query.$or = [{ "player1.id": player }, { "player2.id": player }];
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
          "title status format venue matchDate player1.name player1.logo player2.name player2.logo commentary result"
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
        .populate("player1.id", "name")
        .populate("player2.id", "name")
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
