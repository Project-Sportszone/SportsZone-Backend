const { Match, MatchConstants } = require("../../models/footballModel/match");
const Team = require("../../models/footballModel/teams");
const User = require("../../models/userModel/userModel");

// Football match controller
const footballMatchController = {
  // Update match status (e.g., start first half, halftime, second half, extra time, penalties)
  updateMatchStatus: async (req, res) => {
    try {
      const matchId = req.params.id;
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

      let commentaryText = "";
      switch (status) {
        case MatchConstants.MATCH_STATUS.FIRST_HALF:
          commentaryText = "First half started.";
          break;
        case MatchConstants.MATCH_STATUS.HALF_TIME:
          commentaryText = "Half time break.";
          break;
        case MatchConstants.MATCH_STATUS.SECOND_HALF:
          commentaryText = "Second half started.";
          break;
        case MatchConstants.MATCH_STATUS.EXTRA_TIME:
          commentaryText = "Extra time started.";
          break;
        case MatchConstants.MATCH_STATUS.PENALTIES:
          commentaryText = "Penalty shootout started.";
          break;
        case MatchConstants.MATCH_STATUS.COMPLETED:
          commentaryText = "Match completed.";
          break;
        case MatchConstants.MATCH_STATUS.ABANDONED:
          commentaryText = "Match abandoned.";
          break;
        case MatchConstants.MATCH_STATUS.DELAYED:
          commentaryText = "Match delayed.";
          break;
        default:
          commentaryText = `Match status updated to ${status}.`;
      }

      match.commentary.push({
        minute: 0,
        text: commentaryText,
        type: "start",
        time: new Date(),
      });

      match.lastScorerAction = {
        user: req.user.userId,
        time: new Date(),
        action: `Updated match status to ${status}`,
      };

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

  // Add scorer to match
  addScorer: async (req, res) => {
    try {
      const matchId = req.params.id;
      const memberId = req.params.memberId;

      if (!memberId) {
        return res.status(400).json({
          success: false,
          message: "User ID is required",
        });
      }

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
          message: "Only the match creator can add scorers",
        });
      }

      const isAlreadyScorer = match.scorers.some(
        (scorer) => scorer.user.toString() === memberId.toString()
      );

      if (isAlreadyScorer) {
        return res.status(400).json({
          success: false,
          message: "User is already a scorer for this match",
        });
      }

      const user = await User.findById(memberId).select("name");
      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      match.scorers.push({
        user: user._id,
        name: user.name,
        addedAt: new Date(),
      });

      match.lastScorerAction = {
        user: req.user.userId,
        time: new Date(),
        action: `Added ${user.name} as scorer`,
      };

      await match.save();

      res.status(200).json({
        success: true,
        message: "Scorer added successfully",
        match,
      });
    } catch (error) {
      console.error("Error adding scorer:", error);
      res.status(500).json({
        success: false,
        message: "Failed to add scorer",
        error: error.message,
      });
    }
  },

  // Remove scorer from match
  removeScorer: async (req, res) => {
    try {
      const matchId = req.params.id;
      const scorerId = req.params.scorerId;

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
          message: "Only the match creator can remove scorers",
        });
      }

      const scorerIndex = match.scorers.findIndex(
        (scorer) => scorer.user.toString() === scorerId
      );

      if (scorerIndex === -1) {
        return res.status(400).json({
          success: false,
          message: "User is not a scorer for this match",
        });
      }

      const scorerName = match.scorers[scorerIndex].name;

      match.scorers.splice(scorerIndex, 1);

      match.lastScorerAction = {
        user: req.user.userId,
        time: new Date(),
        action: `Removed ${scorerName} as scorer`,
      };

      await match.save();

      res.status(200).json({
        success: true,
        message: "Scorer removed successfully",
        match,
      });
    } catch (error) {
      console.error("Error removing scorer:", error);
      res.status(500).json({
        success: false,
        message: "Failed to remove scorer",
        error: error.message,
      });
    }
  },

  // Update match events: goals, cards, substitutions
  updateMatchEvent: async (req, res) => {
    try {
      const matchId = req.params.id;
      const { eventType, eventData } = req.body;

      if (!eventType || !eventData) {
        return res.status(400).json({
          success: false,
          message: "Event type and event data are required",
        });
      }

      const match = await Match.findById(matchId);
      if (!match) {
        return res.status(404).json({
          success: false,
          message: "Match not found",
        });
      }

      // Check if user is a scorer for this match
      const isScorer = match.scorers.some(
        (scorer) => scorer.user.toString() === req.user.userId.toString()
      );

      if (!isScorer) {
        return res.status(403).json({
          success: false,
          message: "Only designated scorers can update match events",
        });
      }

      let commentaryText = "";
      switch (eventType) {
        case "goal":
          // Validate required fields for goal
          if (
            !eventData.team ||
            !eventData.player ||
            typeof eventData.minute !== "number"
          ) {
            return res.status(400).json({
              success: false,
              message: "Team, player, and minute are required for goal event",
            });
          }

          // Add goal to match
          match.goals.push({
            team: eventData.team,
            player: eventData.player,
            playerName: eventData.playerName || "",
            minute: eventData.minute,
            isOwnGoal: eventData.isOwnGoal || false,
            isPenalty: eventData.isPenalty || false,
            assistedBy: eventData.assistedBy || null,
          });

          // Dynamically update score for the team
          if (!match.score) {
            match.score = {
              team1: 0,
              team2: 0,
            };
          }

          if (eventData.team.toString() === match.player1.id.toString()) {
            match.score.team1 += 1;
          } else if (
            eventData.team.toString() === match.player2.id.toString()
          ) {
            match.score.team2 += 1;
          }

          commentaryText = `Goal scored by ${
            eventData.playerName || "Unknown"
          } at minute ${eventData.minute}.`;
          break;

        case "card":
          // Validate required fields for card
          if (
            !eventData.team ||
            !eventData.player ||
            typeof eventData.minute !== "number" ||
            !["yellow", "red", "second_yellow"].includes(eventData.type)
          ) {
            return res.status(400).json({
              success: false,
              message:
                "Team, player, minute, and valid card type are required for card event",
            });
          }

          // Add card to match
          match.cards.push({
            team: eventData.team,
            player: eventData.player,
            playerName: eventData.playerName || "",
            minute: eventData.minute,
            type: eventData.type,
          });

          commentaryText = `${eventData.type
            .replace("_", " ")
            .toUpperCase()} card shown to ${
            eventData.playerName || "Unknown"
          } at minute ${eventData.minute}.`;
          break;

        case "substitution":
          // Validate required fields for substitution
          if (
            !eventData.team ||
            !eventData.playerOut ||
            !eventData.playerIn ||
            typeof eventData.minute !== "number"
          ) {
            return res.status(400).json({
              success: false,
              message:
                "Team, playerOut, playerIn, and minute are required for substitution event",
            });
          }

          // Add substitution to match
          match.substitutions.push({
            team: eventData.team,
            playerOut: eventData.playerOut,
            playerOutName: eventData.playerOutName || "",
            playerIn: eventData.playerIn,
            playerInName: eventData.playerInName || "",
            minute: eventData.minute,
          });

          commentaryText = `Substitution at minute ${eventData.minute}: ${
            eventData.playerOutName || "Unknown"
          } out, ${eventData.playerInName || "Unknown"} in.`;
          break;

        default:
          return res.status(400).json({
            success: false,
            message: "Invalid event type",
          });
      }

      // Add commentary
      match.commentary.push({
        minute: eventData.minute || 0,
        text: commentaryText,
        type: eventType,
        time: new Date(),
      });

      // Update last scorer action
      match.lastScorerAction = {
        user: req.user.userId,
        time: new Date(),
        action: `Updated match event: ${eventType}`,
      };

      await match.save();

      res.status(200).json({
        success: true,
        message: "Match event updated successfully",
        match,
      });
    } catch (error) {
      console.error("Error updating match event:", error);
      res.status(500).json({
        success: false,
        message: "Failed to update match event",
        error: error.message,
      });
    }
  },

  // End match / declare result
  endMatch: async (req, res) => {
    try {
      const matchId = req.params.id;
      const { result, playerOfMatch } = req.body;

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
          message: "Only designated scorers can end the match",
        });
      }

      match.status = MatchConstants.MATCH_STATUS.COMPLETED;
      match.endTime = new Date();

      if (result) {
        match.result = {
          winner: result.winner,
          winType: result.winType || "normal",
          playerOfMatch: result.playerOfMatch || null,
        };
      }

      match.lastScorerAction = {
        user: req.user.userId,
        time: new Date(),
        action: "Ended the match",
      };

      await match.save();

      res.status(200).json({
        success: true,
        message: "Match completed successfully",
        match,
      });
    } catch (error) {
      console.error("Error ending match:", error);
      res.status(500).json({
        success: false,
        message: "Error completing match",
        error: error.message,
      });
    }
  },
};

module.exports = footballMatchController;
