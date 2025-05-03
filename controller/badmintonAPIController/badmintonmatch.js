const { Match, MatchConstants } = require("../../models/badmintonModel/match");
const Team = require("../../models/badmintonModel/teams");
const User = require("../../models/userModel/userModel");

// Badminton match controller
const badmintonMatchController = {
  // Update match status (e.g., live, completed, abandoned)
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

      match.commentary.push({
        time: new Date(),
        text: `Match status updated to ${status}`,
        type: "regular",
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

  // Update match game scores
  updateGameScore: async (req, res) => {
    try {
      const matchId = req.params.id;
      const { gameNumber, player1Score, player2Score } = req.body;

      if (
        typeof gameNumber !== "number" ||
        typeof player1Score !== "number" ||
        typeof player2Score !== "number"
      ) {
        return res.status(400).json({
          success: false,
          message: "Game number and scores must be numbers",
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
          message: "Only designated scorers can update game scores",
        });
      }

      // Find the game or create if not exists
      let game = match.games.find((g) => g.gameNumber === gameNumber);
      if (!game) {
        game = {
          gameNumber,
          player1Score,
          player2Score,
          winner: null,
        };
        match.games.push(game);
      } else {
        game.player1Score = player1Score;
        game.player2Score = player2Score;
      }

      // Determine winner if any
      if (player1Score > player2Score) {
        game.winner = match.player1.id;
      } else if (player2Score > player1Score) {
        game.winner = match.player2.id;
      } else {
        game.winner = null;
      }

      match.lastScorerAction = {
        user: req.user.userId,
        time: new Date(),
        action: `Updated score for game ${gameNumber}`,
      };

      await match.save();

      res.status(200).json({
        success: true,
        message: "Game score updated successfully",
        match,
      });
    } catch (error) {
      console.error("Error updating game score:", error);
      res.status(500).json({
        success: false,
        message: "Failed to update game score",
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

      if (result) {
        match.result = {
          winner: result.winner,
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

module.exports = badmintonMatchController;
