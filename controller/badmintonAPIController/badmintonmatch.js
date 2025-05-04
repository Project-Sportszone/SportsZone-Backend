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

  // Update game scores point-by-point with dynamic playerScoredId
  updatePointScore: async (req, res) => {
    try {
      const matchId = req.params.id;
      const { playerScoredId } = req.body; // expects player ID string

      if (!playerScoredId) {
        return res.status(400).json({
          success: false,
          message: "playerScoredId is required",
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
          message: "Only designated scorers can update the score",
        });
      }

      // Initialize current game if none
      if (!match.currentGame) {
        match.currentGame = {
          gameNumber: 1,
          player1Score: 0,
          player2Score: 0,
          winner: null,
        };
      }

      // Determine which player scored and their team
      let playerScoredKey = null;
      let teamScoredKey = null;
      if (match.player1.id.toString() === playerScoredId.toString()) {
        playerScoredKey = "player1";
        teamScoredKey = "team1";
      } else if (match.player2.id.toString() === playerScoredId.toString()) {
        playerScoredKey = "player2";
        teamScoredKey = "team2";
      } else {
        return res.status(400).json({
          success: false,
          message: "playerScoredId does not belong to any player in the match",
        });
      }

      // Update score for the player who scored
      if (playerScoredKey === "player1") {
        match.currentGame.player1Score += 1;
      } else {
        match.currentGame.player2Score += 1;
      }

      // Add commentary for the point scored
      const scoringTeamName =
        teamScoredKey === "team1" ? match.team1.name : match.team2.name;
      match.commentary.push({
        time: new Date(),
        text: `Point scored by player ${playerScoredId} for team ${scoringTeamName}`,
        type: "point",
      });

      // Check if game is won
      const p1 = match.currentGame.player1Score;
      const p2 = match.currentGame.player2Score;
      const maxScore = 30;
      let gameWinner = null;

      if ((p1 >= 21 || p2 >= 21) && Math.abs(p1 - p2) >= 2) {
        gameWinner = p1 > p2 ? match.player1.id : match.player2.id;
      }

      if (gameWinner) {
        match.currentGame.winner = gameWinner;
        // Push current game to games array
        match.games.push(match.currentGame);

        // Reset current game for next game if match not ended
        match.currentGame = {
          gameNumber: match.games.length + 1,
          player1Score: 0,
          player2Score: 0,
          winner: null,
        };

        // Check if match is won (best of 3)
        const player1GamesWon = match.games.filter(
          (g) => g.winner && g.winner.toString() === match.player1.id.toString()
        ).length;
        const player2GamesWon = match.games.filter(
          (g) => g.winner && g.winner.toString() === match.player2.id.toString()
        ).length;

        const gamesNeededToWin = 2; // best of 3

        if (
          player1GamesWon === gamesNeededToWin ||
          player2GamesWon === gamesNeededToWin
        ) {
          match.status = MatchConstants.MATCH_STATUS.COMPLETED;
          match.result = {
            winner:
              player1GamesWon === gamesNeededToWin
                ? match.player1.id
                : match.player2.id,
            playerOfMatch: null,
          };
        }
      }

      match.lastScorerAction = {
        user: req.user.userId,
        time: new Date(),
        action: `Updated point score for player ${playerScoredKey} in team ${teamScoredKey}`,
      };

      await match.save();

      res.status(200).json({
        success: true,
        message: "Point score updated successfully",
        match,
      });
    } catch (error) {
      console.error("Error updating point score:", error);
      res.status(500).json({
        success: false,
        message: "Failed to update point score",
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
