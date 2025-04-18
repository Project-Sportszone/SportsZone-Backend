const { Match, MatchConstants } = require("../../models/cricketModel/match");
const Team = require("../../models/cricketModel/teams");
const User = require("../../models/userModel/userModel");

// Helper function to calculate run rate
const calculateRunRate = (runs, overs, balls = 0) => {
  const totalOvers = overs + balls / 6;
  if (totalOvers === 0) return 0;
  return parseFloat((runs / totalOvers).toFixed(2));
};

// Helper function for DLS calculation - simplified for demo
// In a real app, you would use a more complex DLS library/algorithm
const calculateDLSTarget = (
  originalTarget,
  oversPlayed,
  oversTotal,
  wicketsLost
) => {
  // This is a simplified placeholder algorithm
  // Real DLS is much more complex with resource tables
  const resourcePercentage = (oversTotal - oversPlayed) / oversTotal;
  const wicketFactor = 1 - wicketsLost * 0.05; // Simple factor for wickets
  const revisedTarget = Math.ceil(
    originalTarget * resourcePercentage * wicketFactor
  );
  return Math.max(revisedTarget, 1); // Ensure target is at least 1
};

const matchScoringController = {
  // Update toss details
  updateToss: async (req, res) => {
    try {
      const matchId = req.params.id;
      const { winner, decision } = req.body;

      // Validate required fields
      if (!winner || !decision) {
        return res.status(400).json({
          success: false,
          message: "Winner and decision are required for toss update",
        });
      }

      // Validate decision
      if (decision !== "bat" && decision !== "bowl") {
        return res.status(400).json({
          success: false,
          message: "Decision must be either 'bat' or 'bowl'",
        });
      }

      // Get the match
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
          message: "Only designated scorers can update the toss",
        });
      }

      // Verify winner is one of the teams
      if (
        winner !== match.team1.id.toString() &&
        winner !== match.team2.id.toString()
      ) {
        return res.status(400).json({
          success: false,
          message: "Toss winner must be one of the teams in the match",
        });
      }

      // Update toss information
      match.toss = {
        winner,
        decision,
        time: new Date(),
      };

      // Update match status
      match.status = MatchConstants.MATCH_STATUS.TOSS;

      // Determine batting and bowling teams based on toss
      const team1BatsFirst =
        (winner === match.team1.id.toString() && decision === "bat") ||
        (winner === match.team2.id.toString() && decision === "bowl");

      match.battingTeam = team1BatsFirst ? match.team1.id : match.team2.id;
      match.bowlingTeam = team1BatsFirst ? match.team2.id : match.team1.id;

      // Update first innings
      match.innings[0].battingTeam = match.battingTeam;
      match.innings[0].bowlingTeam = match.bowlingTeam;

      // Add toss commentary
      const winnerName =
        winner === match.team1.id.toString()
          ? match.team1.name
          : match.team2.name;
      const loserName =
        winner === match.team1.id.toString()
          ? match.team2.name
          : match.team1.name;
      const battingTeamName = team1BatsFirst
        ? match.team1.name
        : match.team2.name;

      match.commentary.push({
        over: 0,
        ball: 0,
        innings: 1,
        text: `${winnerName} won the toss and elected to ${decision} first against ${loserName}. ${battingTeamName} will bat first.`,
        type: "start",
        time: new Date(),
      });

      // Update last scorer action
      match.lastScorerAction = {
        user: req.user.userId,
        time: new Date(),
        action: "Updated toss information",
      };

      await match.save();

      res.status(200).json({
        success: true,
        message: "Toss updated successfully",
        match,
      });
    } catch (error) {
      console.error("Error updating toss:", error);
      res.status(500).json({
        success: false,
        message: "Failed to update toss",
        error: error.message,
      });
    }
  },

  // Start the match
  startMatch: async (req, res) => {
    try {
      const matchId = req.params.id;

      // Get the match
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
          message: "Only designated scorers can start the match",
        });
      }

      // Check if toss has been done
      if (!match.toss || !match.toss.winner) {
        return res.status(400).json({
          success: false,
          message: "Toss must be completed before starting the match",
        });
      }

      // Update match status
      match.status = MatchConstants.MATCH_STATUS.LIVE;

      // Add match start commentary
      match.commentary.push({
        over: 0,
        ball: 0,
        innings: match.currentInnings,
        text: `Match started. ${
          match.innings[0].battingTeam.toString() === match.team1.id.toString()
            ? match.team1.name
            : match.team2.name
        } batting first.`,
        type: "start",
        time: new Date(),
      });

      // Update last scorer action
      match.lastScorerAction = {
        user: req.user.userId,
        time: new Date(),
        action: "Started the match",
      };

      await match.save();

      res.status(200).json({
        success: true,
        message: "Match started successfully",
        match,
      });
    } catch (error) {
      console.error("Error starting match:", error);
      res.status(500).json({
        success: false,
        message: "Failed to start match",
        error: error.message,
      });
    }
  },

  // Add scorer to match
  addScorer: async (req, res) => {
    try {
      const matchId = req.params.id;
      const memberId = req.params.memberId;

      // Validate user ID
      if (!memberId) {
        return res.status(400).json({
          success: false,
          message: "User ID is required",
        });
      }

      // Get the match
      const match = await Match.findById(matchId);
      if (!match) {
        return res.status(404).json({
          success: false,
          message: "Match not found",
        });
      }

      // Only match creator can add scorers
      if (match.createdBy.toString() !== req.user.userId.toString()) {
        return res.status(403).json({
          success: false,
          message: "Only the match creator can add scorers",
        });
      }

      // Check if the user is already a scorer
      const isAlreadyScorer = match.scorers.some(
        (scorer) => scorer.user.toString() === memberId.toString()
      );

      if (isAlreadyScorer) {
        return res.status(400).json({
          success: false,
          message: "User is already a scorer for this match",
        });
      }

      // Find user details
      const user = await User.findById(memberId).select("name");
      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      // Add scorer
      match.scorers.push({
        user: user._id,
        name: user.name,
        addedAt: new Date(),
      });

      // Update last action
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
  // Only match creator can remove scor
  // Remove scorer from match
  removeScorer: async (req, res) => {
    try {
      const matchId = req.params.id;
      const scorerId = req.params.scorerId;

      // Get the match
      const match = await Match.findById(matchId);
      if (!match) {
        return res.status(404).json({
          success: false,
          message: "Match not found",
        });
      }

      // Only match creator can remove scorers
      if (match.createdBy.toString() !== req.user.userId.toString()) {
        return res.status(403).json({
          success: false,
          message: "Only the match creator can remove scorers",
        });
      }

      // Check if the user is a scorer
      const scorerIndex = match.scorers.findIndex(
        (scorer) => scorer.user.toString() === scorerId
      );

      if (scorerIndex === -1) {
        return res.status(400).json({
          success: false,
          message: "User is not a scorer for this match",
        });
      }

      // Get scorer name for action log
      const scorerName = match.scorers[scorerIndex].name;

      // Remove scorer
      match.scorers.splice(scorerIndex, 1);

      // Update last action
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

  // Update live score
  updateScore: async (req, res) => {
    try {
      const matchId = req.params.id;
      const { runs, wicket, extra, batsman, bowler, dismissalType, fielder } =
        req.body;

      // Get the match
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
          message: "Only designated scorers can update the score",
        });
      }

      // Validate match status
      if (match.status !== MatchConstants.MATCH_STATUS.LIVE) {
        return res.status(400).json({
          success: false,
          message: "Match is not live. Cannot update score.",
        });
      }

      // Get current innings
      const currentInningsIndex = match.innings.findIndex(
        (innings) => innings.number === match.currentInnings
      );

      if (currentInningsIndex === -1) {
        return res.status(400).json({
          success: false,
          message: "Current innings not found",
        });
      }

      const currentInnings = match.innings[currentInningsIndex];

      // Process the ball
      let ballCommentary = "";
      let commentaryType = "regular";
      let runsOnThisBall = 0;

      // Handle extras
      if (extra) {
        switch (extra.type) {
          case "wide":
            currentInnings.extras.wides += 1;
            currentInnings.runs += 1;
            runsOnThisBall += 1;
            if (extra.runs) {
              currentInnings.extras.wides += extra.runs;
              currentInnings.runs += extra.runs;
              runsOnThisBall += extra.runs;
              ballCommentary = `Wide + ${extra.runs} runs`;
            } else {
              ballCommentary = "Wide";
            }
            break;

          case "noBall":
            currentInnings.extras.noBalls += 1;
            currentInnings.runs += 1;
            runsOnThisBall += 1;
            if (runs) {
              currentInnings.runs += runs;
              runsOnThisBall += runs;
              ballCommentary = `No ball + ${runs} runs`;
            } else {
              ballCommentary = "No ball";
            }
            break;

          case "bye":
            if (extra.runs) {
              currentInnings.extras.byes += extra.runs;
              currentInnings.runs += extra.runs;
              runsOnThisBall += extra.runs;
              ballCommentary = `${extra.runs} byes`;
            }
            // Increment ball count for byes
            if (!wicket) {
              currentInnings.balls++;
              if (currentInnings.balls === 6) {
                currentInnings.overs++;
                currentInnings.balls = 0;
              }
            }
            break;

          case "legBye":
            if (extra.runs) {
              currentInnings.extras.legByes += extra.runs;
              currentInnings.runs += extra.runs;
              runsOnThisBall += extra.runs;
              ballCommentary = `${extra.runs} leg byes`;
            }
            // Increment ball count for leg byes
            if (!wicket) {
              currentInnings.balls++;
              if (currentInnings.balls === 6) {
                currentInnings.overs++;
                currentInnings.balls = 0;
              }
            }
            break;

          case "penalty":
            if (extra.runs) {
              currentInnings.extras.penalty += extra.runs;
              currentInnings.runs += extra.runs;
              runsOnThisBall += extra.runs;
              ballCommentary = `${extra.runs} penalty runs`;
            }
            break;
        }

        // Update total extras
        currentInnings.totalExtras =
          currentInnings.extras.wides +
          currentInnings.extras.noBalls +
          currentInnings.extras.byes +
          currentInnings.extras.legByes +
          currentInnings.extras.penalty;
      }
      // Handle regular runs
      else if (runs !== undefined && !wicket) {
        currentInnings.runs += runs;
        runsOnThisBall = runs;

        if (runs === 4) {
          ballCommentary = "FOUR!";
          commentaryType = "boundary";
        } else if (runs === 6) {
          ballCommentary = "SIX!";
          commentaryType = "six";
        } else {
          ballCommentary = `${runs} run${runs !== 1 ? "s" : ""}`;
        }

        // Increment ball count for regular deliveries
        currentInnings.balls++;
        if (currentInnings.balls === 6) {
          currentInnings.overs++;
          currentInnings.balls = 0;
        }

        // Update batsman stats
        if (batsman && currentInnings.currentBatsmen) {
          // Find and update striker's stats
          const batsmanStatIndex = currentInnings.battingStats.findIndex(
            (stat) => stat.player.toString() === batsman.id
          );

          if (batsmanStatIndex !== -1) {
            currentInnings.battingStats[batsmanStatIndex].runs += runs;
            currentInnings.battingStats[batsmanStatIndex].balls += 1;

            // Update fours and sixes
            if (runs === 4) {
              currentInnings.battingStats[batsmanStatIndex].fours += 1;
            } else if (runs === 6) {
              currentInnings.battingStats[batsmanStatIndex].sixes += 1;
            }

            // Update strike rate
            const batsmanStat = currentInnings.battingStats[batsmanStatIndex];
            batsmanStat.strikeRate = parseFloat(
              ((batsmanStat.runs / batsmanStat.balls) * 100).toFixed(2)
            );
          }
        }

        // Update bowler stats
        if (bowler && currentInnings.currentBowler) {
          const bowlerStatIndex = currentInnings.bowlingStats.findIndex(
            (stat) => stat.player.toString() === bowler.id
          );

          if (bowlerStatIndex !== -1) {
            currentInnings.bowlingStats[bowlerStatIndex].runs += runs;
            currentInnings.bowlingStats[bowlerStatIndex].balls += 1;

            // Update overs
            const bowlerStat = currentInnings.bowlingStats[bowlerStatIndex];
            bowlerStat.overs = Math.floor(bowlerStat.balls / 6);
            bowlerStat.balls = bowlerStat.balls % 6;

            // Update economy
            const totalOvers = bowlerStat.overs + bowlerStat.balls / 6;
            bowlerStat.economy = parseFloat(
              (bowlerStat.runs / totalOvers).toFixed(2)
            );
          }
        }
      }

      // Handle wicket
      if (wicket && batsman) {
        currentInnings.wickets++;
        commentaryType = "wicket";

        // Update batsman stats
        const batsmanStatIndex = currentInnings.battingStats.findIndex(
          (stat) => stat.player.toString() === batsman.id
        );

        if (batsmanStatIndex !== -1) {
          currentInnings.battingStats[batsmanStatIndex].dismissalType =
            dismissalType;

          // Add fielder and bowler if applicable
          if (
            fielder &&
            ["caught", "stumped", "run_out"].includes(dismissalType)
          ) {
            currentInnings.battingStats[batsmanStatIndex].fielder = fielder.id;
          }

          if (
            bowler &&
            ["bowled", "caught", "lbw", "stumped"].includes(dismissalType)
          ) {
            currentInnings.battingStats[batsmanStatIndex].bowler = bowler.id;
          }

          // Record out at score
          currentInnings.battingStats[batsmanStatIndex].outAt =
            currentInnings.runs;

          // Add to fall of wickets
          currentInnings.fallOfWickets.push({
            wicketNumber: currentInnings.wickets,
            runs: currentInnings.runs,
            overs: currentInnings.overs,
            balls: currentInnings.balls,
            player: batsman.id,
            playerName: batsman.name,
            dismissalType: dismissalType,
            bowler: bowler ? bowler.id : null,
            fielder: fielder ? fielder.id : null,
          });

          // Generate wicket commentary
          let wicketDescription = "";
          switch (dismissalType) {
            case "bowled":
              wicketDescription = `${batsman.name} b ${bowler.name}`;
              break;
            case "caught":
              wicketDescription = `${batsman.name} c ${
                fielder ? fielder.name : "Substitute"
              } b ${bowler.name}`;
              break;
            case "lbw":
              wicketDescription = `${batsman.name} lbw b ${bowler.name}`;
              break;
            case "stumped":
              wicketDescription = `${batsman.name} st ${fielder.name} b ${bowler.name}`;
              break;
            case "run_out":
              wicketDescription = `${batsman.name} run out (${
                fielder ? fielder.name : "Substitute"
              })`;
              break;
            default:
              wicketDescription = `${batsman.name} ${dismissalType}`;
          }

          ballCommentary = `WICKET! ${wicketDescription}`;

          // Update bowler wicket stats if applicable
          if (
            bowler &&
            ["bowled", "caught", "lbw", "stumped"].includes(dismissalType)
          ) {
            const bowlerStatIndex = currentInnings.bowlingStats.findIndex(
              (stat) => stat.player.toString() === bowler.id
            );

            if (bowlerStatIndex !== -1) {
              currentInnings.bowlingStats[bowlerStatIndex].wickets += 1;

              // Increment ball count if it's a legal delivery
              if (
                !extra ||
                (extra && !["wide", "noBall"].includes(extra.type))
              ) {
                currentInnings.bowlingStats[bowlerStatIndex].balls += 1;

                // Update overs
                const bowlerStat = currentInnings.bowlingStats[bowlerStatIndex];
                bowlerStat.overs = Math.floor(bowlerStat.balls / 6);
                bowlerStat.balls = bowlerStat.balls % 6;

                // Increment innings ball count
                currentInnings.balls++;
                if (currentInnings.balls === 6) {
                  currentInnings.overs++;
                  currentInnings.balls = 0;
                }
              }
            }
          }
        }
      }

      // Update match commentary
      match.commentary.push({
        over: currentInnings.overs,
        ball: currentInnings.balls,
        innings: match.currentInnings,
        text: ballCommentary,
        type: commentaryType,
        time: new Date(),
      });

      // Calculate current run rate
      currentInnings.currentRunRate = calculateRunRate(
        currentInnings.runs,
        currentInnings.overs,
        currentInnings.balls
      );

      // Calculate required run rate if this is second innings
      if (match.currentInnings > 1 && currentInnings.target) {
        const remainingRuns = currentInnings.target - currentInnings.runs;
        const remainingOvers =
          currentInnings.maxOvers -
          currentInnings.overs -
          currentInnings.balls / 6;

        if (remainingOvers > 0) {
          currentInnings.requiredRunRate = parseFloat(
            (remainingRuns / remainingOvers).toFixed(2)
          );
        }
      }

      // Check if innings is completed
      let inningsCompleted = false;

      // Check if all wickets are down
      if (currentInnings.wickets === 10) {
        inningsCompleted = true;
      }

      // Check if max overs are played
      if (
        currentInnings.maxOvers &&
        currentInnings.overs >= currentInnings.maxOvers &&
        currentInnings.balls === 0
      ) {
        inningsCompleted = true;
      }

      // Check if target is achieved in second innings
      if (
        match.currentInnings > 1 &&
        currentInnings.target &&
        currentInnings.runs >= currentInnings.target
      ) {
        inningsCompleted = true;
        match.status = MatchConstants.MATCH_STATUS.COMPLETED;

        // Set match result
        match.result = {
          winner: match.battingTeam,
          winMargin: 10 - currentInnings.wickets,
          winMarginType: "wickets",
        };

        // Add result commentary
        match.commentary.push({
          over: currentInnings.overs,
          ball: currentInnings.balls,
          innings: match.currentInnings,
          text: `${
            match.battingTeam.toString() === match.team1.id.toString()
              ? match.team1.name
              : match.team2.name
          } wins by ${10 - currentInnings.wickets} wickets!`,
          type: "end",
          time: new Date(),
        });
      }

      // Handle innings completion
      if (
        inningsCompleted &&
        match.status !== MatchConstants.MATCH_STATUS.COMPLETED
      ) {
        // For first innings in limited overs match
        if (
          match.currentInnings === 1 &&
          match.format !== MatchConstants.MATCH_FORMAT.TEST
        ) {
          // Create second innings
          const target = currentInnings.runs + 1;

          // Determine batting and bowling teams for second innings
          const secondInningsBattingTeam = match.bowlingTeam;
          const secondInningsBowlingTeam = match.battingTeam;

          // Create second innings
          match.innings.push({
            number: 2,
            battingTeam: secondInningsBattingTeam,
            bowlingTeam: secondInningsBowlingTeam,
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
            maxOvers: currentInnings.maxOvers,
            target: target,
            requiredRunRate: parseFloat(
              (target / currentInnings.maxOvers).toFixed(2)
            ),
            currentRunRate: 0,
            battingStats: [],
            bowlingStats: [],
            fallOfWickets: [],
          });

          // Update match status
          match.status = MatchConstants.MATCH_STATUS.INNINGS_BREAK;
          match.currentInnings = 2;
          match.battingTeam = secondInningsBattingTeam;
          match.bowlingTeam = secondInningsBowlingTeam;

          // Add innings break commentary
          match.commentary.push({
            over: currentInnings.overs,
            ball: currentInnings.balls,
            innings: 1,
            text: `End of innings. ${
              match.team1.id.toString() === match.battingTeam.toString()
                ? match.team2.name
                : match.team1.name
            } needs ${target} runs to win.`,
            type: "end",
            time: new Date(),
          });
        }
        // For second innings or test match
        else if (
          match.currentInnings === 2 ||
          match.format === MatchConstants.MATCH_FORMAT.TEST
        ) {
          // For test match specific logic
          if (match.format === MatchConstants.MATCH_FORMAT.TEST) {
            // Test match logic would go here
            // For simplicity, we're skipping detailed test match logic
          } else {
            // Limited overs match is complete
            match.status = MatchConstants.MATCH_STATUS.COMPLETED;

            // Determine winner
            const firstInnings = match.innings[0];
            const secondInnings = match.innings[1];

            // Second innings didn't reach target
            match.result = {
              winner: firstInnings.battingTeam,
              winMargin: firstInnings.runs - secondInnings.runs,
              winMarginType: "runs",
            };

            // Add result commentary
            match.commentary.push({
              over: currentInnings.overs,
              ball: currentInnings.balls,
              innings: match.currentInnings,
              text: `${
                match.result.winner.toString() === match.team1.id.toString()
                  ? match.team1.name
                  : match.team2.name
              } wins by ${match.result.winMargin} runs!`,
              type: "end",
              time: new Date(),
            });
          }
        }
      }

      // Update last scorer action
      match.lastScorerAction = {
        user: req.user.userId,
        time: new Date(),
        action: `Updated score: ${runsOnThisBall} run(s)${
          wicket ? " and a wicket" : ""
        }${extra ? " with extras" : ""}`,
      };

      await match.save();

      res.status(200).json({
        success: true,
        message: "Score updated successfully",
        match,
      });
    } catch (error) {
      console.error("Error updating score:", error);
      res.status(500).json({
        success: false,
        message: "Failed to update score",
        error: error.message,
      });
    }
  },

  // Start second innings
  startSecondInnings: async (req, res) => {
    try {
      const matchId = req.params.id;

      // Get the match
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
          message: "Only designated scorers can start the second innings",
        });
      }

      // Validate match status
      if (match.status !== MatchConstants.MATCH_STATUS.INNINGS_BREAK) {
        return res.status(400).json({
          success: false,
          message:
            "Match is not in innings break. Cannot start second innings.",
        });
      }

      // Update match status
      match.status = MatchConstants.MATCH_STATUS.LIVE;

      // Add second innings start commentary
      match.commentary.push({
        over: 0,
        ball: 0,
        innings: 2,
        text: `Second innings started. ${
          match.battingTeam.toString() === match.team1.id.toString()
            ? match.team1.name
            : match.team2.name
        } batting, target: ${match.innings[0].target}`,
        type: "start",
        time: new Date(),
      });

      // Update last scorer action
      match.lastScorerAction = {
        user: req.user.userId,
        time: new Date(),
        action: "Started second innings",
      };

      await match.save();

      res.status(200).json({
        success: true,
        message: "Second innings started successfully",
        match,
      });
    } catch (error) {
      console.error("Error starting second innings:", error);
      res.status(500).json({
        success: false,
        message: "Failed to start second innings",
        error: error.message,
      });
    }
  },

  // Apply DLS method for rain interruption
  applyDLS: async (req, res) => {
    try {
      const matchId = req.params.id;
      const { reason, oversReduced } = req.body;

      // Validate required fields
      if (!reason || !oversReduced) {
        return res.status(400).json({
          success: false,
          message: "Reason and oversReduced are required fields",
        });
      }

      // Get the match
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
          message: "Only designated scorers can apply DLS method",
        });
      }

      // Validate match is in progress and not a test match
      if (
        match.status !== MatchConstants.MATCH_STATUS.LIVE ||
        match.format === MatchConstants.MATCH_FORMAT.TEST
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Cannot apply DLS method. Match must be in progress and not a Test match.",
        });
      }

      // Set match status to rain interrupted
      match.status = MatchConstants.MATCH_STATUS.RAIN_INTERRUPTED;

      // Get current innings
      const currentInningsIndex = match.innings.findIndex(
        (innings) => innings.number === match.currentInnings
      );

      if (currentInningsIndex === -1) {
        return res.status(400).json({
          success: false,
          message: "Current innings not found",
        });
      }

      const currentInnings = match.innings[currentInningsIndex];

      // Calculate DLS target if this is second innings
      if (match.currentInnings === 2) {
        const firstInnings = match.innings[0];
        const originalTarget = currentInnings.target;
        const originalMaxOvers = currentInnings.maxOvers;
        const oversPlayed = currentInnings.overs + currentInnings.balls / 6;
        const revisedMaxOvers = originalMaxOvers - oversReduced;

        // Calculate revised target using DLS method
        const revisedTarget = calculateDLSTarget(
          originalTarget - 1, // Original target is firstInnings.runs + 1
          oversPlayed,
          revisedMaxOvers,
          currentInnings.wickets
        );

        // Update innings with revised target and max overs
        currentInnings.target = revisedTarget;
        currentInnings.maxOvers = revisedMaxOvers;

        // Calculate revised required run rate
        const remainingRuns = revisedTarget - currentInnings.runs;
        const remainingOvers =
          revisedMaxOvers - currentInnings.overs - currentInnings.balls / 6;

        if (remainingOvers > 0) {
          currentInnings.requiredRunRate = parseFloat(
            (remainingRuns / remainingOvers).toFixed(2)
          );
        }

        // Add DLS calculation to match
        match.dlsCalculations.push({
          type: MatchConstants.DLS_TYPES.RAIN_INTERRUPTION,
          time: new Date(),
          innings: match.currentInnings,
          atOver: currentInnings.overs,
          atBall: currentInnings.balls,
          originalTarget: originalTarget,
          revisedTarget: revisedTarget,
          oversReduced: oversReduced,
          reason: reason,
          calculatedBy: req.user.userId,
        });

        // Add DLS commentary
        match.commentary.push({
          over: currentInnings.overs,
          ball: currentInnings.balls,
          innings: match.currentInnings,
          text: `Match interrupted due to ${reason}. DLS method applied. Revised target: ${revisedTarget} runs from ${revisedMaxOvers} overs.`,
          type: "dls",
          time: new Date(),
        });
      }
      // First innings DLS adjustment
      else {
        // Just reduce overs for first innings
        const originalMaxOvers = currentInnings.maxOvers;
        const revisedMaxOvers = originalMaxOvers - oversReduced;

        // Update innings with revised max overs
        currentInnings.maxOvers = revisedMaxOvers;

        // Add DLS calculation to match
        match.dlsCalculations.push({
          type: MatchConstants.DLS_TYPES.INNINGS_ADJUSTMENT,
          time: new Date(),
          innings: match.currentInnings,
          atOver: currentInnings.overs,
          atBall: currentInnings.balls,
          originalTarget: null,
          revisedTarget: null,
          oversReduced: oversReduced,
          reason: reason,
          calculatedBy: req.user.userId,
        });

        // Add DLS commentary
        match.commentary.push({
          over: currentInnings.overs,
          ball: currentInnings.balls,
          innings: match.currentInnings,
          text: `Match interrupted due to ${reason}. Innings reduced to ${revisedMaxOvers} overs.`,
          type: "dls",
          time: new Date(),
        });
      }

      // Update last scorer action
      match.lastScorerAction = {
        user: req.user.userId,
        time: new Date(),
        action: `Applied DLS method: ${oversReduced} overs reduced due to ${reason}`,
      };

      await match.save();

      res.status(200).json({
        success: true,
        message: "DLS method applied successfully",
        match,
      });
    } catch (error) {
      console.error("Error applying DLS method:", error);
      res.status(500).json({
        success: false,
        message: "Failed to apply DLS method",
        error: error.message,
      });
    }
  },

  // Resume match after rain delay
  resumeMatch: async (req, res) => {
    try {
      const matchId = req.params.id;

      // Get the match
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
          message: "Only designated scorers can resume the match",
        });
      }

      // Validate match status
      if (
        match.status !== MatchConstants.MATCH_STATUS.RAIN_INTERRUPTED &&
        match.status !== MatchConstants.MATCH_STATUS.DELAYED
      ) {
        return res.status(400).json({
          success: false,
          message: "Match is not interrupted or delayed. Cannot resume.",
        });
      }

      // Update match status
      match.status = MatchConstants.MATCH_STATUS.LIVE;

      // Add resume commentary
      match.commentary.push({
        over: match.innings[match.currentInnings - 1].overs,
        ball: match.innings[match.currentInnings - 1].balls,
        innings: match.currentInnings,
        text: `Match resumed after interruption.`,
        type: "start",
        time: new Date(),
      });

      // Update last scorer action
      match.lastScorerAction = {
        user: req.user.userId,
        time: new Date(),
        action: "Resumed match after interruption",
      };

      await match.save();

      res.status(200).json({
        success: true,
        message: "Match resumed successfully",
        match,
      });
    } catch (error) {
      console.error("Error resuming match:", error);
      res.status(500).json({
        success: false,
        message: "Failed to resume match",
        error: error.message,
      });
    }
  },

  // End match / declare result
  endMatch: async (req, res) => {
    try {
      const matchId = req.params.id;
      const { result, playerOfMatch } = req.body;

      // Get the match
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
          message: "Only designated scorers can end the match",
        });
      }

      // Update match status
      match.status = MatchConstants.MATCH_STATUS.COMPLETED;

      // Set result details
      match.endTime = new Date();
      match.duration = Math.floor((match.endTime - match.startTime) / 1000); // Duration in seconds

      // Set result based on the provided result data
      if (result) {
        match.result = {
          winner: result.winner,
          isDraw: result.isDraw || false,
          winMargin: result.winMargin,
          winMarginType: result.winMarginType,
        };
      } else {
        // Determine winner based on scores if result not provided
        if (match.homeTeamScore > match.awayTeamScore) {
          match.result = {
            winner: match.homeTeam,
            loser: match.awayTeam,
            isDraw: false,
          };
        } else if (match.awayTeamScore > match.homeTeamScore) {
          match.result = {
            winner: match.awayTeam,
            loser: match.homeTeam,
            isDraw: false,
          };
        } else {
          match.result = {
            winner: null,
            loser: null,
            isDraw: true,
          };
        }
      }

      // Set player of the match if provided
      if (playerOfMatch) {
        match.result.playerOfMatch = playerOfMatch;
      }

      // Save the updated match
      await match.save();

      return res.status(200).json({
        success: true,
        message: "Match completed successfully",
        match: match,
      });
    } catch (error) {
      console.error("Error ending match:", error);
      return res.status(500).json({
        success: false,
        message: "Error completing match",
        error: error.message,
      });
    }
  },
};
module.exports = matchScoringController;
