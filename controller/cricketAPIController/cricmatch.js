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
  // Create a new match
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
        .populate("members.user", "_id name email")
        .populate("captain", "_id name email")
        .populate("viceCaptain", "_id name email");

      const team2 = await Team.findById(team2Id)
        .populate("members.user", "_id name email")
        .populate("captain", "_id name email")
        .populate("viceCaptain", "_id name email");
      console.log("Team2", team2);

      if (!team1 || !team2) {
        return res.status(404).json({
          success: false,
          message: "One or both teams not found",
        });
      }

      // Validate team sizes - both teams must have exactly 11 members
      if (team1.members.length !== 11) {
        return res.status(400).json({
          success: false,
          message: `Team ${team1.name} must have exactly 11 members (currently has ${team1.members.length})`,
        });
      }

      if (team2.members.length !== 11) {
        return res.status(400).json({
          success: false,
          message: `Team ${team2.name} must have exactly 11 members (currently has ${team2.members.length})`,
        });
      }

      // Verify teams have different owners
      // if (team1.owner.toString() === team2.owner.toString()) {
      //   return res.status(400).json({
      //     success: false,
      //     message: "Match cannot be created between teams with the same owner",
      //   });
      // }

      // Check if user has permission to create a match for team1

      const isTeam1Admin = team1.members.some(
        (member) =>
          member.user && // check if user exists
          member.user._id.toString() === req.user.userId.toString() &&
          member.role == "admin"
      );

      const isTeam1Owner = team1.owner.toString() == req.user.userId.toString();

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
        name: member.user?.name,
        isCaptain:
          team1.captain &&
          team1.captain._id.toString() === member.user._id.toString(),
        isWicketkeeper: false, // Default, would be set manually later
      }));
      const team2Players = team2.members.map((member) => ({
        player: member.user._id,
        name: member.user?.name,
        isCaptain:
          team2.captain &&
          team2.captain._id.toString() === member.user._id.toString(),
        isWicketkeeper: false, // Default, would be set manually later
      }));

      console.log("team2Players", team2Players);

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
        innings: [initialInnings],
        scorers: scorersList,
        battingTeam: team1._id,
        bowlingTeam: team2._id,
        createdBy: req.user.userId,
        commentary: [
          {
            over: 0,
            ball: 0,
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
  getMatchDetails: async (req, res) => {
    try {
      const matchId = req.params.id;

      // Fetch the match by ID
      const match = await Match.findById(matchId)
        .populate("team1.id", "name title logo")
        .populate("team2.id", "name title logo")
        .populate("scorers.user", "name")
        .populate("battingTeam", "name")
        .populate("bowlingTeam", "name");

      if (!match) {
        return res.status(404).json({
          success: false,
          message: "Match not found",
        });
      }

      // Extract team details
      const team1Details = {
        name: match.team1.name,
        title: match.team1.title || "No title",
        logo: match.team1.logo || null,
      };

      const team2Details = {
        name: match.team2.name,
        title: match.team2.title || "No title",
        logo: match.team2.logo || null,
      };

      // Extract live updates
      const liveUpdates = {
        status: match.status,
        currentInnings: match.currentInnings,
        battingTeam: match.battingTeam.name,
        bowlingTeam: match.bowlingTeam.name,
        runs: match.innings[match.currentInnings - 1]?.runs || 0,
        wickets: match.innings[match.currentInnings - 1]?.wickets || 0,
        overs: match.innings[match.currentInnings - 1]?.overs || 0,
        balls: match.innings[match.currentInnings - 1]?.balls || 0,
        target: match.innings[match.currentInnings - 1]?.target || null,
        requiredRunRate:
          match.innings[match.currentInnings - 1]?.requiredRunRate || null,
      };

      // Extract commentary
      const commentary = match.commentary.map((comment) => ({
        over: comment.over,
        ball: comment.ball,
        text: comment.text,
        type: comment.type,
        time: comment.time,
      }));

      // Extract score details
      const scoreDetails = {
        team1: {
          runs: match.innings[0]?.runs || 0,
          wickets: match.innings[0]?.wickets || 0,
          overs: match.innings[0]?.overs || 0,
          balls: match.innings[0]?.balls || 0,
        },
        team2: {
          runs: match.innings[1]?.runs || 0,
          wickets: match.innings[1]?.wickets || 0,
          overs: match.innings[1]?.overs || 0,
          balls: match.innings[1]?.balls || 0,
        },
      };

      // Return the match details
      res.status(200).json({
        success: true,
        matchDetails: {
          team1Details,
          team2Details,
          liveUpdates,
          commentary,
          scoreDetails,
        },
      });
    } catch (error) {
      console.error("Error fetching match details:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch match details",
        error: error.message,
      });
    }
  },
  // Get all matches with filters
  // getAllMatches: async (req, res) => {
  //   try {
  //     const { status, format, team, date, upcoming } = req.query;

  //     // Build query
  //     const query = {};

  //     if (status) {
  //       query.status = status;
  //     }

  //     if (format) {
  //       query.format = format;
  //     }

  //     if (team) {
  //       query.$or = [{ "team1.id": team }, { "team2.id": team }];
  //     }

  //     if (date) {
  //       const startDate = new Date(date);
  //       startDate.setHours(0, 0, 0, 0);

  //       const endDate = new Date(date);
  //       endDate.setHours(23, 59, 59, 999);

  //       query.matchDate = {
  //         $gte: startDate,
  //         $lte: endDate,
  //       };
  //     }

  //     if (upcoming === "true") {
  //       query.matchDate = {
  //         $gte: new Date(),
  //       };
  //       query.status = {
  //         $in: [
  //           MatchConstants.MATCH_STATUS.UPCOMING,
  //           MatchConstants.MATCH_STATUS.TOSS,
  //         ],
  //       };
  //     }

  //     // Get matches with selected fields for list view
  //     const matches = await Match.find(query)
  //       .select(
  //         "title status format venue matchDate team1.name team1.logo team2.name team2.logo innings.runs innings.wickets innings.overs innings.balls innings result toss"
  //       )
  //       .sort({ matchDate: -1 });

  //     res.status(200).json({
  //       success: true,
  //       count: matches.length,
  //       matches,
  //     });
  //   } catch (error) {
  //     console.error("Error fetching matches:", error);
  //     res.status(500).json({
  //       success: false,
  //       message: "Failed to fetch matches",
  //       error: error.message,
  //     });
  //   }
  // },

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
        .select({
          title: 1,
          status: 1,
          format: 1,
          venue: 1,
          matchDate: 1,
          "team1.name": 1,
          "team1.logo": 1,
          "team2.name": 1,
          "team2.logo": 1,
          "innings.runs": 1,
          "innings.wickets": 1,
          "innings.overs": 1,
          "innings.balls": 1,
          result: 1,
          toss: 1,
        })
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

  // Get a specific match with all details
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

  // Update toss details
  updateToss: async (req, res) => {
    console.log("Function ENters");
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
        inningsNumber: 1,
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
    
    // Set current innings to 1 if not already set
    match.currentInnings = 1;

    // Add match start commentary
    match.commentary.push({
      over: 0,
      ball: 0,
      inningsNumber: 1, // Fixed: Set to 1 for first innings
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

    // Set match start time
    match.startTime = new Date();

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
      const { userId } = req.body;

      // Validate user ID
      if (!userId) {
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
        (scorer) => scorer.user.toString() === userId
      );

      if (isAlreadyScorer) {
        return res.status(400).json({
          success: false,
          message: "User is already a scorer for this match",
        });
      }

      // Find user details
      const user = await User.findById(userId).select("name");
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

  // Remove scorer from match
  // removeScorer: async (req, res) => {
  //   try {
  //     const matchId = req.params.id;
  //     const scorerId = req.params.scorerId;

  //     // Get the match
  //     const match = await Match.findById(matchId);
  //     if (!match) {
  //       return res.status(404).json({
  //         success: false,
  //         message: "Match not found"
  //       });
  //     }
  //   }  catch(err){
  //     console.log(err);
  //   }
  // },

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

      // Get current innings properly
      const currentInningsIndex = match.currentInnings - 1;
      const innings = match.innings[currentInningsIndex];
      if (!innings) {
        return res.status(400).json({
          success: false,
          message: "Current innings not found",
        });
      }

      // Initialize batting stats if empty (for fresh teams)
      if (innings.battingStats.length === 0) {
        const battingTeamPlayers =
          match.currentInnings === 1
            ? match.team1.players
            : match.team2.players;

        battingTeamPlayers.forEach((player) => {
          innings.battingStats.push({
            player: player.player,
            name: player.name,
            runs: 0,
            balls: 0,
            fours: 0,
            sixes: 0,
            strikeRate: 0,
            dismissalType: null,
            bowler: null,
            fielder: null,
            position: null,
            inAt: null,
            outAt: null,
          });
        });
      }

      // Initialize bowling stats if empty (for fresh teams)
      if (innings.bowlingStats.length === 0) {
        const bowlingTeamPlayers =
          match.currentInnings === 1
            ? match.team2.players
            : match.team1.players;

        bowlingTeamPlayers.forEach((player) => {
          innings.bowlingStats.push({
            player: player.player,
            name: player.name,
            overs: 0,
            balls: 0,
            maidens: 0,
            runs: 0,
            wickets: 0,
            economy: 0,
            noBalls: 0,
            wides: 0,
          });
        });
      }

      // Process the ball
      let ballCommentary = "";
      let commentaryType = "regular";
      let runsOnThisBall = 0;

      // Handle extras
      if (extra) {
        switch (extra.type) {
          case "wide":
            innings.extras.wides += 1;
            innings.runs += 1;
            runsOnThisBall += 1;
            if (extra.runs) {
              innings.extras.wides += extra.runs;
              innings.runs += extra.runs;
              runsOnThisBall += extra.runs;
              ballCommentary = `Wide + ${extra.runs} runs`;
            } else {
              ballCommentary = "Wide";
            }
            break;

          // ... other extra types remain the same ...
        }

        innings.totalExtras =
          innings.extras.wides +
          innings.extras.noBalls +
          innings.extras.byes +
          innings.extras.legByes +
          innings.extras.penalty;
      }
      // Handle regular runs
      else if (runs !== undefined && !wicket) {
        innings.runs += runs;
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

        // Increment ball count
        innings.balls++;
        if (innings.balls === 6) {
          innings.overs++;
          innings.balls = 0;
        }

        // Handle fresh batsman - add if not exists
        if (batsman && innings.currentBatsmen) {
          const batsmanId = typeof batsman === "string" ? batsman : batsman.id;
          const batsmanStatIndex = innings.battingStats.findIndex(
            (stat) => stat.player.toString() === batsmanId.toString()
          );

          // Add fresh batsman if not found
          if (batsmanStatIndex === -1) {
            innings.battingStats.push({
              player: batsman.id,
              name: batsman.name,
              runs: 0,
              balls: 0,
              fours: 0,
              sixes: 0,
              strikeRate: 0,
              dismissalType: null,
              bowler: null,
              fielder: null,
              position: innings.battingStats.length + 1, // Next position
              inAt: innings.runs,
              outAt: null,
            });
            batsmanStatIndex = innings.battingStats.length - 1;
          }

          // Update batsman stats
          const batsmanStat = innings.battingStats[batsmanStatIndex];
          batsmanStat.runs += runs;
          batsmanStat.balls += 1;
          if (runs === 4) batsmanStat.fours += 1;
          if (runs === 6) batsmanStat.sixes += 1;
          batsmanStat.strikeRate = parseFloat(
            ((batsmanStat.runs / batsmanStat.balls) * 100).toFixed(2)
          );
        }

        // Update bowler stats
        if (bowler && innings.currentBowler) {
          const bowlerId = typeof bowler === "string" ? bowler : bowler.id;
          const bowlerStatIndex = innings.bowlingStats.findIndex(
            (stat) => stat.player.toString() === bowlerId.toString()
          );
          if (bowlerStatIndex !== -1) {
            const bowlerStat = innings.bowlingStats[bowlerStatIndex];
            bowlerStat.runs += runs;
            bowlerStat.balls += 1;
            bowlerStat.overs = Math.floor(bowlerStat.balls / 6);
            bowlerStat.balls = bowlerStat.balls % 6;
            bowlerStat.economy = parseFloat(
              (
                bowlerStat.runs /
                (bowlerStat.overs + bowlerStat.balls / 6)
              ).toFixed(2)
            );
          }
        }
      }

      // Handle wickets
      if (wicket && batsman) {
        innings.wickets++;
        commentaryType = "wicket";
        console.log("batsman", innings.battingStats);
        let batsmanStatIndex = innings.battingStats.findIndex(
          (stat) => stat.player.toString() === batsman.id
        );

        // Add fresh batsman if not found (shouldn't happen but defensive programming)
        if (batsmanStatIndex === -1) {
          innings.battingStats.push({
            player: batsman.id,
            name: batsman.name,
            runs: 0,
            balls: 0,
            fours: 0,
            sixes: 0,
            strikeRate: 0,
            dismissalType: dismissalType,
            bowler: bowler ? bowler.id : null,
            fielder: fielder ? fielder.id : null,
            position: innings.battingStats.length + 1,
            inAt: innings.runs,
            outAt: innings.runs,
          });
          batsmanStatIndex = innings.battingStats.length - 1;
        }

        const batsmanStat = innings.battingStats[batsmanStatIndex];
        batsmanStat.dismissalType = dismissalType;
        batsmanStat.outAt = innings.runs;

        if (
          fielder &&
          ["caught", "stumped", "run_out"].includes(dismissalType)
        ) {
          batsmanStat.fielder = fielder.id;
        }

        if (
          bowler &&
          ["bowled", "caught", "lbw", "stumped"].includes(dismissalType)
        ) {
          batsmanStat.bowler = bowler.id;
        }

        // Add to fall of wickets
        innings.fallOfWickets.push({
          wicketNumber: innings.wickets,
          runs: innings.runs,
          overs: innings.overs,
          balls: innings.balls,
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
            wicketDescription = `${batsman.name} st ${
              fielder ? fielder.name : "Substitute"
            } b ${bowler.name}`;
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

        // Update bowler stats if applicable
        if (
          bowler &&
          ["bowled", "caught", "lbw", "stumped"].includes(dismissalType)
        ) {
          const bowlerStatIndex = innings.bowlingStats.findIndex(
            (stat) => stat.player.toString() === bowler.id
          );
          if (bowlerStatIndex !== -1) {
            innings.bowlingStats[bowlerStatIndex].wickets += 1;
            if (!extra || (extra && !["wide", "noBall"].includes(extra.type))) {
              innings.bowlingStats[bowlerStatIndex].balls += 1;
              const bowlerStat = innings.bowlingStats[bowlerStatIndex];
              bowlerStat.overs = Math.floor(bowlerStat.balls / 6);
              bowlerStat.balls = bowlerStat.balls % 6;
              innings.balls++;
              if (innings.balls === 6) {
                innings.overs++;
                innings.balls = 0;
              }
            }
          }
        }
      }

      // Update match commentary
      match.commentary.push({
        over: innings.overs,
        ball: innings.balls,
        inningsNumber: match.currentInnings, // Using the correct field name as defined in the schema
        text: ballCommentary,
        type: commentaryType,
        time: new Date(),
      });

      // Calculate current run rate
      const totalOvers = innings.overs + innings.balls / 6;
      innings.currentRunRate =
        totalOvers > 0 ? parseFloat((innings.runs / totalOvers).toFixed(2)) : 0;

      // Calculate required run rate if this is second innings
      if (match.currentInnings > 1 && innings.target) {
        const remainingRuns = innings.target - innings.runs;
        const remainingOvers =
          innings.maxOvers - innings.overs - innings.balls / 6;
        innings.requiredRunRate =
          remainingOvers > 0
            ? parseFloat((remainingRuns / remainingOvers).toFixed(2))
            : 0;
      }

      // Check if innings is completed
      let inningsCompleted =
        innings.wickets === 10 ||
        (innings.maxOvers &&
          innings.overs >= innings.maxOvers &&
          innings.balls === 0) ||
        (match.currentInnings > 1 &&
          innings.target &&
          innings.runs >= innings.target);

      if (
        inningsCompleted &&
        match.status !== MatchConstants.MATCH_STATUS.COMPLETED
      ) {
        if (
          match.currentInnings === 1 &&
          match.format !== MatchConstants.MATCH_FORMAT.TEST
        ) {
          // Create second innings
          const target = innings.runs + 1;
          const secondInningsBattingTeam = match.bowlingTeam;
          const secondInningsBowlingTeam = match.battingTeam;

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
            maxOvers: innings.maxOvers,
            target: target,
            requiredRunRate: parseFloat((target / innings.maxOvers).toFixed(2)),
            currentRunRate: 0,
            battingStats: [],
            bowlingStats: [],
            fallOfWickets: [],
          });

          match.status = MatchConstants.MATCH_STATUS.INNINGS_BREAK;
          match.currentInnings = 2;
          match.battingTeam = secondInningsBattingTeam;
          match.bowlingTeam = secondInningsBowlingTeam;

          match.commentary.push({
            over: innings.overs,
            ball: innings.balls,
            inningsNumber: 1,
            text: `End of innings. ${
              match.team1.id.toString() === match.battingTeam.toString()
                ? match.team2.name
                : match.team1.name
            } needs ${target} runs to win.`,
            type: "end",
            time: new Date(),
          });
        } else if (
          match.currentInnings === 2 ||
          match.format === MatchConstants.MATCH_FORMAT.TEST
        ) {
          match.status = MatchConstants.MATCH_STATUS.COMPLETED;
          if (match.format !== MatchConstants.MATCH_FORMAT.TEST) {
            const firstInnings = match.innings[0];
            const secondInnings = match.innings[1];
            match.result = {
              winner:
                innings.runs >= innings.target
                  ? match.battingTeam
                  : firstInnings.battingTeam,
              winMargin:
                innings.runs >= innings.target
                  ? 10 - innings.wickets
                  : firstInnings.runs - secondInnings.runs,
              winMarginType:
                innings.runs >= innings.target ? "wickets" : "runs",
            };

            match.commentary.push({
              over: innings.overs,
              ball: innings.balls,
              inningsNumber: match.currentInnings,
              text: `${
                match.result.winner.toString() === match.team1.id.toString()
                  ? match.team1.name
                  : match.team2.name
              } wins by ${match.result.winMargin} ${
                match.result.winMarginType
              }!`,
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
        inningsNumber: 2,
        text: `Second innings started. ${
          match.battingTeam.toString() === match.team1.id.toString()
            ? match.team1.name
            : match.team2.name
        } batting, target: ${match.innings[1].target}`,
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
          inningsNumber: match.currentInnings,
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
          inningsNumber: match.currentInnings,
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
        inningsNumber: match.currentInnings, // Using the correct field name as defined in the schema
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
          loser: result.loser,
          isDraw: result.isDraw || false,
          winningMethod: result.winningMethod,
          notes: result.notes,
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
        match.playerOfMatch = playerOfMatch;
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
