// controllers/dashboardController.js

const User = require('../../models/userModel/userModel');
const Match = require('../../models/cricketModel/match');
const Sport = require('../../models/dashboardModel/Sport');
const Statistics = require('../../models/dashboardModel/Statistics');
const Team = require('../../models/cricketModel/teams');
const Scorecard = require('../../models/dashboardModel/Scorecard');
const mongoose = require('mongoose'); // Ensure mongoose is imported
const teamController = require('../cricketAPIController/teamController');

const VALID_SPORTS = ["Cricket", "Football", "Volleyball", "Badminton"];
const VALID_ROLES = {
  Cricket: ["Batsman", "Bowler", "All-rounder", "Wicketkeeper"],
  Football: ["Striker", "Midfielder", "Defender", "Goalkeeper"],
  Volleyball: ["Setter", "Spiker", "Libero"],
  Badminton: ["Singles Player", "Doubles Player"],
};

// Static statistics data (to be replaced with dynamic data later)
const STATIC_STATS = {
  Cricket: {
    Batsman: {
      matches: 15,
      runs: 450,
      average: 30.0,
      highestScore: 75,
      strikeRate: 120.5,
      fifties: 3,
    },
    Bowler: {
      matches: 15,
      wickets: 25,
      economy: 6.8,
      bestFigures: "4/23",
      average: 22.4,
    },
    "All-rounder": {
      matches: 15,
      runs: 320,
      wickets: 18,
      battingAverage: 26.7,
      bowlingAverage: 24.2,
    },
    Wicketkeeper: {
      matches: 15,
      dismissals: 22,
      stumpings: 8,
      catches: 14,
    },
  },
  Football: {
    Striker: {
      matches: 18,
      goals: 12,
      assists: 5,
      shotsOnTarget: 38,
      conversionRate: "31.6%",
    },
    Midfielder: {
      matches: 18,
      goals: 4,
      assists: 10,
      passAccuracy: "87.3%",
      distanceCovered: "210.4 km",
    },
    Defender: {
      matches: 18,
      cleanSheets: 7,
      tackles: 45,
      interceptions: 32,
      clearances: 78,
    },
    Goalkeeper: {
      matches: 18,
      cleanSheets: 7,
      saves: 54,
      savePercentage: "76.2%",
      penaltiesSaved: 2,
    },
  },
  Volleyball: {
    Setter: {
      matches: 12,
      assists: 205,
      aces: 15,
      blocks: 8,
      digs: 45,
    },
    Spiker: {
      matches: 12,
      kills: 135,
      aces: 22,
      blocks: 18,
      attackPercentage: "42.5%",
    },
    Libero: {
      matches: 12,
      digs: 182,
      receptions: 210,
      aces: 8,
      passAccuracy: "95.2%",
    },
  },
  Badminton: {
    "Singles Player": {
      matches: 24,
      wins: 16,
      winPercentage: "66.7%",
      highestScore: "21-8",
      tournaments: 5,
    },
    "Doubles Player": {
      matches: 22,
      wins: 14,
      winPercentage: "63.6%",
      highestScore: "21-12",
      tournaments: 5,
    },
  },
};
/**
 * Dashboard Controller
 * Handles all operations related to the dashboard view and data
 */
class DashboardController {
  /**
   * Get dashboard data for the current user
   * @route GET /api/dashboard
   */
  async getDashboard(req, res) {
    try {
      const userId = req.user?.userId;
      let { sport } = req.query;
      if (!sport) {
        const userSports = await User.findById(userId).select('sports');
        console.log(userSports,"userSports");
        if (userSports && userSports.sports && userSports.sports.length > 0) {
          sport = userSports.sports[0].sport_name;
        } else {
          sport = 'Cricket'; // Default fallback
        }
      }

      if (!userId) {
        console.log("userIdS")
        return res.status(400).json({
          success: false,
          message: 'User ID is required',
        });
      }

      // Get user data
      const user = await User.findById(userId);
      if (!user) {
        console.log("usr")
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      // Fetch all required data
      const sports = await User.findById(userId).select('sports.sport_name'); 
      const teams = await this.getUserTeams(userId);
      // Find the user's role for the requested sport
      const userSport = user.sports.find(s => s.sport_name === sport);
      console.log("userSport",userSport.role);
      const stats = await this.getSportStatistics(userId, sport,userSport.role);

      // const upcomingMatches = await this.getUpcomingMatches(userId);
      // const liveMatch = await this.getLiveMatch(userId);

      // Respond with dashboard data
      res.status(200).json({
        success: true,
        data: {
          user,
          activeSport: sport,
          teams,
          stats
        },
      });
    } catch (error) {
      console.error('Error fetching dashboard:', error);
      res.status(500).json({
        success: false,
        message: 'Server error',
        error: error.message,
      });
    }
  }



  /**
   * Get user stats for a specific sport
   */
  
  // teamController.js
async getUserTeams (userId) {
  try {
    const teams = await Team.find({
      $or: [
        { owner: userId },
        { "members.user": userId }
      ]
    })
      .populate("owner", "name email")
      .populate("members.user", "name email")
      .populate("captain", "name email")
      .populate("viceCaptain", "name email");

    return teams;
  } catch (error) {
    throw new Error(error.message);
  }
}

// Assuming you want to remove req, res entirely
async getSportStatistics(userId, sportName, sportRole) {
  try {

    // Ensure sportName and sportRole are provided
    if (!sportName || !sportRole) {
      throw new Error("Sport name and role are required");
    }

    // Find user in MongoDB
    const user = await User.findById(userId);
    if (!user) {
      throw new Error("User not found");
    }

    // Check if user has this sport and role
    const hasSport = user.sports.some(
      (s) => s.sport_name === sportName && s.role === sportRole
    );

    if (!hasSport) {
      throw new Error("Sport not found in user profile");
    }
    // Get static statistics for this sport and role
    const stats = STATIC_STATS[sportName] && STATIC_STATS[sportName][sportRole]
      ? STATIC_STATS[sportName][sportRole]
      : {};

    return {
      success: true,
      sport: {
        name: sportName,
        role: sportRole,
        statistics: stats,
      },
    };
  } catch (error) {
    console.error("Get sport statistics error:", error.message);
    return {
      success: false,
      message: error.message,
    };
  }
}


  

  /**
   * Format statistics based on sport and role
   */
  formatStatistics(statistics, sport, role) {
    if (sport.toLowerCase() === 'cricket') {
      if (role.toLowerCase() === 'batsman') {
        return [
          {
            id: 'batting_average',
            label: 'Batting Average',
            value: statistics.battingAverage || 0,
            change: statistics.battingAverageChange || 0,
            changeType:
              statistics.battingAverageChange > 0 ? 'increase' : 'decrease',
          },
          {
            id: 'strike_rate',
            label: 'Strike Rate',
            value: statistics.strikeRate || 0,
            change: statistics.strikeRateChange || 0,
            changeType:
              statistics.strikeRateChange > 0 ? 'increase' : 'decrease',
          },
          {
            id: 'total_matches',
            label: 'Total Matches',
            value: statistics.matches || 0,
            change: statistics.recentMatches || 0,
            changeType: 'increase',
          },
        ];
      } else if (role.toLowerCase() === 'bowler') {
        return [
          {
            id: 'bowling_economy',
            label: 'Bowling Economy',
            value: statistics.economy || 0,
            change: statistics.economyChange || 0,
            changeType:
              statistics.economyChange < 0 ? 'increase' : 'decrease',
          },
          {
            id: 'bowling_average',
            label: 'Bowling Average',
            value: statistics.bowlingAverage || 0,
            change: statistics.bowlingAverageChange || 0,
            changeType:
              statistics.bowlingAverageChange < 0 ? 'increase' : 'decrease',
          },
          {
            id: 'total_matches',
            label: 'Total Matches',
            value: statistics.matches || 0,
            change: statistics.recentMatches || 0,
            changeType: 'increase',
          },
        ];
      }
    }

    // Generic stats for other sports or roles
    return [
      {
        id: 'total_matches',
        label: 'Total Matches',
        value: statistics.matches || 0,
        change: statistics.recentMatches || 0,
        changeType: 'increase',
      },
      {
        id: 'wins',
        label: 'Wins',
        value: statistics.wins || 0,
        change: statistics.recentWins || 0,
        changeType: 'increase',
      },
      {
        id: 'performance_index',
        label: 'Performance Index',
        value: statistics.performanceIndex || 0,
        change: statistics.performanceIndexChange || 0,
        changeType:
          statistics.performanceIndexChange > 0 ? 'increase' : 'decrease',
      },
    ];
  }

  /**
   * Get upcoming matches for the user
   */
  async getUpcomingMatches(userId) {
    try {
      const objectId = mongoose.Types.ObjectId(userId); // Convert userId to ObjectId
      const userTeams = await Team.find({
        $or: [{ owner: objectId }, { members: objectId }],
      }).select('_id');
  
      const teamIds = userTeams.map((team) => mongoose.Types.ObjectId(team._id)); // Convert team IDs to ObjectId
  
      const now = new Date();
      const matches = await Match.find({
        $or: [{ team1: { $in: teamIds } }, { team2: { $in: teamIds } }],
        startTime: { $gt: now },
        status: { $in: ['scheduled', 'confirmed'] },
      })
        .populate('team1 team2 sport venue')
        .sort({ startTime: 1 })
        .limit(5);
  
      return matches.map((match) => ({
        id: match._id,
        teams: `${match.team1.name} vs ${match.team2.name}`,
        format: match.format,
        venue: match.venue ? match.venue.name : 'TBD',
        sport: match.sport.name.toLowerCase(),
        sportIcon: match.sport.icon,
        startTime: match.startTime,
        timeRemaining: this.formatTimeRemaining(match.startTime),
      }));
    } catch (error) {
      console.error('Error fetching upcoming matches:', error);
      return [];
    }
  }

  /**
   * Format time remaining in a human-readable format
   */
  formatTimeRemaining(startTime) {
    const now = new Date();
    const diff = startTime - now;

    if (diff > 24 * 60 * 60 * 1000) {
      const options = { weekday: 'short', hour: '2-digit', minute: '2-digit' };
      return startTime.toLocaleDateString('en-US', options);
    }

    const hours = Math.floor(diff / (60 * 60 * 1000));
    const minutes = Math.floor((diff % (60 * 60 * 1000)) / (60 * 1000));

    return hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;
  }

  /**
   * Get live match data if available
   */
  async getLiveMatch(userId) {
    try {
      const userTeams = await Team.find({
        $or: [{ owner: userId }, { members: userId }],
      }).select('_id');

      const teamIds = userTeams.map((team) => team._id);

      const liveMatch = await Match.findOne({
        $or: [{ team1: { $in: teamIds } }, { team2: { $in: teamIds } }],
        status: 'in_progress',
      })
        .populate('team1 team2 sport venue')
        .sort({ startTime: -1 });

      if (!liveMatch) return null;

      const scorecard = await Scorecard.findOne({ match: liveMatch._id });
      if (!scorecard) return null;

      return this.formatLiveMatch(liveMatch, scorecard);
    } catch (error) {
      console.error('Error fetching live match:', error);
      return null;
    }
  }

  /**
   * Format live match data
   */
  formatLiveMatch(liveMatch, scorecard) {
    if (liveMatch.sport.name.toLowerCase() === 'cricket') {
      return {
        id: liveMatch._id,
        format: liveMatch.format,
        venue: liveMatch.venue ? liveMatch.venue.name : 'Unknown',
        team1: {
          name: liveMatch.team1.name,
          score: `${scorecard.team1Score}/${scorecard.team1Wickets}`,
          overs: scorecard.team1Overs.toFixed(1),
        },
        team2: {
          name: liveMatch.team2.name,
          score: scorecard.team2BattingStarted
            ? `${scorecard.team2Score}/${scorecard.team2Wickets}`
            : '-/-',
          overs: scorecard.team2BattingStarted
            ? scorecard.team2Overs.toFixed(1)
            : '0.0',
        },
        batsmen: scorecard.currentBatsmen.map((batsman) => ({
          name: batsman.name,
          runs: batsman.runs,
          balls: batsman.balls,
        })),
        bowler: scorecard.currentBowler
          ? {
              name: scorecard.currentBowler.name,
              overs: Math.floor(scorecard.currentBowler.balls / 6),
              runs: scorecard.currentBowler.runs,
              wickets: scorecard.currentBowler.wickets,
            }
          : null,
        currentOver: scorecard.currentOverBalls || [],
        currentOverSummary: scorecard.currentOverSummary || '',
      };
    }

    // Generic format for other sports
    return {
      id: liveMatch._id,
      format: liveMatch.format,
      venue: liveMatch.venue ? liveMatch.venue.name : 'Unknown',
      team1: { name: liveMatch.team1.name, score: scorecard.team1Score },
      team2: { name: liveMatch.team2.name, score: scorecard.team2Score },
      status: liveMatch.status,
      currentPeriod: scorecard.currentPeriod,
    };
  }
}

module.exports = new DashboardController();