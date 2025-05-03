// models/Statistics.js

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

/**
 * Statistics Schema
 * Tracks performance metrics across different sports and roles
 */
const StatisticsSchema = new Schema({
  // References
  user: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  sport: {
    type: Schema.Types.ObjectId,
    ref: 'Sport',
    required: true
  },
  role: {
    type: String,
    required: true,
    trim: true
  },
  
  // General statistics (across all sports)
  matches: {
    type: Number,
    default: 0
  },
  recentMatches: {
    type: Number,
    default: 0,
    comment: 'Matches played in the last month'
  },
  wins: {
    type: Number,
    default: 0
  },
  recentWins: {
    type: Number,
    default: 0,
    comment: 'Wins in the last month'
  },
  losses: {
    type: Number,
    default: 0
  },
  draws: {
    type: Number,
    default: 0
  },
  performanceIndex: {
    type: Number,
    default: 0,
    comment: 'Overall performance rating from 0-100'
  },
  performanceIndexChange: {
    type: Number,
    default: 0,
    comment: 'Change in performance index over the last month'
  },

  // Cricket - Batting statistics
  battingAverage: {
    type: Number,
    default: 0
  },
  battingAverageChange: {
    type: Number,
    default: 0
  },
  runsScored: {
    type: Number,
    default: 0
  },
  recentRuns: {
    type: Number,
    default: 0,
    comment: 'Runs scored in the last month'
  },
  ballsFaced: {
    type: Number,
    default: 0
  },
  strikeRate: {
    type: Number,
    default: 0,
    comment: 'Runs per 100 balls'
  },
  strikeRateChange: {
    type: Number,
    default: 0
  },
  centuries: {
    type: Number,
    default: 0
  },
  halfCenturies: {
    type: Number,
    default: 0
  },
  fours: {
    type: Number,
    default: 0
  },
  sixes: {
    type: Number,
    default: 0
  },
  highestScore: {
    type: Number,
    default: 0
  },

  // Cricket - Bowling statistics
  economy: {
    type: Number,
    default: 0,
    comment: 'Runs conceded per over'
  },
  economyChange: {
    type: Number,
    default: 0
  },
  wickets: {
    type: Number,
    default: 0
  },
  recentWickets: {
    type: Number,
    default: 0,
    comment: 'Wickets taken in the last month'
  },
  runsConceded: {
    type: Number,
    default: 0
  },
  oversBowled: {
    type: Number,
    default: 0
  },
  bowlingAverage: {
    type: Number,
    default: 0,
    comment: 'Runs conceded per wicket'
  },
  bowlingAverageChange: {
    type: Number,
    default: 0
  },
  bestBowling: {
    wickets: { type: Number, default: 0 },
    runs: { type: Number, default: 0 },
    match: { type: Schema.Types.ObjectId, ref: 'Match' }
  },
  fiferHauls: {
    type: Number,
    default: 0,
    comment: 'Number of 5 wicket hauls'
  },

  // Football - Generic statistics
  goals: {
    type: Number,
    default: 0
  },
  recentGoals: {
    type: Number,
    default: 0,
    comment: 'Goals scored in the last month'
  },
  assists: {
    type: Number,
    default: 0
  },
  recentAssists: {
    type: Number,
    default: 0
  },
  yellowCards: {
    type: Number,
    default: 0
  },
  redCards: {
    type: Number,
    default: 0
  },
  minutesPlayed: {
    type: Number,
    default: 0
  },

  // Football - Defender statistics
  tackles: {
    type: Number,
    default: 0
  },
  recentTackles: {
    type: Number,
    default: 0
  },
  clearances: {
    type: Number,
    default: 0
  },
  recentClearances: {
    type: Number,
    default: 0
  },
  interceptions: {
    type: Number,
    default: 0
  },
  cleanSheets: {
    type: Number,
    default: 0,
    comment: 'Applicable for defenders and goalkeepers'
  },

  // Football - Goalkeeper statistics
  saves: {
    type: Number,
    default: 0
  },
  savePercentage: {
    type: Number,
    default: 0
  },
  penaltySaves: {
    type: Number,
    default: 0
  },
  
  // Tracking and metadata
  lastUpdated: {
    type: Date,
    default: Date.now
  },
  seasonId: {
    type: Schema.Types.ObjectId,
    ref: 'Season',
    comment: 'Optional reference to track statistics by season'
  }
}, {
  timestamps: true
});

// Index for faster queries
StatisticsSchema.index({ user: 1, sport: 1, role: 1 });
StatisticsSchema.index({ sport: 1 });
StatisticsSchema.index({ user: 1 });

// Instance methods for calculating derived statistics
StatisticsSchema.methods = {
  /**
   * Calculate batting average
   * @returns {Number} Current batting average
   */
  calculateBattingAverage: function() {
    if (this.matches === 0) return 0;
    return this.runsScored / this.matches;
  },

  /**
   * Calculate bowling economy
   * @returns {Number} Current bowling economy
   */
  calculateEconomy: function() {
    if (this.oversBowled === 0) return 0;
    return this.runsConceded / this.oversBowled;
  },
  
  /**
   * Calculate bowling average
   * @returns {Number} Current bowling average
   */
  calculateBowlingAverage: function() {
    if (this.wickets === 0) return 0;
    return this.runsConceded / this.wickets;
  },
  
  /**
   * Calculate strike rate (batting)
   * @returns {Number} Current strike rate
   */
  calculateStrikeRate: function() {
    if (this.ballsFaced === 0) return 0;
    return (this.runsScored / this.ballsFaced) * 100;
  },
  
  /**
   * Update statistics after a match
   * @param {Object} matchStats Match statistics for this user
   * @returns {Promise} Promise that resolves when statistics are updated
   */
  updateAfterMatch: async function(matchStats) {
    // Update basic counters
    this.matches += 1;
    this.recentMatches += 1;
    
    if (matchStats.win) {
      this.wins += 1;
      this.recentWins += 1;
    } else if (matchStats.draw) {
      this.draws += 1;
    } else {
      this.losses += 1;
    }
    
    // Update sport-specific statistics based on role
    switch(this.sport.name.toLowerCase()) {
      case 'cricket':
        if (this.role.toLowerCase() === 'batsman') {
          this.runsScored += matchStats.runs || 0;
          this.recentRuns += matchStats.runs || 0;
          this.ballsFaced += matchStats.balls || 0;
          
          // Update centuries and half-centuries
          if (matchStats.runs >= 100) this.centuries += 1;
          else if (matchStats.runs >= 50) this.halfCenturies += 1;
          
          // Update highest score if applicable
          if (matchStats.runs > this.highestScore) {
            this.highestScore = matchStats.runs;
          }
          
          // Record boundaries
          this.fours += matchStats.fours || 0;
          this.sixes += matchStats.sixes || 0;
          
          // Recalculate derived stats
          this.battingAverage = this.calculateBattingAverage();
          this.strikeRate = this.calculateStrikeRate();
        } 
        else if (this.role.toLowerCase() === 'bowler') {
          this.wickets += matchStats.wickets || 0;
          this.recentWickets += matchStats.wickets || 0;
          this.runsConceded += matchStats.runsConceded || 0;
          this.oversBowled += matchStats.overs || 0;
          
          // Update best bowling if applicable
          if ((matchStats.wickets > this.bestBowling.wickets) || 
              (matchStats.wickets === this.bestBowling.wickets && 
               matchStats.runsConceded < this.bestBowling.runs)) {
            this.bestBowling = {
              wickets: matchStats.wickets,
              runs: matchStats.runsConceded,
              match: matchStats.matchId
            };
          }
          
          // Record five wicket hauls
          if (matchStats.wickets >= 5) this.fiferHauls += 1;
          
          // Recalculate derived stats
          this.economy = this.calculateEconomy();
          this.bowlingAverage = this.calculateBowlingAverage();
        }
        break;
        
      case 'football':
        // Common football stats
        this.goals += matchStats.goals || 0;
        this.recentGoals += matchStats.goals || 0;
        this.assists += matchStats.assists || 0;
        this.recentAssists += matchStats.assists || 0;
        this.yellowCards += matchStats.yellowCards || 0;
        this.redCards += matchStats.redCards || 0;
        this.minutesPlayed += matchStats.minutesPlayed || 0;
        
        if (this.role.toLowerCase() === 'defender') {
          this.tackles += matchStats.tackles || 0;
          this.recentTackles += matchStats.tackles || 0;
          this.clearances += matchStats.clearances || 0;
          this.recentClearances += matchStats.clearances || 0;
          this.interceptions += matchStats.interceptions || 0;
          if (matchStats.cleanSheet) this.cleanSheets += 1;
        }
        else if (this.role.toLowerCase() === 'goalkeeper') {
          this.saves += matchStats.saves || 0;
          this.savePercentage = matchStats.shotsOnTarget > 0 ? 
            (matchStats.saves / matchStats.shotsOnTarget) * 100 : this.savePercentage;
          this.penaltySaves += matchStats.penaltySaves || 0;
          if (matchStats.cleanSheet) this.cleanSheets += 1;
        }
        break;
        
      default:
        // Generic stats for other sports
        break;
    }
    
    // Update performance index using weighted algorithm
    this.calculatePerformanceIndex();
    
    // Update timestamp
    this.lastUpdated = Date.now();
    
    return this.save();
  },
  
  /**
   * Calculate performance index based on sport and role
   * Uses a weighted algorithm to determine overall performance
   */
  calculatePerformanceIndex: function() {
    let previousIndex = this.performanceIndex;
    let newIndex = 0;
    
    switch(this.sport.name.toLowerCase()) {
      case 'cricket':
        if (this.role.toLowerCase() === 'batsman') {
          // Weight factors for batting performance
          const avgFactor = Math.min(this.battingAverage / 50, 1) * 40; // 40% weight
          const srFactor = Math.min(this.strikeRate / 150, 1) * 30;    // 30% weight
          const matchesFactor = Math.min(this.matches / 20, 1) * 15;   // 15% weight
          const centuriesFactor = Math.min((this.centuries * 2 + this.halfCenturies) / 10, 1) * 15; // 15% weight
          
          newIndex = avgFactor + srFactor + matchesFactor + centuriesFactor;
        } 
        else if (this.role.toLowerCase() === 'bowler') {
          // Weight factors for bowling performance
          const econFactor = Math.max(0, Math.min(2 - (this.economy / 6), 1)) * 35; // 35% weight (lower is better)
          const avgFactor = Math.max(0, Math.min(2 - (this.bowlingAverage / 25), 1)) * 35; // 35% weight (lower is better)
          const matchesFactor = Math.min(this.matches / 20, 1) * 15;  // 15% weight
          const wicketsFactor = Math.min(this.wickets / 50, 1) * 15;  // 15% weight
          
          newIndex = econFactor + avgFactor + matchesFactor + wicketsFactor;
        }
        break;
        
      case 'football':
        if (this.role.toLowerCase() === 'forward') {
          // Weight factors for forwards
          const goalsFactor = Math.min(this.goals / 20, 1) * 50;      // 50% weight
          const assistsFactor = Math.min(this.assists / 15, 1) * 30;  // 30% weight
          const matchesFactor = Math.min(this.matches / 30, 1) * 20;  // 20% weight
          
          newIndex = goalsFactor + assistsFactor + matchesFactor;
        }
        else if (this.role.toLowerCase() === 'defender') {
          // Weight factors for defenders
          const tacklesFactor = Math.min(this.tackles / 100, 1) * 30;      // 30% weight
          const clearancesFactor = Math.min(this.clearances / 120, 1) * 25; // 25% weight
          const interceptionsFactor = Math.min(this.interceptions / 80, 1) * 20; // 20% weight
          const cleanSheetsFactor = Math.min(this.cleanSheets / 10, 1) * 15; // 15% weight
          const matchesFactor = Math.min(this.matches / 30, 1) * 10;       // 10% weight
          
          newIndex = tacklesFactor + clearancesFactor + interceptionsFactor + cleanSheetsFactor + matchesFactor;
        }
        else if (this.role.toLowerCase() === 'goalkeeper') {
          // Weight factors for goalkeepers
          const savesFactor = Math.min(this.savePercentage / 90, 1) * 50;   // 50% weight
          const cleanSheetsFactor = Math.min(this.cleanSheets / 15, 1) * 30; // 30% weight
          const matchesFactor = Math.min(this.matches / 30, 1) * 20;        // 20% weight
          
          newIndex = savesFactor + cleanSheetsFactor + matchesFactor;
        }
        else {
          // Midfielders and generic football roles
          const assistsFactor = Math.min(this.assists / 15, 1) * 30;   // 30% weight
          const goalsFactor = Math.min(this.goals / 10, 1) * 30;       // 30% weight
          const passSuccessFactor = Math.min(this.passSuccess / 90, 1) * 25; // 25% weight (if tracked)
          const matchesFactor = Math.min(this.matches / 30, 1) * 15;   // 15% weight
          
          newIndex = assistsFactor + goalsFactor + (this.passSuccess ? passSuccessFactor : 0) + matchesFactor;
        }
        break;
        
      default:
        // Generic performance calculation
        const winRatio = this.matches > 0 ? (this.wins / this.matches) * 100 : 0;
        newIndex = winRatio * 0.8; // 80% based on win ratio
        newIndex += Math.min(this.matches / 20, 1) * 20; // 20% based on experience
    }
    
    // Ensure index is between 0-100
    this.performanceIndex = Math.min(Math.max(Math.round(newIndex), 0), 100);
    
    // Calculate change in performance index
    this.performanceIndexChange = this.performanceIndex - previousIndex;
    
    return this.performanceIndex;
  },
  
  /**
   * Reset recent statistics (typically called at the start of each month)
   */
  resetRecentStats: function() {
    this.recentMatches = 0;
    this.recentWins = 0;
    this.recentRuns = 0;
    this.recentWickets = 0;
    this.recentGoals = 0;
    this.recentAssists = 0;
    this.recentTackles = 0;
    this.recentClearances = 0;
    
    // Calculate changes before resetting
    if (this.role.toLowerCase() === 'batsman') {
      const prevAvg = this.battingAverage;
      this.battingAverage = this.calculateBattingAverage();
      this.battingAverageChange = this.battingAverage - prevAvg;
      
      const prevSR = this.strikeRate;
      this.strikeRate = this.calculateStrikeRate();
      this.strikeRateChange = this.strikeRate - prevSR;
    }
    else if (this.role.toLowerCase() === 'bowler') {
      const prevEcon = this.economy;
      this.economy = this.calculateEconomy();
      this.economyChange = this.economy - prevEcon;
      
      const prevAvg = this.bowlingAverage;
      this.bowlingAverage = this.calculateBowlingAverage();
      this.bowlingAverageChange = this.bowlingAverage - prevAvg;
    }
    
    return this.save();
  }
};

// Static methods
StatisticsSchema.statics = {
  /**
   * Get leaderboard for a specific sport and metric
   * @param {ObjectId} sportId - Sport ID
   * @param {String} metric - Statistic to rank by (e.g., battingAverage, goals)
   * @param {String} role - Optional role filter
   * @returns {Promise<Array>} Sorted array of players and their stats
   */
  async getLeaderboard(sportId, metric, role = null) {
    const query = { sport: sportId };
    
    if (role) {
      query.role = role;
    }
    
    const sortObj = {};
    sortObj[metric] = -1; // Descending order
    
    return this.find(query)
      .sort(sortObj)
      .limit(10)
      .populate('user', 'name avatar')
      .lean();
  },
  
  /**
   * Get statistics for comparison between two players
   * @param {ObjectId} user1Id - First user ID
   * @param {ObjectId} user2Id - Second user ID
   * @param {ObjectId} sportId - Sport ID to compare
   * @returns {Promise<Object>} Object containing both users' statistics
   */
  async compareUsers(user1Id, user2Id, sportId) {
    const user1Stats = await this.findOne({ user: user1Id, sport: sportId })
      .populate('user', 'name avatar')
      .lean();
      
    const user2Stats = await this.findOne({ user: user2Id, sport: sportId })
      .populate('user', 'name avatar')
      .lean();
      
    return { user1Stats, user2Stats };
  }
};

module.exports = mongoose.model('Statistics', StatisticsSchema);