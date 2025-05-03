const mongoose = require('mongoose');

const ScorecardSchema = new mongoose.Schema({
  match: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Match',
    required: [true, 'Scorecard must be linked to a match']
  },
  // Common fields for all sports
  team1Score: {
    type: Number,
    default: 0
  },
  team2Score: {
    type: Number,
    default: 0
  },
  // Cricket-specific fields
  team1Wickets: {
    type: Number,
    default: 0
  },
  team1Overs: {
    type: Number,
    default: 0
  },
  team2Wickets: {
    type: Number,
    default: 0
  },
  team2Overs: {
    type: Number,
    default: 0
  },
  team2BattingStarted: {
    type: Boolean,
    default: false
  },
  currentBatsmen: [{
    name: String,
    playerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    runs: {
      type: Number,
      default: 0
    },
    balls: {
      type: Number,
      default: 0
    }
  }],
  currentBowler: {
    name: String,
    playerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    balls: {
      type: Number,
      default: 0
    },
    runs: {
      type: Number,
      default: 0
    },
    wickets: {
      type: Number,
      default: 0
    }
  },
  currentOverBalls: [mongoose.Schema.Types.Mixed],
  currentOverSummary: String,
  
  // Football-specific fields
  currentTime: String,
  recentEvents: [{
    type: String
  }],
  
  // Generic fields
  currentPeriod: String,
  
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Update the updatedAt field on save
ScorecardSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('Scorecard', ScorecardSchema);
