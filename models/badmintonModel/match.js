const mongoose = require("mongoose");
const Schema = mongoose.Schema;

// Match status options
const MATCH_STATUS = {
  UPCOMING: "upcoming",
  LIVE: "live",
  COMPLETED: "completed",
  ABANDONED: "abandoned",
  DELAYED: "delayed",
};

// Match format options
const MATCH_FORMAT = {
  SINGLES: "singles",
  DOUBLES: "doubles",
  MIXED_DOUBLES: "mixed_doubles",
};

const MatchSchema = new Schema({
  title: {
    type: String,
    required: true,
    trim: true,
  },
  format: {
    type: String,
    required: true,
    enum: Object.values(MATCH_FORMAT),
  },
  venue: {
    type: String,
    required: true,
  },
  matchDate: {
    type: Date,
    required: true,
  },
  status: {
    type: String,
    default: MATCH_STATUS.UPCOMING,
    enum: Object.values(MATCH_STATUS),
  },

  // Players or teams info depending on format
  player1: {
    id: { type: Schema.Types.ObjectId, ref: "Team", required: true },
    name: { type: String, required: true },
    logo: String,
    members: [
      {
        player: { type: Schema.Types.ObjectId, ref: "User" },
        name: String,
        position: String, // e.g., Left, Right for doubles
      },
    ],
  },
  player2: {
    id: { type: Schema.Types.ObjectId, ref: "Team", required: true },
    name: { type: String, required: true },
    logo: String,
    members: [
      {
        player: { type: Schema.Types.ObjectId, ref: "User" },
        name: String,
        position: String,
      },
    ],
  },

  // Match officials
  officials: {
    umpire: String,
    serviceJudge: String,
    referee: String,
  },

  // Match scorers / stats editors
  scorers: [
    {
      user: { type: Schema.Types.ObjectId, ref: "User", required: true },
      name: String,
      addedAt: { type: Date, default: Date.now },
    },
  ],

  // Scores per game (best of 3 or 5 games)
  games: [
    {
      gameNumber: Number,
      player1Score: Number,
      player2Score: Number,
      winner: { type: Schema.Types.ObjectId, ref: "Team" },
    },
  ],

  // Commentary (optional)
  commentary: [
    {
      time: { type: Date, default: Date.now },
      text: String,
      type: {
        type: String,
        enum: ["point", "fault", "start", "end", "injury", "regular"],
      },
    },
  ],

  // Result
  result: {
    winner: { type: Schema.Types.ObjectId, ref: "Team" },
    playerOfMatch: {
      player: { type: Schema.Types.ObjectId, ref: "User" },
      name: String,
    },
  },

  // Timestamps
  createdBy: {
    type: Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
  lastScorerAction: {
    user: {
      type: Schema.Types.ObjectId,
      ref: "User",
    },
    time: Date,
    action: String,
  },
});

// Pre-save middleware to update timestamps
MatchSchema.pre("save", function (next) {
  this.updatedAt = new Date();
  next();
});

// Export constants
const MatchConstants = {
  MATCH_STATUS,
  MATCH_FORMAT,
};

const Match = mongoose.model("Match", MatchSchema);

module.exports = {
  Match,
  MatchConstants,
};
