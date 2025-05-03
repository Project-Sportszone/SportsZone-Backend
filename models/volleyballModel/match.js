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
  SETS_3: "best_of_3",
  SETS_5: "best_of_5",
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

  // Teams info
  team1: {
    id: { type: Schema.Types.ObjectId, ref: "Team", required: true },
    name: { type: String, required: true },
    logo: String,
    players: [
      {
        player: { type: Schema.Types.ObjectId, ref: "User" },
        name: String,
        position: String, // e.g., Setter, Libero, etc.
      },
    ],
  },
  team2: {
    id: { type: Schema.Types.ObjectId, ref: "Team", required: true },
    name: { type: String, required: true },
    logo: String,
    players: [
      {
        player: { type: Schema.Types.ObjectId, ref: "User" },
        name: String,
        position: String,
      },
    ],
  },

  // Match officials
  officials: {
    referee: String,
    umpire1: String,
    umpire2: String,
    scorer: String,
  },

  // Match scorers / stats editors
  scorers: [
    {
      user: { type: Schema.Types.ObjectId, ref: "User", required: true },
      name: String,
      addedAt: { type: Date, default: Date.now },
    },
  ],

  // Scores per set (best of 3 or 5 sets)
  sets: [
    {
      setNumber: Number,
      team1Score: Number,
      team2Score: Number,
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

const Match = mongoose.model("VolleyballMatch", MatchSchema);

module.exports = {
  Match,
  MatchConstants,
};
