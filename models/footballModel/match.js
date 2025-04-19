const mongoose = require("mongoose");
const Schema = mongoose.Schema;

// Match status options
const MATCH_STATUS = {
  UPCOMING: "upcoming",
  FIRST_HALF: "first_half",
  HALF_TIME: "half_time",
  SECOND_HALF: "second_half",
  EXTRA_TIME: "extra_time",
  PENALTIES: "penalties",
  COMPLETED: "completed",
  ABANDONED: "abandoned",
  DELAYED: "delayed",
};

// Match format options
const MATCH_FORMAT = {
  FRIENDLY: "friendly",
  LEAGUE: "league",
  CUP: "cup",
  INTERNATIONAL: "international",
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
        shirtNumber: Number,
        isCaptain: { type: Boolean, default: false },
        position: String, // e.g., Goalkeeper, Defender, Midfielder, Forward
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
        shirtNumber: Number,
        isCaptain: { type: Boolean, default: false },
        position: String,
      },
    ],
  },

  // Match officials
  officials: {
    referee: String,
    assistant1: String,
    assistant2: String,
    fourthOfficial: String,
    varOfficial: String,
  },

  // Match scorers / stats editors
  scorers: [
    {
      user: { type: Schema.Types.ObjectId, ref: "User", required: true },
      name: String,
      addedAt: { type: Date, default: Date.now },
    },
  ],

  // Goals
  goals: [
    {
      team: { type: Schema.Types.ObjectId, ref: "Team" },
      player: { type: Schema.Types.ObjectId, ref: "User" },
      playerName: String,
      minute: Number,
      isOwnGoal: { type: Boolean, default: false },
      isPenalty: { type: Boolean, default: false },
      assistedBy: {
        player: { type: Schema.Types.ObjectId, ref: "User" },
        name: String,
      },
    },
  ],

  // Cards
  cards: [
    {
      team: { type: Schema.Types.ObjectId, ref: "Team" },
      player: { type: Schema.Types.ObjectId, ref: "User" },
      playerName: String,
      minute: Number,
      type: { type: String, enum: ["yellow", "red", "second_yellow"] },
    },
  ],

  // Substitutions
  substitutions: [
    {
      team: { type: Schema.Types.ObjectId, ref: "Team" },
      playerOut: { type: Schema.Types.ObjectId, ref: "User" },
      playerOutName: String,
      playerIn: { type: Schema.Types.ObjectId, ref: "User" },
      playerInName: String,
      minute: Number,
    },
  ],

  // Match stats per player (optional, can be expanded later)
  playerStats: [
    {
      player: { type: Schema.Types.ObjectId, ref: "User" },
      name: String,
      team: { type: Schema.Types.ObjectId, ref: "Team" },
      minutesPlayed: Number,
      goals: Number,
      assists: Number,
      yellowCards: Number,
      redCards: Number,
      passesCompleted: Number,
      shotsOnTarget: Number,
      saves: Number, // For goalkeepers
    },
  ],

  // Commentary (optional)
  commentary: [
    {
      minute: Number,
      text: String,
      type: {
        type: String,
        enum: [
          "goal",
          "card",
          "substitution",
          "start",
          "half_time",
          "end",
          "injury",
          "regular",
        ],
      },
      time: { type: Date, default: Date.now },
    },
  ],

  // Result
  result: {
    winner: { type: Schema.Types.ObjectId, ref: "Team" },
    winType: {
      type: String,
      enum: ["normal", "extra_time", "penalties", "draw"],
    },
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
