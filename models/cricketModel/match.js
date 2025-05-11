const mongoose = require("mongoose");
const Schema = mongoose.Schema;

// Match status options
const MATCH_STATUS = {
  UPCOMING: "upcoming",
  TOSS: "toss",
  LIVE: "live",
  INNINGS_BREAK: "innings_break",
  COMPLETED: "completed",
  ABANDONED: "abandoned",
  DELAYED: "delayed",
  RAIN_INTERRUPTED: "rain_interrupted",
};

// Match format options
const MATCH_FORMAT = {
  T20: "t20",
  ODI: "odi",
  TEST: "test",
};

// DLS calculation types
const DLS_TYPES = {
  RAIN_INTERRUPTION: "rain_interruption",
  INNINGS_ADJUSTMENT: "innings_adjustment",
};

const MatchSchema = new Schema({
  // Basic match information
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

  // Teams information
  team1: {
    id: {
      type: Schema.Types.ObjectId,
      ref: "Team",
      required: true,
    },
    name: {
      type: String,
      required: true,
    },
    logo: {
      type: String,
    },
    players: [
      {
        player: {
          type: Schema.Types.ObjectId,
          ref: "User",
        },
        name: String,
        isCaptain: {
          type: Boolean,
          default: false,
        },
        isWicketkeeper: {
          type: Boolean,
          default: false,
        },
      },
    ],
  },
  team2: {
    id: {
      type: Schema.Types.ObjectId,
      ref: "Team",
      required: true,
    },
    name: {
      type: String,
      required: true,
    },
    logo: {
      type: String,
    },
    players: [
      {
        player: {
          type: Schema.Types.ObjectId,
          ref: "User",
        },
        name: String,
        isCaptain: {
          type: Boolean,
          default: false,
        },
        isWicketkeeper: {
          type: Boolean,
          default: false,
        },
      },
    ],
  },

  // Toss information
  toss: {
    winner: {
      type: Schema.Types.ObjectId,
      ref: "Team",
    },
    decision: {
      type: String,
      enum: ["bat", "bowl"],
    },
    time: {
      type: Date,
    },
  },

  // Match officials
  officials: {
    umpire1: String,
    umpire2: String,
    thirdUmpire: String,
    matchReferee: String,
  },

  // Match scorers (users with permission to update the score)
  scorers: [
    {
      user: {
        type: Schema.Types.ObjectId,
        ref: "User",
        required: true,
      },
      name: String,
      addedAt: {
        type: Date,
        default: Date.now,
      },
    },
  ],

  // Current innings information
  currentInnings: {
    type: Number,
    default: 1,
    min: 1,
    max: 4, // Max for test matches
  },
  battingTeam: {
    type: Schema.Types.ObjectId,
    ref: "Team",
  },
  bowlingTeam: {
    type: Schema.Types.ObjectId,
    ref: "Team",
  },

  // Innings data
  innings: [
    {
      number: {
        type: Number,
        default: 1,
      },
      battingTeam: {
        type: Schema.Types.ObjectId,
        ref: "Team",
        required: true,
      },
      bowlingTeam: {
        type: Schema.Types.ObjectId,
        ref: "Team",
        required: true,
      },
      runs: {
        type: Number,
        default: 0,
      },
      wickets: {
        type: Number,
        default: 0,
        min: 0,
        max: 10,
      },
      overs: {
        type: Number,
        default: 0,
      },
      balls: {
        type: Number,
        default: 0,
      },
      extras: {
        wides: { type: Number, default: 0 },
        noBalls: { type: Number, default: 0 },
        byes: { type: Number, default: 0 },
        legByes: { type: Number, default: 0 },
        penalty: { type: Number, default: 0 },
      },
      totalExtras: {
        type: Number,
        default: 0,
      },
      maxOvers: {
        type: Number,
      },
      target: {
        type: Number,
      },
      requiredRunRate: {
        type: Number,
      },
      currentRunRate: {
        type: Number,
        default: 0,
      },
      partnerships: [
        {
          runs: Number,
          balls: Number,
          wicket: Number,
          players: [
            {
              player: { type: Schema.Types.ObjectId, ref: "User" },
              name: String,
            },
          ],
        },
      ],
      // Per-player batting stats
      battingStats: [
        {
          player: {
            type: Schema.Types.ObjectId,
            ref: "User",
          },
          name: String,
          runs: { type: Number, default: 0 },
          balls: { type: Number, default: 0 },
          fours: { type: Number, default: 0 },
          sixes: { type: Number, default: 0 },
          strikeRate: { type: Number, default: 0 },
          dismissalType: {
            type: String,
            enum: [
              "not_out",
              "bowled",
              "caught",
              "run_out",
              "stumped",
              "lbw",
              "hit_wicket",
              "retired_hurt",
              "retired_out",
              "obstructing_field",
              "timed_out",
              "handling_ball",
              "retired",
            ],
          },
          bowler: { type: Schema.Types.ObjectId, ref: "User" },
          fielder: { type: Schema.Types.ObjectId, ref: "User" },
          position: Number,
          inAt: Number,
          outAt: Number,
        },
      ],
      // Per-player bowling stats
      bowlingStats: [
        {
          player: {
            type: Schema.Types.ObjectId,
            ref: "User",
          },
          name: String,
          overs: { type: Number, default: 0 },
          balls: { type: Number, default: 0 },
          maidens: { type: Number, default: 0 },
          runs: { type: Number, default: 0 },
          wickets: { type: Number, default: 0 },
          economy: { type: Number, default: 0 },
          noBalls: { type: Number, default: 0 },
          wides: { type: Number, default: 0 },
        },
      ],
      // Live batsmen at the crease
      currentBatsmen: {
        striker: {
          player: { type: Schema.Types.ObjectId, ref: "User" },
          name: String,
          battingStatId: { type: Schema.Types.ObjectId },
        },
        nonStriker: {
          player: { type: Schema.Types.ObjectId, ref: "User" },
          name: String,
          battingStatId: { type: Schema.Types.ObjectId },
        },
      },
      // Current bowler
      currentBowler: {
        player: { type: Schema.Types.ObjectId, ref: "User" },
        name: String,
        bowlingStatId: { type: Schema.Types.ObjectId },
      },
      fallOfWickets: [
        {
          wicketNumber: Number,
          runs: Number,
          overs: Number,
          balls: Number,
          player: {
            type: Schema.Types.ObjectId,
            ref: "User",
          },
          playerName: String,
          dismissalType: String,
          bowler: {
            type: Schema.Types.ObjectId,
            ref: "User",
          },
          fielder: {
            type: Schema.Types.ObjectId,
            ref: "User",
          },
        },
      ],
    },
  ],

  // Over-by-over commentary
  commentary: [
    {
      over: Number,
      ball: Number,
      inningsNumber: Number, // Changed from 'innings' to 'inningsNumber' to avoid collision
      text: String,
      type: {
        type: String,
        enum: [
          "regular",
          "wicket",
          "boundary",
          "six",
          "milestone",
          "start",
          "end",
          "drinks",
          "rain",
          "dls",
          "review",
        ],
      },
      time: {
        type: Date,
        default: Date.now,
      },
    },
  ],

  // DLS method calculations
  dlsCalculations: [
    {
      type: {
        type: String,
        enum: Object.values(DLS_TYPES),
      },
      time: {
        type: Date,
        default: Date.now,
      },
      inningsNumber: Number, // Changed from 'innings' to 'inningsNumber' to avoid collision
      atOver: Number,
      atBall: Number,
      originalTarget: Number,
      revisedTarget: Number,
      oversReduced: Number,
      reason: String,
      calculatedBy: {
        type: Schema.Types.ObjectId,
        ref: "User",
      },
    },
  ],

  // Match result
  result: {
    winner: {
      type: Schema.Types.ObjectId,
      ref: "Team",
    },
    winMargin: Number,
    winMarginType: {
      type: String,
      enum: ["runs", "wickets", "draw", "tie", "no_result", "dls"],
    },
    playerOfMatch: {
      player: {
        type: Schema.Types.ObjectId,
        ref: "User",
      },
      name: String,
    },
  },

  // Match creation and modification info
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
    time: {
      type: Date,
    },
    action: String,
  },
});

// Virtual property for current innings data
MatchSchema.virtual("currentInningsData").get(function () {
  if (this.innings && this.innings.length > 0 && this.currentInnings) {
    return this.innings.find((inn) => inn.number === this.currentInnings);
  }
  return null;
});

// Pre-save middleware to update timestamps
MatchSchema.pre("save", function (next) {
  this.updatedAt = new Date();
  next();
});

// Export constants for use in other files
const MatchConstants = {
  MATCH_STATUS,
  MATCH_FORMAT,
  DLS_TYPES,
};

const Match = mongoose.model("Match", MatchSchema);

module.exports = {
  Match,
  MatchConstants,
};
