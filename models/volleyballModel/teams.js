const mongoose = require("mongoose");

const teamSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    description: {
      type: String,
      trim: true,
    },
    logo: {
      type: String, // URL or base64 string for the logo
      default: null,
    },
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    members: [
      {
        user: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
        },
        role: {
          type: String,
          enum: ["admin", "member"],
          default: "member",
        },
        joinedAt: {
          type: Date,
          default: Date.now,
        },
        position: {
          type: String,
          enum: [
            "setter",
            "libero",
            "outside_hitter",
            "middle_blocker",
            "opposite_hitter",
            "defensive_specialist",
          ],
          default: "outside_hitter",
        },
      },
    ],
    captain: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
    viceCaptain: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
    creationStep: {
      type: Number,
      enum: [1, 2, 3, 4], // 1: Initial, 2: Members Added, 3: Captains Assigned, 4: Completed
      default: 1,
    },
    createdAt: {
      type: Date,
      default: null, // Will be set when team creation is completed
    },
    updatedAt: {
      type: Date,
      default: Date.now,
    },
    activeSport: {
      type: String,
      default: "Volleyball",
    },
  },
  { timestamps: { createdAt: false, updatedAt: true } }
);

module.exports = mongoose.model("VolleyballTeam", teamSchema);
