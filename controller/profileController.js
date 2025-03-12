// controllers/profile.controller.js
const User = require("../models/userModel");
const { admin } = require("../config/firebase-config");

// Define valid sports and roles (using the same constants from auth.controller)
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

const profileController = {
  // Get user profile
  getProfile: async (req, res) => {
    try {
      const { userId } = req.user; // From auth middleware

      // Find user in MongoDB
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Get Firebase user for profile picture URL
      const firebaseUser = await admin.auth().getUser(user.firebaseUid);
      const profilePicUrl = firebaseUser.photoURL || null;

      // Get sports with static statistics
      const sports = user.sports.map((sport) => {
        // Get static statistics for this sport and role
        const stats = STATIC_STATS[sport.name] && STATIC_STATS[sport.name][sport.role]
          ? STATIC_STATS[sport.name][sport.role]
          : {};

        return {
          ...sport,
          statistics: stats,
        };
      });

      res.status(200).json({
        profile: {
          id: user._id,
          name: user.name,
          location: user.location,
          profilePicture: profilePicUrl,
          sports: sports,
        },
      });
    } catch (error) {
      console.error("Get profile error:", error);
      res.status(500).json({
        message: "Failed to get profile",
        error: error.message,
      });
    }
  },
  getProfileById: async (req, res) => {
    try {
      const { id } = req.params;

      // Find user in MongoDB
      const user = await User.findById(id);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Get Firebase user for profile picture URL
      const firebaseUser = await admin.auth().getUser(user.firebaseUid);
      const profilePicUrl = firebaseUser.photoURL || null;

      // Get sports with static statistics
      const sports = user.sports.map((sport) => {
        // Get static statistics for this sport and role
        const stats = STATIC_STATS[sport.name] && STATIC_STATS[sport.name][sport.role]
          ? STATIC_STATS[sport.name][sport.role]
          : {};

        return {
          ...sport,
          statistics: stats,
        };
      });

      // Return public profile information
      res.status(200).json({
        profile: {
          id: user._id,
          name: user.name,
          location: user.location,
          profilePicture: profilePicUrl,
          sports: sports,
          // Exclude sensitive information for other users' profiles
        },
      });
    } catch (error) {
      console.error("Get profile by ID error:", error);
      res.status(500).json({
        message: "Failed to get profile",
        error: error.message,
      });
    }
  },

  // Update profile picture
  updateProfilePicture: async (req, res) => {
    try {
      const { userId } = req.user;
      const { photoURL } = req.body;

      if (!photoURL) {
        return res.status(400).json({ message: "Photo URL is required" });
      }

      // Find user in MongoDB
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Update Firebase user photo URL
      await admin.auth().updateUser(user.firebaseUid, {
        photoURL: photoURL,
      });

      res.status(200).json({ 
        message: "Profile picture updated successfully",
        photoURL: photoURL
      });
    } catch (error) {
      console.error("Update profile picture error:", error);
      res.status(500).json({
        message: "Failed to update profile picture",
        error: error.message,
      });
    }
  },

  // Update profile information
  updateProfile: async (req, res) => {
    try {
      const { userId } = req.user;
      const { name, location } = req.body;

      // Validate inputs
      if (!name && !location) {
        return res.status(400).json({ message: "No updates provided" });
      }

      // Find user in MongoDB
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Update user fields if provided
      if (name) user.name = name;
      if (location) user.location = location;

      // Save updates
      await user.save();

      // If name was updated, also update in Firebase
      if (name) {
        await admin.auth().updateUser(user.firebaseUid, {
          displayName: name,
        });
      }

      res.status(200).json({
        message: "Profile updated successfully",
        profile: {
          name: user.name,
          location: user.location,
        },
      });
    } catch (error) {
      console.error("Update profile error:", error);
      res.status(500).json({
        message: "Failed to update profile",
        error: error.message,
      });
    }
  },

  // Add a new sport to user's profile
  addSport: async (req, res) => {
    try {
      const { userId } = req.user;
      const { sportName, sportRole } = req.body;

      // Validate sport and role
      if (!sportName || !sportRole) {
        return res.status(400).json({ message: "Sport name and role are required" });
      }

      if (!VALID_SPORTS.includes(sportName)) {
        return res.status(400).json({ message: "Invalid sport selected" });
      }

      if (!VALID_ROLES[sportName].includes(sportRole)) {
        return res.status(400).json({ message: "Invalid role for selected sport" });
      }

      // Find user in MongoDB
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Check if sport already exists
      const sportExists = user.sports.some(
        (s) => s.name === sportName && s.role === sportRole
      );

      if (sportExists) {
        return res.status(400).json({ message: "Sport already added to profile" });
      }

      // Add new sport
      user.sports.push({ name: sportName, role: sportRole });
      await user.save();

      // Get static statistics for this sport and role
      const stats = STATIC_STATS[sportName] && STATIC_STATS[sportName][sportRole]
        ? STATIC_STATS[sportName][sportRole]
        : {};

      res.status(200).json({
        message: "Sport added successfully",
        sport: {
          name: sportName,
          role: sportRole,
          statistics: stats,
        },
      });
    } catch (error) {
      console.error("Add sport error:", error);
      res.status(500).json({
        message: "Failed to add sport",
        error: error.message,
      });
    }
  },

  // Remove a sport from user's profile
  removeSport: async (req, res) => {
    try {
      const { userId } = req.user;
      const { sportName, sportRole } = req.body;

      // Validate inputs
      if (!sportName || !sportRole) {
        return res.status(400).json({ message: "Sport name and role are required" });
      }

      // Find user in MongoDB
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Find sport in user's sports array
      const sportIndex = user.sports.findIndex(
        (s) => s.name === sportName && s.role === sportRole
      );

      if (sportIndex === -1) {
        return res.status(404).json({ message: "Sport not found in profile" });
      }

      // Remove sport
      user.sports.splice(sportIndex, 1);
      await user.save();

      res.status(200).json({
        message: "Sport removed successfully",
        remainingSports: user.sports,
      });
    } catch (error) {
      console.error("Remove sport error:", error);
      res.status(500).json({
        message: "Failed to remove sport",
        error: error.message,
      });
    }
  },

  // Get available sports options (reused from auth.controller)
  getSportsOptions: async (req, res) => {
    try {
      // Format sports options for frontend
      const sportsOptions = VALID_SPORTS.map(sport => ({
        name: sport,
        roles: VALID_ROLES[sport]
      }));
      
      res.json({ sports: sportsOptions });
    } catch (error) {
      console.error("Get sports options error:", error);
      res.status(500).json({
        message: "Failed to get sports options",
        error: error.message,
      });
    }
  },

  // Get statistics for a specific sport (placeholder for future dynamic stats)
  getSportStatistics: async (req, res) => {
    try {
      const { userId } = req.user;
      const { sportName, sportRole } = req.params;

      // Find user in MongoDB
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Check if user has this sport
      const hasSport = user.sports.some(
        (s) => s.name === sportName && s.role === sportRole
      );

      if (!hasSport) {
        return res.status(404).json({ message: "Sport not found in user profile" });
      }

      // Get static statistics for this sport and role
      const stats = STATIC_STATS[sportName] && STATIC_STATS[sportName][sportRole]
        ? STATIC_STATS[sportName][sportRole]
        : {};

      res.status(200).json({
        sport: {
          name: sportName,
          role: sportRole,
          statistics: stats,
        },
      });
    } catch (error) {
      console.error("Get sport statistics error:", error);
      res.status(500).json({
        message: "Failed to get sport statistics",
        error: error.message,
      });
    }
  },
};

module.exports = profileController;