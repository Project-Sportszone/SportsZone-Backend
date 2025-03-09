// controllers/auth.controller.js
const { admin, auth } = require("../config/firebase-config");
const {
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  sendEmailVerification,
  sendPasswordResetEmail,
  updatePassword,
} = require("firebase/auth");
const User = require("../models/userModel");
const { hashPassword, comparePassword } = require("../utils/password_utils");
const { generateToken } = require("../config/jwt_config");

// Define valid sports and roles
const VALID_SPORTS = ["Cricket", "Football", "Volleyball", "Badminton"];
const VALID_ROLES = {
  Cricket: ["Batsman", "Bowler", "All-rounder", "Wicketkeeper"],
  Football: ["Striker", "Midfielder", "Defender", "Goalkeeper"],
  Volleyball: ["Setter", "Spiker", "Libero"],
  Badminton: ["Singles Player", "Doubles Player"],
};

const authController = {
  signup: async (req, res) => {
    try {
      const { name, email, password, location, dateOfBirth } = req.body;

      // Check if user already exists in MongoDB
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: "User already exists" });
      }

      // Create user in Firebase
      const userCredential = await createUserWithEmailAndPassword(
        auth,
        email,
        password
      );
      const firebaseUser = userCredential.user;

      // Hash password for MongoDB storage
      const hashedPassword = await hashPassword(password);

      // Send verification email
      await sendEmailVerification(firebaseUser);

      // Create user in MongoDB
      const user = new User({
        name,
        email,
        password: hashedPassword,
        location,
        dateOfBirth,
        firebaseUid: firebaseUser.uid,
        isEmailVerified: false,
        sports: [],
        isFirstLogin: true,
        onboardingStep: 0, // 0: Not started, 1: Sports selection, 2: Confirmation, 3: Completed
      });

      await user.save();

      // Generate JWT token
      const token = generateToken({
        userId: user._id,
        firebaseToken: await firebaseUser.getIdToken(),
      });

      res.status(201).json({
        message: "User created successfully. Please verify your email.",
        token,
        userId: firebaseUser.uid,
        onboardingRequired: true,
        currentStep: 0,
      });
    } catch (error) {
      console.error("Signup error:", error);
      res.status(400).json({
        message: "Signup failed",
        error: error.message,
      });
    }
  },

  login: async (req, res) => {
    try {
      const { email, password } = req.body;

      // Find user in MongoDB
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Verify password
      const isPasswordValid = await comparePassword(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      // Sign in with Firebase
      const userCredential = await signInWithEmailAndPassword(
        auth,
        email,
        password
      );
      const firebaseUser = userCredential.user;

      // Check if email is verified
      if (!firebaseUser.emailVerified) {
        return res.status(403).json({
          message: "Please verify your email first",
          verified: false,
        });
      }

      // Generate Firebase token
      const firebaseToken = await firebaseUser.getIdToken();

      // Generate JWT token
      const token = generateToken({
        userId: user._id,
        firebaseToken,
        sports: user.sports,
      });

      // Update email verification status in MongoDB if needed
      if (firebaseUser.emailVerified && !user.isEmailVerified) {
        user.isEmailVerified = true;
        await user.save();
      }

      // Determine if onboarding is required
      const onboardingRequired = user.isFirstLogin;
      const currentStep = user.onboardingStep || 0;

      res.status(200).json({
        token,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          location: user.location,
          dateOfBirth: user.dateOfBirth,
          isEmailVerified: user.isEmailVerified,
          sports: user.sports,
        },
        onboardingRequired,
        currentStep,
      });
    } catch (error) {
      console.error("Login error:", error);
      res.status(401).json({
        message: "Login failed",
        error: error.message,
      });
    }
  },

  // Check onboarding status
  checkOnboardingStatus: async (req, res) => {
    try {
      const { userId } = req.user;
      
      // Find user in MongoDB
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      res.json({
        onboardingRequired: user.isFirstLogin,
        currentStep: user.onboardingStep || 0,
        isEmailVerified: user.isEmailVerified
      });
    } catch (error) {
      console.error("Onboarding status check error:", error);
      res.status(500).json({
        message: "Failed to check onboarding status",
        error: error.message,
      });
    }
  },
  
  // Start the onboarding process
  startOnboarding: async (req, res) => {
    try {
      const { userId } = req.user;
      
      // Find user in MongoDB
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      // Verify email first
      if (!user.isEmailVerified) {
        return res.status(403).json({
          message: "Please verify your email before starting onboarding",
          verified: false
        });
      }
      
      // Start onboarding if not already started
      if (user.onboardingStep === 0) {
        user.onboardingStep = 1; // Step 1: Sports selection
        await user.save();
      }
      
      res.json({
        message: "Onboarding started",
        currentStep: user.onboardingStep
      });
    } catch (error) {
      console.error("Start onboarding error:", error);
      res.status(500).json({
        message: "Failed to start onboarding",
        error: error.message,
      });
    }
  },
  
  // Update onboarding steps
  updateOnboardingStep: async (req, res) => {
    try {
      const { userId } = req.user;
      const { step, selectedSports, complete } = req.body;
      
      // Find user in MongoDB
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      // Validate step sequence
      if (user.onboardingStep !== step) {
        return res.status(400).json({ message: "Invalid step sequence" });
      }
      
      // Step 1: Sports selection
      if (step === 1 && selectedSports) {
        // Validate sports and roles
        const validSelectedSports = selectedSports.filter(
          (s) => VALID_SPORTS.includes(s.name) && VALID_ROLES[s.name].includes(s.role)
        );
        
        if (validSelectedSports.length === 0) {
          return res.status(400).json({ message: "Invalid sports or roles selected" });
        }
        
        // Update user's sports preferences
        user.sports = validSelectedSports;
        user.onboardingStep = 2; // Move to Step 2: Confirmation
        await user.save();
        
        return res.json({
          message: "Sports preferences saved",
          currentStep: 2
        });
      }
      
      // Step 2: Complete onboarding
      if (step === 2 && complete) {
        // Finalize onboarding
        user.isFirstLogin = false;
        user.onboardingStep = 3; // Onboarding completed
        await user.save();
        
        return res.json({
          message: "Onboarding completed successfully",
          onboardingRequired: false
        });
      }
      
      // Invalid step update
      return res.status(400).json({ message: "Invalid step data" });
    } catch (error) {
      console.error("Update onboarding step error:", error);
      res.status(500).json({
        message: "Failed to update onboarding step",
        error: error.message,
      });
    }
  },
  
  // Get available sports options
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

  forgotPassword: async (req, res) => {
    try {
      const { email } = req.body;

      // Find user in MongoDB
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Send password reset email using Firebase
      await sendPasswordResetEmail(auth, email);

      // Generate reset token
      const resetToken = generateToken({ userId: user._id });

      // Update user with reset token
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
      await user.save();

      res.json({
        message: "Password reset email sent successfully",
        resetToken,
      });
    } catch (error) {
      console.error("Forgot password error:", error);
      res.status(400).json({
        message: "Failed to send reset email",
        error: error.message,
      });
    }
  },

  resetPassword: async (req, res) => {
    try {
      const { token, newPassword } = req.body;

      // Find user with valid reset token
      const user = await User.findOne({
        resetPasswordToken: token,
        resetPasswordExpires: { $gt: Date.now() },
      });

      if (!user) {
        return res
          .status(400)
          .json({ message: "Invalid or expired reset token" });
      }

      // Update Firebase password
      const firebaseUser = await admin.auth().getUser(user.firebaseUid);
      await admin.auth().updateUser(user.firebaseUid, {
        password: newPassword,
      });

      // Hash new password for MongoDB
      const hashedPassword = await hashPassword(newPassword);

      // Update MongoDB password and clear reset token
      user.password = hashedPassword;
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      await user.save();

      res.json({ message: "Password reset successful" });
    } catch (error) {
      console.error("Reset password error:", error);
      res.status(400).json({
        message: "Failed to reset password",
        error: error.message,
      });
    }
  },

  verifyEmail: async (req, res) => {
    try {
      const { token } = req.params;

      // Verify the token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.userId);

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Get Firebase user
      const firebaseUser = await admin.auth().getUser(user.firebaseUid);

      if (!firebaseUser.emailVerified) {
        // Update Firebase email verification status
        await admin.auth().updateUser(user.firebaseUid, {
          emailVerified: true,
        });
      }

      // Update MongoDB user
      user.isEmailVerified = true;
      await user.save();

      res.json({
        message: "Email verified successfully",
        verified: true,
        onboardingRequired: user.isFirstLogin,
        currentStep: user.onboardingStep
      });
    } catch (error) {
      console.error("Email verification error:", error);
      res.status(400).json({
        message: "Failed to verify email",
        error: error.message,
      });
    }
  },

  resendVerificationEmail: async (req, res) => {
    try {
      const { email } = req.body;

      // Find user in MongoDB
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Check if email is already verified
      if (user.isEmailVerified) {
        return res.status(400).json({ message: "Email is already verified" });
      }

      // Get current Firebase user
      const firebaseUser = await admin.auth().getUser(user.firebaseUid);

      // Send new verification email
      const customToken = await admin
        .auth()
        .createCustomToken(user.firebaseUid);
      await signInWithCustomToken(auth, customToken);
      await sendEmailVerification(auth.currentUser);

      res.json({ message: "Verification email resent successfully" });
    } catch (error) {
      console.error("Resend verification error:", error);
      res.status(400).json({
        message: "Failed to resend verification email",
        error: error.message,
      });
    }
  },

  changePassword: async (req, res) => {
    try {
      const { userId } = req.user; // From auth middleware
      const { currentPassword, newPassword } = req.body;

      // Find user in MongoDB
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Verify current password
      const isPasswordValid = await comparePassword(
        currentPassword,
        user.password
      );
      if (!isPasswordValid) {
        return res
          .status(401)
          .json({ message: "Current password is incorrect" });
      }

      // Update Firebase password
      await updatePassword(auth.currentUser, newPassword);

      // Hash new password for MongoDB
      const hashedPassword = await hashPassword(newPassword);

      // Update MongoDB password
      user.password = hashedPassword;
      await user.save();

      res.json({ message: "Password changed successfully" });
    } catch (error) {
      console.error("Change password error:", error);
      res.status(400).json({
        message: "Failed to change password",
        error: error.message,
      });
    }
  },

  // Legacy onboarding method (now replaced by multi-step process)
  onboarding: async (req, res) => {
    try {
      const { userId } = req.user;
      const { sports } = req.body;

      const validSports = VALID_SPORTS;
      const validRoles = VALID_ROLES;

      const assignedSports = sports.filter(
        (s) =>
          validSports.includes(s.name) && validRoles[s.name].includes(s.role)
      );

      if (assignedSports.length === 0) {
        return res
          .status(400)
          .json({ message: "Invalid sports or roles selected" });
      }

      await User.findByIdAndUpdate(userId, {
        sports: assignedSports,
        isFirstLogin: false,
        onboardingStep: 3 // Completed
      });

      res.json({ message: "Onboarding completed successfully" });
    } catch (error) {
      console.error("Onboarding error:", error);
      res
        .status(400)
        .json({ message: "Onboarding failed", error: error.message });
    }
  },

  logout: async (req, res) => {
    try {
      const { userId } = req.user; // From auth middleware
      
      // Find user in MongoDB
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // You may want to add any tokens to a blacklist in a production environment
      // This could be implemented with Redis or another fast storage solution
      
      // Optionally update the last logout time
      user.lastLogout = new Date();
      await user.save();

      res.status(200).json({ message: "Logout successful" });
    } catch (error) {
      console.error("Logout error:", error);
      res.status(500).json({
        message: "Logout failed",
        error: error.message,
      });
    }
  }
};

module.exports = authController;