// controllers/auth.controller.js
const { admin, auth } = require('../config/firebase-config');
const { 
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  sendEmailVerification,
  sendPasswordResetEmail,
  updatePassword
} = require('firebase/auth');
const User = require('../models/userModel');
const { hashPassword, comparePassword } = require('../utils/password_utils');
const { generateToken } = require('../config/jwt_config');

const authController = {
  signup: async (req, res) => {
    try {
      const { name, email, password, location, dateOfBirth } = req.body;

      // Check if user already exists in MongoDB
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: 'User already exists' });
      }

      // Create user in Firebase
      const userCredential = await createUserWithEmailAndPassword(auth, email, password);
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
        isEmailVerified: false
      });

      await user.save();

      // Generate JWT token
      const token = generateToken({
        userId: user._id,
        firebaseToken: await firebaseUser.getIdToken()
      });

      res.status(201).json({ 
        message: 'User created successfully. Please verify your email.',
        token,
        userId: firebaseUser.uid 
      });
    } catch (error) {
      console.error('Signup error:', error);
      res.status(400).json({ 
        message: 'Signup failed', 
        error: error.message 
      });
    }
  },

  login: async (req, res) => {
    try {
      const { email, password } = req.body;

      // Find user in MongoDB
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      // Verify password
      const isPasswordValid = await comparePassword(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Sign in with Firebase
      const userCredential = await signInWithEmailAndPassword(auth, email, password);
      const firebaseUser = userCredential.user;

      // Check if email is verified
      if (!firebaseUser.emailVerified) {
        return res.status(403).json({ 
          message: 'Please verify your email first',
          verified: false
        });
      }

      // Generate Firebase token
      const firebaseToken = await firebaseUser.getIdToken();

      // Generate JWT token
      const token = generateToken({
        userId: user._id,
        firebaseToken
      });

      // Update email verification status in MongoDB if needed
      if (firebaseUser.emailVerified && !user.isEmailVerified) {
        user.isEmailVerified = true;
        await user.save();
      }

      res.json({ 
        token,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          location: user.location,
          dateOfBirth: user.dateOfBirth,
          isEmailVerified: user.isEmailVerified
        }
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(401).json({ 
        message: 'Login failed', 
        error: error.message 
      });
    }
  },

  forgotPassword: async (req, res) => {
    try {
      const { email } = req.body;

      // Find user in MongoDB
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
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
        message: 'Password reset email sent successfully',
        resetToken 
      });
    } catch (error) {
      console.error('Forgot password error:', error);
      res.status(400).json({ 
        message: 'Failed to send reset email', 
        error: error.message 
      });
    }
  },

  resetPassword: async (req, res) => {
    try {
      const { token, newPassword } = req.body;

      // Find user with valid reset token
      const user = await User.findOne({
        resetPasswordToken: token,
        resetPasswordExpires: { $gt: Date.now() }
      });

      if (!user) {
        return res.status(400).json({ message: 'Invalid or expired reset token' });
      }

      // Update Firebase password
      const firebaseUser = await admin.auth().getUser(user.firebaseUid);
      await admin.auth().updateUser(user.firebaseUid, {
        password: newPassword
      });

      // Hash new password for MongoDB
      const hashedPassword = await hashPassword(newPassword);

      // Update MongoDB password and clear reset token
      user.password = hashedPassword;
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      await user.save();

      res.json({ message: 'Password reset successful' });
    } catch (error) {
      console.error('Reset password error:', error);
      res.status(400).json({ 
        message: 'Failed to reset password', 
        error: error.message 
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
        return res.status(404).json({ message: 'User not found' });
      }

      // Get Firebase user
      const firebaseUser = await admin.auth().getUser(user.firebaseUid);
      
      if (!firebaseUser.emailVerified) {
        // Update Firebase email verification status
        await admin.auth().updateUser(user.firebaseUid, {
          emailVerified: true
        });
      }

      // Update MongoDB user
      user.isEmailVerified = true;
      await user.save();

      res.json({ 
        message: 'Email verified successfully',
        verified: true
      });
    } catch (error) {
      console.error('Email verification error:', error);
      res.status(400).json({ 
        message: 'Failed to verify email', 
        error: error.message 
      });
    }
  },

  resendVerificationEmail: async (req, res) => {
    try {
      const { email } = req.body;

      // Find user in MongoDB
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      // Check if email is already verified
      if (user.isEmailVerified) {
        return res.status(400).json({ message: 'Email is already verified' });
      }

      // Get current Firebase user
      const firebaseUser = await admin.auth().getUser(user.firebaseUid);
      
      // Send new verification email
      const customToken = await admin.auth().createCustomToken(user.firebaseUid);
      await signInWithCustomToken(auth, customToken);
      await sendEmailVerification(auth.currentUser);

      res.json({ message: 'Verification email resent successfully' });
    } catch (error) {
      console.error('Resend verification error:', error);
      res.status(400).json({ 
        message: 'Failed to resend verification email', 
        error: error.message 
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
        return res.status(404).json({ message: 'User not found' });
      }

      // Verify current password
      const isPasswordValid = await comparePassword(currentPassword, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ message: 'Current password is incorrect' });
      }

      // Update Firebase password
      await updatePassword(auth.currentUser, newPassword);

      // Hash new password for MongoDB
      const hashedPassword = await hashPassword(newPassword);
      
      // Update MongoDB password
      user.password = hashedPassword;
      await user.save();

      res.json({ message: 'Password changed successfully' });
    } catch (error) {
      console.error('Change password error:', error);
      res.status(400).json({ 
        message: 'Failed to change password', 
        error: error.message 
      });
    }
  }
};

module.exports = authController;