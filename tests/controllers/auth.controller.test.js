const authController = require('../../controller/authController');
const User = require('../../models/userModel');
const { admin, auth } = require('../../config/firebase-config');
const { hashPassword, comparePassword } = require('../../utils/password_utils');
const { generateToken } = require('../../config/jwt_config');
const {
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  sendEmailVerification,
  sendPasswordResetEmail,
  updatePassword,
} = require('firebase/auth');

// Mock dependencies
jest.mock('../../models/userModel');
jest.mock('../../config/firebase-config');
jest.mock('../../utils/password_utils');
jest.mock('../../config/jwt_config');
jest.mock('firebase/auth');

describe('Auth Controller', () => {
  let req, res;

  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();
    
    // Setup request and response objects
    req = {
      body: {},
      user: { userId: 'mockUserId' },
      params: {},
    };
    
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
  });

  describe('signup', () => {
    beforeEach(() => {
      req.body = {
        name: 'Test User',
        email: 'test@example.com',
        password: 'Password123',
        location: 'Test City',
        dateOfBirth: '1990-01-01',
      };
      
      // Mock implementations
      User.findOne.mockResolvedValue(null);
      hashPassword.mockResolvedValue('hashedPassword');
      
      const mockFirebaseUser = {
        uid: 'firebaseUid123',
        getIdToken: jest.fn().mockResolvedValue('mockFirebaseToken'),
      };
      
      createUserWithEmailAndPassword.mockResolvedValue({
        user: mockFirebaseUser,
      });
      
      sendEmailVerification.mockResolvedValue();
      
      User.prototype.save = jest.fn().mockResolvedValue({
        _id: 'mongoUserId123',
        ...req.body,
        password: 'hashedPassword',
        firebaseUid: 'firebaseUid123',
      });
      
      generateToken.mockReturnValue('jwtToken123');
    });

    it('should create a new user successfully', async () => {
      await authController.signup(req, res);

      // Assertions
      expect(User.findOne).toHaveBeenCalledWith({ email: req.body.email });
      expect(createUserWithEmailAndPassword).toHaveBeenCalledWith(
        auth,
        req.body.email,
        req.body.password
      );
      expect(hashPassword).toHaveBeenCalledWith(req.body.password);
      expect(sendEmailVerification).toHaveBeenCalled();
      expect(User.prototype.save).toHaveBeenCalled();
      expect(generateToken).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        message: expect.any(String),
        token: 'jwtToken123',
        userId: 'firebaseUid123',
      }));
    });

    it('should return 400 if user already exists', async () => {
      User.findOne.mockResolvedValue({ _id: 'existingUserId' });

      await authController.signup(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        message: 'User already exists',
      }));
      expect(createUserWithEmailAndPassword).not.toHaveBeenCalled();
    });

    it('should handle errors during signup', async () => {
      createUserWithEmailAndPassword.mockRejectedValue(new Error('Firebase error'));

      await authController.signup(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        message: 'Signup failed',
        error: 'Firebase error',
      }));
    });
  });

  describe('login', () => {
    beforeEach(() => {
      req.body = {
        email: 'test@example.com',
        password: 'Password123',
      };
      
      // Mock implementations
      const mockUser = {
        _id: 'mongoUserId123',
        email: req.body.email,
        password: 'hashedPassword',
        name: 'Test User',
        location: 'Test City',
        dateOfBirth: '1990-01-01',
        isEmailVerified: true,
        sports: [],
        save: jest.fn().mockResolvedValue(true),
      };
      
      User.findOne.mockResolvedValue(mockUser);
      comparePassword.mockResolvedValue(true);
      
      const mockFirebaseUser = {
        uid: 'firebaseUid123',
        emailVerified: true,
        getIdToken: jest.fn().mockResolvedValue('mockFirebaseToken'),
      };
      
      signInWithEmailAndPassword.mockResolvedValue({
        user: mockFirebaseUser,
      });
      
      generateToken.mockReturnValue('jwtToken123');
    });

    it('should login a user successfully', async () => {
      await authController.login(req, res);

      // Assertions
      expect(User.findOne).toHaveBeenCalledWith({ email: req.body.email });
      expect(comparePassword).toHaveBeenCalledWith(req.body.password, 'hashedPassword');
      expect(signInWithEmailAndPassword).toHaveBeenCalledWith(
        auth,
        req.body.email,
        req.body.password
      );
      expect(generateToken).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        token: 'jwtToken123',
        user: expect.any(Object),
      }));
    });

    it('should return 404 if user not found', async () => {
      User.findOne.mockResolvedValue(null);

      await authController.login(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        message: 'User not found',
      }));
    });

    it('should return 401 if password is invalid', async () => {
      comparePassword.mockResolvedValue(false);

      await authController.login(req, res);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        message: 'Invalid credentials',
      }));
    });

    it('should return 403 if email is not verified', async () => {
      signInWithEmailAndPassword.mockResolvedValue({
        user: {
          uid: 'firebaseUid123',
          emailVerified: false,
          getIdToken: jest.fn(),
        },
      });

      await authController.login(req, res);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        message: 'Please verify your email first',
        verified: false,
      }));
    });

    it('should update email verification status if needed', async () => {
      // Set up user with unverified email in MongoDB
      const mockUser = {
        _id: 'mongoUserId123',
        email: req.body.email,
        password: 'hashedPassword',
        name: 'Test User',
        isEmailVerified: false,
        sports: [],
        save: jest.fn().mockResolvedValue(true),
      };
      
      User.findOne.mockResolvedValue(mockUser);
      
      // But Firebase says it's verified
      signInWithEmailAndPassword.mockResolvedValue({
        user: {
          uid: 'firebaseUid123',
          emailVerified: true,
          getIdToken: jest.fn().mockResolvedValue('mockFirebaseToken'),
        },
      });

      await authController.login(req, res);

      expect(mockUser.save).toHaveBeenCalled();
      expect(mockUser.isEmailVerified).toBe(true);
    });
  });

  describe('forgotPassword', () => {
    beforeEach(() => {
      req.body = {
        email: 'test@example.com',
      };
      
      const mockUser = {
        _id: 'mongoUserId123',
        email: req.body.email,
        save: jest.fn().mockResolvedValue(true),
      };
      
      User.findOne.mockResolvedValue(mockUser);
      sendPasswordResetEmail.mockResolvedValue();
      generateToken.mockReturnValue('resetToken123');
    });

    it('should send password reset email successfully', async () => {
      await authController.forgotPassword(req, res);

      // Assertions
      expect(User.findOne).toHaveBeenCalledWith({ email: req.body.email });
      expect(sendPasswordResetEmail).toHaveBeenCalledWith(auth, req.body.email);
      expect(generateToken).toHaveBeenCalled();
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        message: 'Password reset email sent successfully',
        resetToken: 'resetToken123',
      }));
    });

    it('should return 404 if user not found', async () => {
      User.findOne.mockResolvedValue(null);

      await authController.forgotPassword(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        message: 'User not found',
      }));
    });

    it('should handle errors during password reset', async () => {
      sendPasswordResetEmail.mockRejectedValue(new Error('Firebase error'));

      await authController.forgotPassword(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        message: 'Failed to send reset email',
        error: 'Firebase error',
      }));
    });
  });

  describe('resetPassword', () => {
    beforeEach(() => {
      req.body = {
        token: 'validResetToken',
        newPassword: 'newPassword123',
      };
      
      const mockUser = {
        _id: 'mongoUserId123',
        firebaseUid: 'firebaseUid123',
        resetPasswordToken: 'validResetToken',
        resetPasswordExpires: Date.now() + 1000000, // Valid expiration
        save: jest.fn().mockResolvedValue(true),
      };
      
      User.findOne.mockResolvedValue(mockUser);
      hashPassword.mockResolvedValue('newHashedPassword');
      
      admin.auth().getUser = jest.fn().mockResolvedValue({ uid: 'firebaseUid123' });
      admin.auth().updateUser = jest.fn().mockResolvedValue({});
    });

    it('should reset password successfully', async () => {
      await authController.resetPassword(req, res);

      // Assertions
      expect(User.findOne).toHaveBeenCalledWith({
        resetPasswordToken: req.body.token,
        resetPasswordExpires: { $gt: expect.any(Number) },
      });
      expect(admin.auth().getUser).toHaveBeenCalledWith('firebaseUid123');
      expect(admin.auth().updateUser).toHaveBeenCalledWith(
        'firebaseUid123',
        { password: req.body.newPassword }
      );
      expect(hashPassword).toHaveBeenCalledWith(req.body.newPassword);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        message: 'Password reset successful',
      }));
    });

    it('should return 400 if token is invalid or expired', async () => {
      User.findOne.mockResolvedValue(null);

      await authController.resetPassword(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        message: 'Invalid or expired reset token',
      }));
    });
  });

  describe('onboarding', () => {
    beforeEach(() => {
      req.user = { userId: 'mongoUserId123' };
      req.body = {
        sports: [
          { name: 'Cricket', role: 'Batsman' },
          { name: 'Football', role: 'Striker' },
        ],
      };
      
      User.findByIdAndUpdate = jest.fn().mockResolvedValue({
        _id: 'mongoUserId123',
        sports: req.body.sports,
        isFirstLogin: false,
      });
    });

    it('should complete onboarding successfully', async () => {
      await authController.onboarding(req, res);

      // Assertions
      expect(User.findByIdAndUpdate).toHaveBeenCalledWith(
        'mongoUserId123',
        {
          sports: req.body.sports,
          isFirstLogin: false,
        }
      );
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        message: 'Onboarding completed successfully',
      }));
    });

    it('should return 400 if sports are invalid', async () => {
      req.body.sports = [
        { name: 'InvalidSport', role: 'InvalidRole' },
      ];

      await authController.onboarding(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        message: 'Invalid sports or roles selected',
      }));
    });
  });

  describe('logout', () => {
    beforeEach(() => {
      req.user = { userId: 'mongoUserId123' };
      
      const mockUser = {
        _id: 'mongoUserId123',
        lastLogout: null,
        save: jest.fn().mockResolvedValue(true),
      };
      
      User.findById = jest.fn().mockResolvedValue(mockUser);
    });

    it('should logout user successfully', async () => {
      await authController.logout(req, res);

      // Assertions
      expect(User.findById).toHaveBeenCalledWith('mongoUserId123');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        message: 'Logout successful',
      }));
    });

    it('should return 404 if user not found', async () => {
      User.findById.mockResolvedValue(null);

      await authController.logout(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        message: 'User not found',
      }));
    });

    it('should handle errors during logout', async () => {
      User.findById.mockRejectedValue(new Error('Database error'));

      await authController.logout(req, res);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
        message: 'Logout failed',
        error: 'Database error',
      }));
    });
  });
});