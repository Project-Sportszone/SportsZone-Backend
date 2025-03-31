const express = require("express");
const router = express.Router();
const authController = require("../../controller/authController/authController");
const authenticateUser = require("../../middleware/auth_middleware");

router.get('/status', authenticateUser, authController.checkOnboardingStatus);
router.post('/start', authenticateUser, authController.startOnboarding);
router.get('/sports', authenticateUser, authController.getSportsOptions);
router.post('/step', authenticateUser, authController.updateOnboardingStep);
router.post('/complete', authenticateUser, authController.onboarding);  // Legacy method, keep for backward compatibility

module.exports = router;