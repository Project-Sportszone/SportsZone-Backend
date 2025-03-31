// routes/profile.routes.js
const express = require('express');
const router = express.Router();
const profileController = require('../../controller/profileController/profileController');
const authenticateToken = require('../../middleware/auth_middleware');

// Apply authentication middleware to all profile routes

// Get user profile
router.get('/',authenticateToken,profileController.getProfile);
router.get('/players', authenticateToken, profileController.getAllPlayers);

router.get('/:id', authenticateToken, profileController.getProfileById);
// Update profile information
router.put('/update',authenticateToken, profileController.updateProfile);

// Update profile picture
router.put('/picture',authenticateToken, profileController.updateProfilePicture);

// Sports management
router.get('/sports/options',authenticateToken, profileController.getSportsOptions);
router.post('/sports/add', authenticateToken,profileController.addSport);
router.delete('/sports/remove',authenticateToken, profileController.removeSport);
router.get('/sports/:sportName/:sportRole/statistics',authenticateToken, profileController.getSportStatistics);

module.exports = router;