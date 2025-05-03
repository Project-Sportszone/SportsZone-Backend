const express = require('express');
const router = express.Router();
const dashboardController = require('../../controller/dashboardController/dashboardController');
const authenticateToken = require('../../middleware/auth_middleware');

// Apply authentication middleware to all dashboard routes
router.use(authenticateToken);

/**
 * GET /api/dashboard
 * Get dashboard data for the current user
 */
router.get('/user-dashboard', dashboardController.getDashboard.bind(dashboardController));
module.exports = router;