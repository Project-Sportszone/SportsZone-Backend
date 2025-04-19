const express = require("express");
const router = express.Router();

const badmintonRoutes = require("./badmintonRoutes");
const teamRoutes = require("./teamRoutes");
const matchRoutes = require("./matchRoutes");

// Use the routes
router.use("/", badmintonRoutes);
router.use("/teams", teamRoutes);
router.use("/matches", matchRoutes);

module.exports = router;
