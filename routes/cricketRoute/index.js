const express = require("express");
const router = express.Router();

const cricketRoutes = require("./cricketRoutes");
const teamRoutes = require("./teamRoutes");
const matchRoutes = require("./matchRoutes");

// Use the routes
router.use("/", cricketRoutes);
router.use("/teams", teamRoutes);
router.use("/matches", matchRoutes);

module.exports = router;
