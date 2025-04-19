const express = require("express");
const router = express.Router();

const volleyballRoutes = require("./volleyballRoutes");
const teamRoutes = require("./teamRoutes");
const matchRoutes = require("./matchRoutes");

// Use the routes
router.use("/", volleyballRoutes);
router.use("/teams", teamRoutes);
router.use("/matches", matchRoutes);

module.exports = router;
