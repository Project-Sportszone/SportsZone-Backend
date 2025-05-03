const express = require("express");
const router = express.Router();

const footballRoutes = require("./footballRoutes");
const teamRoutes = require("./teamRoutes");
const matchRoutes = require("./matchRoutes");

// Use the routes
router.use("/", footballRoutes);
router.use("/teams", teamRoutes);
router.use("/matches", matchRoutes);

module.exports = router;
