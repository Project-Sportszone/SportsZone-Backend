// Dependecies
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const firebase = require("firebase/app");
const authRoutes = require("./routes/authRoutes/authRoutes");
require("dotenv").config();
const app = express();
const profileRoutes = require("./routes/profileRoutes/profileRoutes");
const onboardingRoutes = require("./routes/authRoutes/onboardingRoutes");
const teamRoutes = require("./routes/cricketRoute/teamRoutes");
const matchRoutes = require("./routes/cricketRoute/matchRoutes");
const cricketRoutes = require("./routes/cricketRoute/cricketRoutes");
const dashboardRoutes = require("./routes/profileRoutes/dashboardRoutes");

const footballAPI = require("./routes/footballRoutes/index");
const badmintonAPI = require("./routes/badmintonRoutes/index");
const volleyballAPI = require("./routes/volleyballRoutes/index");

// MongoDB
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.log("Cannot connect to MongoDB"));

// Middleware
app.use(express.json());
app.use(cors());
app.use("/api/auth", authRoutes);
app.use("/api/profile", profileRoutes);
app.use("/api/onboarding", onboardingRoutes);
app.use("/api/cricket/team", teamRoutes);
app.use("/api/cricket/innings", cricketRoutes);
app.use("/api/cricket/match", matchRoutes);
app.use("/api/dashboard", dashboardRoutes);

app.use("/api/football", footballAPI);
app.use("/api/badminton", badmintonAPI);
app.use("/api/volleyball", volleyballAPI);

const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
