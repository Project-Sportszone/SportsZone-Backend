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
const cricketAPI = require("./routes/cricketRoute/index");
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
app.use("/api/cricket", cricketAPI);
app.use("/api/football", footballAPI);
app.use("/api/badminton", badmintonAPI);
app.use("/api/volleyball", volleyballAPI);
const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
