const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  location: { type: String, required: true },
  dateOfBirth: { type: Date, required: true },
  isEmailVerified: { type: Boolean, default: false },
  firebaseUid: { type: String, required: true },
  sports: [
    {
      name: {
        type: String,
        enum: ["Cricket", "Football", "Volleyball", "Badminton"],
      },
      role: { type: String },
    },
  ],
  isFirstLogin: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("User", userSchema);
