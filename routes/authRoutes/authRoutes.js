const express = require("express");
const router = express.Router();
const authController = require("../../controller/authController/authController");
const authMiddleware = require("../../middleware/auth_middleware");
const { auth } = require("firebase-admin");

router.post("/signup", authController.signup);
router.post("/login", authController.login);
router.post("/forgot-password", authController.forgotPassword); // X
router.post("/reset-password", authController.resetPassword); // X
router.get("/verify-email/:token", authController.verifyEmail); //X
router.post("/logout", authMiddleware, authController.logout);
// Protected route example
router.get("/profile", authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

module.exports = router;
