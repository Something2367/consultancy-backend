const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");

// @route   POST /auth/signup
// @desc    Register user
router.post("/signup", authController.register);

// @route   POST /auth/login
// @desc    Login user
router.post("/login", authController.login);

// @route   POST /auth/google
// @desc    Google OAuth login/signup
router.post("/google", authController.googleLogin);

// @route   POST /auth/send-otp
// @desc    Send OTP to user
router.post("/send-otp", authController.sendOtp);

// @route   POST /auth/verify-otp
// @desc    Verify OTP
router.post("/verify-otp", authController.verifyOtp);

// @route   POST /auth/forgot-password
// @desc    Send password reset link
router.post("/forgot-password", authController.forgotPassword);

// @route   POST /auth/reset-password
// @desc    Reset password
router.post("/reset-password", authController.resetPassword);

module.exports = router;
