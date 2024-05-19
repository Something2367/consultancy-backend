const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const User = require("../models/User");
const sendEmail = require("../utils/email");
const otpGenerator = require("otp-generator");
require("dotenv").config();

let otpStore = {};
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const register = async (req, res) => {
  const { name, email, password, gender, city, zipcode, state } = req.body;
  try {
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ msg: "User already exists" });
    }

    user = new User({
      name,
      email,
      password,
      gender,
      city,
      zipcode,
      state,
    });

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);

    await user.save();

    const payload = {
      user: {
        id: user.id,
      },
    };

    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: "5 days" },
      (err, token) => {
        if (err) throw err;
        res.json({ token });
      }
    );

    sendEmail(
      user.email,
      "Welcome to Spirea Arch",
      "Your account has been created successfully."
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ msg: "Invalid Credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: "Invalid Credentials" });
    }

    const payload = {
      user: {
        id: user.id,
      },
    };

    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: "5 days" },
      (err, token) => {
        if (err) throw err;
        res.json({ token });
      }
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
};

const googleLogin = async (req, res) => {
  const { tokenId } = req.body;
  try {
    const response = await client.verifyIdToken({
      idToken: tokenId,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const { email_verified, name, email } = response.payload;
    if (email_verified) {
      let user = await User.findOne({ email });
      if (!user) {
        user = new User({
          name,
          email,
          googleId: response.payload.sub,
        });
        await user.save();
      }

      const payload = {
        user: {
          id: user.id,
        },
      };

      jwt.sign(
        payload,
        process.env.JWT_SECRET,
        { expiresIn: "5 days" },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } else {
      res.status(400).json({ msg: "Google login failed" });
    }
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
};

const sendOtp = async (req, res) => {
  const { email } = req.body;
  try {
    const otp = otpGenerator.generate(6, {
      upperCase: false,
      specialChars: false,
      alphabets: false,
    });

    otpStore[email] = { otp, expiresAt: Date.now() + 300000 };
    sendEmail(email, "Your OTP Code", `Your OTP code is ${otp}`);

    res.status(200).json({ msg: "OTP sent" });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
};

const verifyOtp = async (req, res) => {
  const { email, otp } = req.body;
  try {
    const storedOtp = otpStore[email];

    if (!storedOtp) {
      return res.status(400).json({ msg: "OTP not found or expired" });
    }

    if (storedOtp.otp !== otp) {
      return res.status(400).json({ msg: "Invalid OTP" });
    }

    delete otpStore[email];

    res.status(200).json({ msg: "OTP verified" });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
};

const forgotPassword = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ msg: "User not found" });
    }

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    const resetLink = `http://yourfrontend.com/reset-password/${token}`;
    sendEmail(
      user.email,
      "Password Reset",
      `Click the link to reset your password: ${resetLink}`
    );
    res.status(200).json({ msg: "Password reset link sent" });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
};

const resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    let user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(400).json({ msg: "Invalid token" });
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();

    res.status(200).json({ msg: "Password reset successful" });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
};

module.exports = {
  register,
  login,
  googleLogin,
  sendOtp,
  verifyOtp,
  forgotPassword,
  resetPassword,
};
