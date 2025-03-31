import User from "../models/user.model.js";
import crypto from "crypto";
import nodemailer from "nodemailer";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

// Register user controller
const registerUser = async (req, res) => {
  const { name, email, password } = req.body;

  // Validate inputs
  if (!name || !email || !password) {
    return res.status(400).json({
      message: "All fields are required",
    });
  }

  try {
    // Check if the user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        message: "User already exists",
      });
    }

    // Create new user
    const user = await User.create({
      name,
      email,
      password,
    });

    if (!user) {
      return res.status(400).json({
        message: "User not registered",
      });
    }

    // Generate verification token
    const token = crypto.randomBytes(32).toString("hex");
    user.verificationToken = token;
    await user.save();

    // Send verification email
    const transporter = nodemailer.createTransport({
      host: process.env.MAILTRAP_HOST,
      port: process.env.MAILTRAP_PORT,
      secure: false,
      auth: {
        user: process.env.MAILTRAP_USERNAME,
        pass: process.env.MAILTRAP_PASSWORD,
      },
    });

    const mailOptions = {
      from: process.env.MAILTRAP_SENDEREMAIL,
      to: user.email,
      subject: "Verify your email",
      text: `Please click on the following link to verify your email:
      ${process.env.BASE_URL}/api/v1/users/verify/${token}
      `,
    };

    await transporter.sendMail(mailOptions);

    res.status(201).json({
      message: "User registered successfully",
      success: true,
    });
  } catch (error) {
    res.status(400).json({
      message: "User not registered",
      error,
      success: false,
    });
  }
};

// Verify user email controller
const verifyUser = async (req, res) => {
  const { token } = req.params;

  if (!token) {
    return res.status(400).json({
      message: "Invalid token",
    });
  }

  try {
    const user = await User.findOne({ verificationToken: token });

    if (!user) {
      return res.status(400).json({
        message: "Invalid token",
      });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();

    res.status(200).json({
      message: "User verified successfully",
      success: true,
    });
  } catch (error) {
    res.status(400).json({
      message: "User not verified",
      error,
      success: false,
    });
  }
};

// Login user controller
const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      message: "All fields are required",
    });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({
        message: "Invalid email or password",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({
        message: "Invalid email or password",
      });
    }

    const accessToken = jwt.sign(
      { id: user._id, role: user.role },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "60m" }
    );
    const refreshToken = jwt.sign(
      { id: user._id, role: user.role },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: "24h" }
    );

    const cookieOptions = {
      httpOnly: true,
      secure: true,
      maxAge: 24 * 60 * 60 * 1000,
    };

    res.cookie("accessToken", accessToken, cookieOptions);
    user.refreshToken = refreshToken;
    await user.save();
    res.cookie("refreshToken", refreshToken, cookieOptions);

    res.status(200).json({
      success: true,
      message: "Login successful",
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        name: user.name,
        role: user.role,
      },
    });
  } catch (error) {
    return res.status(400).json({
      message: "Error in login",
    });
  }
};

// Get logged-in user details
const getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "User not found",
      });
    }

    res.status(200).json({
      success: true,
      user,
    });
  } catch (error) {
    console.log("Error in get me", error);
  }
};

// Logout user controller
const logoutUser = async (req, res) => {
  try {
    const token = req.cookies.refreshToken;
    if (!token) {
      res.status(400).json({
        success: false,
        message: "Unauthorized Access",
      });
    }

    const info = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(info.id).select("-password -refreshToken");

    if (!user) {
      res.status(400).json({
        success: false,
        message: "Invalid token access",
      });
    }

    await User.findByIdAndUpdate(user._id, {
      $set: { refreshToken: undefined },
    });

    res.cookie("accessToken", "", {});
    res.cookie("refreshToken", "", {});

    res.status(200).json({
      success: true,
      message: "Logged Out",
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: "Error in logout",
    });
  }
};

// Refresh access token controller
const refreshAccessToken = async (req, res) => {
  const currentRefreshToken = req.cookies.refreshToken;

  if (!currentRefreshToken) {
    res.status(400).json({
      success: false,
      message: "Unauthenticated request",
    });
  }

  const info = jwt.verify(
    currentRefreshToken,
    process.env.REFRESH_TOKEN_SECRET
  );

  if (!info) {
    res.status(400).json({
      success: false,
      message: "Invalid token, info not found",
    });
  }

  try {
    const user = await User.findById(info.id);
    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid token, user not found",
      });
    }

    if (currentRefreshToken !== user.refreshToken) {
      return res.status(400).json({
        success: false,
        message: "Token mismatch",
      });
    }

    const accessToken = jwt.sign(
      { id: user._id, role: user.role },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "60m" }
    );
    const refreshToken = jwt.sign(
      { id: user._id, role: user.role },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: "24h" }
    );

    const cookieOptions = {
      httpOnly: true,
      secure: true,
      maxAge: 24 * 60 * 60 * 1000,
    };

    res.cookie("accessToken", accessToken, cookieOptions);
    res.cookie("refreshToken", refreshToken, cookieOptions);

    res.status(200).json({
      success: true,
      message: "Access token refreshed",
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: "Error in refreshing access token",
    });
  }
};

const forgotPassword = async (req, res) => {
    const { email } = req.body;
    try {
      const user = await User.findOne({ email });
      if (!user) return res.status(404).json({ message: "User not found" });
      const resetToken = crypto.randomBytes(32).toString("hex");
      user.resetPasswordToken = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");
      user.resetPasswordExpires = Date.now() + 15 * 60 * 1000;
      await user.save();
      const resetLink = `${process.env.BASE_URL}/api/v1/users/reset-password/${resetToken}`;
      await sendEmail(
        user.email,
        "Reset your password",
        `Click the link to reset your password: ${resetLink}`
      );
      res
        .status(200)
        .json({ message: "Password reset link sent", success: true });
    } catch (error) {
      res.status(500).json({ message: "Internal server error", success: false });
    }
  };
  
  const resetPassword = async (req, res) => {
    const { token } = req.params;
    const { newPassword } = req.body;
    if (!newPassword)
      return res.status(400).json({ message: "New password is required" });
    try {
      const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
      const user = await User.findOne({
        resetPasswordToken: hashedToken,
        resetPasswordExpires: { $gt: Date.now() },
      });
      if (!user)
        return res.status(400).json({ message: "Invalid or expired token" });
      user.password = newPassword;
      console.log("New Password (hashed):", user.password);
  
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      await user.save();
      res
        .status(200)
        .json({ message: "Password reset successful", success: true });
    } catch (err) {
      res.status(500).json({ message: "Something went wrong", success: false });
    }
  };
  

export {
  registerUser,
  verifyUser,
  login,
  getProfile,
  logoutUser,
  resetPassword,
  forgotPassword,
  refreshAccessToken,
};
