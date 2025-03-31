import express from "express";
import {
  getMe,
  login,
  logout,
  registerUser,refreshAccessToken,
  verifyUser,forgotPassword, resetPassword
} from "../controller/user.controller.js";
import { isLoggedIn } from "../middlewares/isLoggedIn.middlewares.js";

const router = express.Router();
router.post("/register", registerUser);
router.get("/verify/:token", verify);
router.post("/login", login);
router.get("/getMe", isLoggedIn, getMe);
router.post("/logout", isLoggedIn, logout);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token", resetPassword);
export default router;
