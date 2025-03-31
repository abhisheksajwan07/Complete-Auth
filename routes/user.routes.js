import express from"express";
import {getProfile,login,logout,registerUser,verify} from "../controller/user.controller.js";
import { isLoggedIn } from "../middlewares/isLoggedIn.middlewares.js";

const router = express.Router();
router.post("/register",registerUser);
router.get("/verify/:token",verify);
router.post("/login",login);
router.get("/get-profile",isLoggedIn,getProfile);
router.post("/logout",isLoggedIn,logout);
export default router;