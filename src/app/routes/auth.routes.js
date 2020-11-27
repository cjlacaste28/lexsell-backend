import express from "express";
import authController from "../controllers/auth.controller"
import { asyncWrapper } from "../utils/asyncWrapper";

const authRoutes = express.Router();

authRoutes.get("/", function (req, res, next) {
    res.json({ message: "API from auth." });
});

// Create
authRoutes.post("/register", asyncWrapper(authController.register));
// Login
authRoutes.post("/login", asyncWrapper(authController.login));
// Google Login
authRoutes.post("/googleLogin", asyncWrapper(authController.googleLogin));

authRoutes.post("/verify/:email"), asyncWrapper(authController.verify)

export default authRoutes;