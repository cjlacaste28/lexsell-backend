import express from "express";
import authRoutes from "./auth.routes";

const apiRoutes = express.Router();

apiRoutes.get("/api", function (req, res, next) {
    res.json({ message: 'Welcome to Bears Team 1 Project!' });
});

apiRoutes.use("/api/auth", authRoutes);



export default apiRoutes;
