const express = require("express");
const {
  register,
  logoutUser,
  loginUser,
} = require("../controllers/authController");

const authRoutes = express.Router();

authRoutes.post("/register", register);
authRoutes.post("/login", loginUser);
authRoutes.post("/logout", logoutUser);

module.exports = authRoutes;
