const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("../models/user");
const dotenv = require('dotenv');

dotenv.config();

const { accessTokenSecret, refreshTokenSecret } = process.env;

const isAuth = async (req, res, next) => {
  const token = req.headers["authorization"];
  try {
    if (!token) {
      return res.status(401).send({ errors: [{ msg: "Vous n'êtes pas autorisé!" }] });
    }
    const decoded = jwt.verify(token, accessTokenSecret);
    req.user = { id: decoded.id };
    next();
  } catch (error) {
    return res.status(401).send({ errors: [{ msg: "Vous n'êtes pas autorisé!" }] });
  }
};

const generateAccessToken = (user) => {
  const payload = { id: user._id };
  return jwt.sign(payload, accessTokenSecret, { expiresIn: "3d" });
};

const generateRefreshToken = (user) => {
  const payload = { id: user._id };
  return jwt.sign(payload, refreshTokenSecret, { expiresIn: "7d" });
};

const refreshAccessToken = async (refreshToken) => {
  try {
    const decoded = jwt.verify(refreshToken, refreshTokenSecret);
    const userId = decoded.id;
    const accessToken = generateAccessToken({ _id: userId });
    return accessToken;
  } catch (error) {
    throw new Error("Token de rafraîchissement invalide");
  }
};

const encryptPassword = async (password) => {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
};

const register = async (req, res) => {
  const { username, password } = req.body;
  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).send({ errors: [{ msg: "Cet utilisateur existe déjà" }] });
    }
    const hashedPassword = await encryptPassword(password);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    const accessToken = generateAccessToken(newUser);
    res.status(201).send({ accessToken });
  } catch (error) {
    console.error(error);
    res.status(500).send("Erreur lors de l'enregistrement de l'utilisateur");
  }
};

const login = async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).send({ errors: [{ msg: "Identifiants invalides" }] });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).send({ errors: [{ msg: "Identifiants invalides" }] });
    }
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    res.json({ accessToken, refreshToken });
  } catch (error) {
    console.error(error);
    res.status(500).send("Erreur lors de l'authentification");
  }
};

const refreshToken = async (req, res) => {
  const refreshToken = req.body.refreshToken;
  if (!refreshToken) {
    return res.status(400).json({ msg: "Refresh token is required" });
  }
  try {
    const newAccessToken = await refreshAccessToken(refreshToken);
    res.status(200).json({ accessToken: newAccessToken });
  } catch (error) {
    res.status(401).json({ msg: "Invalid refresh token" });
  }
};

module.exports = { register, login, refreshToken };
