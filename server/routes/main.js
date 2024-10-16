const express = require("express");
const router = express.Router();
const Video = require("../models/Video");
const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const jwtSecret = process.env.JWT_SECRET;
const cookieOption = {
  maxAge: 24 * 60 * 60 * 1000,
  httpOnly: true,
  secure: true,
};

const authMiddleware = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, jwtSecret);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ message: "Unauthorized" });
  }
};

router.get("", async (req, res) => {
  try {
    if (req.cookies.token) {
      const decoded = jwt.verify(req.cookies.token, jwtSecret);
      const currentUser = await User.findById(decoded.userId);
      const allLink = await Video.find({ user: currentUser._id });
      res.render("index", { data: allLink });
    } else {
      res.redirect("/login");
    }
  } catch (error) {
    console.error("Homepage: ", error);
    res.status(500).json({
      message: "An unexpected error occurred. Please try again later.",
    });
  }
});
router.get("/login", (req, res) => {
  try {
    if (!req.cookies.token) {
      res.render("login");
    } else {
      res.redirect("/");
    }
  } catch (error) {
    console.error("Login Page: ", error);
    res.status(500).json({
      message: "An unexpected error occurred. Please try again later.",
    });
  }
});
router.get("/register", (req, res) => {
  try {
    if (!req.cookies.token) {
      res.render("register");
    } else {
      res.redirect("/");
    }
  } catch (error) {
    console.error("Register Page: ", error);
    res.status(500).json({
      message: "An unexpected error occurred. Please try again later.",
    });
  }
});
router.get("/create", authMiddleware, (req, res) => {
  try {
    if (req.cookies.token) {
      res.render("add-link");
    } else {
      res.redirect("/login");
    }
  } catch (error) {
    console.error("Add Link Page: ", error);
    res.status(500).json({
      message: "An unexpected error occurred. Please try again later.",
    });
  }
});
router.get("/video/:id", authMiddleware, async (req, res) => {
  try {
    if (req.cookies.token) {
      const videoId = req.params.id;
      const video = await Video.findById({ _id: videoId });
      res.render("full-link", { video });
    } else {
      res.redirect("/login");
    }
  } catch (error) {
    console.error("Link Page: ", error);
    res.status(500).json({
      message: "An unexpected error occurred. Please try again later.",
    });
  }
});

router.get("/video/update/:id", authMiddleware, async (req, res) => {
  try {
    if (req.cookies.token) {
      const videoId = req.params.id;
      const video = await Video.findById({ _id: videoId });
      if (!video) {
        return res.status(404).json({ message: "Video not found" });
      } else {
        res.render("update-link", { video });
      }
    } else {
      res.redirect("/login");
    }
  } catch (error) {
    console.error("Update Link Page: ", error);
    res.status(500).json({
      message: "An unexpected error occurred. Please try again later.",
    });
  }
});

router.post("/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: "Please fill in all fields." });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "Username already in use" });
    }
    const user = await User.create({ username, password: hashedPassword });
    if (!user) {
      return res.status(400).json({ message: "Failed to create user." });
    } else {
      const token = jwt.sign({ userId: user._id }, jwtSecret);
      res.cookie("token", token, cookieOption);
      res.redirect("/");
    }
  } catch (error) {
    console.error("Register/post: ", error);
    res.status(500).json({
      message: "An unexpected error occurred. Please try again later.",
    });
  }
});
router.post("/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: "Please fill in all fields." });
    }
    const user = await User.findOne({ username }).select("+password");
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!user || !isValidPassword) {
      return res.status(401).json({ message: "Invalid email or password" });
    } else {
      const token = jwt.sign({ userId: user._id }, jwtSecret);
      res.cookie("token", token, cookieOption);
      res.redirect("/");
    }
  } catch (error) {
    console.error("Login/post: ", error);
    res.status(500).json({
      message: "An unexpected error occurred. Please try again later.",
    });
  }
});
router.get("/auth/logout", authMiddleware, (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});
router.get("*", (req, res) => {
  res
    .status(404)
    .send(
      `<div style="padding: 2rem; text-align: center;"><h1>OOPS ! 404 page not found :(</h1><h3><a href="/" style=" color: inherit">Back to homepage</a></h6></div>`
    );
});

router.post("/add/link", authMiddleware, async (req, res) => {
  try {
    const decoded = jwt.verify(req.cookies.token, jwtSecret);
    const currentUser = await User.findById(decoded.userId);
    const { title, url } = req.body;
    if (!currentUser || !title || !url) {
      return res.status(400).json({ message: "Please fill in all fields." });
    }
    const link = await Video.create({ title, url, user: currentUser._id });
    if (!link) {
      return res
        .status(500)
        .json({ message: "An unexpected error occurred. Please try again" });
    }
    res.redirect("/create");
  } catch (error) {
    console.error("Add link/post: ", error);
    res.status(500).json({
      message: "An unexpected error occurred. Please try again later.",
    });
  }
});
router.delete("/video/delete/:id", authMiddleware, async (req, res) => {
  try {
    const videoId = req.params.id;
    const video = await Video.findByIdAndDelete({ _id: videoId });
    if (!video) {
      return res.status(404).json({ message: "Video not found." });
    }
    res.redirect("/");
  } catch (error) {
    console.error("Delete.post ", error);
    res.status(500).json({
      message: "An unexpected error occurred. Please try again later.",
    });
  }
});

router.put("/api/video/update/:id", authMiddleware, async (req, res) => {
  try {
    const videoId = req.params.id;
    const { title, url } = req.body;
    const video = await Video.findByIdAndUpdate(videoId, {
      title: title,
      url: url,
    });
    if (!video) {
      return res.status(404).json({ message: "Video not found." });
    }
    res.redirect(`/video/${videoId}`);
  } catch (error) {
    console.error("Delete.post ", error);
    res.status(500).json({
      message: "An unexpected error occurred. Please try again later.",
    });
  }
});

router.post("/search", authMiddleware, async (req, res) => {
  try {
    const searchTerm = req.body.search;
    const searchNoSpecialChar = searchTerm
      .replace(/[^a-zA-Z0-9 ]/g, "")
      .trim()
      .replace(/\s+/g, " ");
    const data = await Video.find({
      $or: [{ title: { $regex: new RegExp(searchNoSpecialChar, "i") } }],
    });
    res.render("search", { data, searchTerm });
  } catch (error) {
    console.error("Search ", error);
    res.status(500).json({
      message: "An unexpected error occurred. Please try again later.",
    });
  }
});
module.exports = router;
