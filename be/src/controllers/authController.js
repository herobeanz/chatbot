import bcrypt from "bcrypt";
import User from "../models/User.js";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import Session from "../models/Session.js";

const ACCESS_TOKEN_TTL = "30m"; // 30 minutes
const REFRESH_TOKEN_TTL = 14 * 24 * 60 * 60 * 1000; // 14 days in milliseconds

export const signup = async (req, res) => {
    try {
        // get data from request body
        const { username, password, email, firstName, lastName } = req.body;
        if (!username || !password || !email || !firstName || !lastName) {
            return res.status(400).json({ message: "All fields are required" });
        }
        // check if username is already taken
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(409).json({ message: "Username already exists" });
        }
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        // create user
        await User.create({ username, email, hashedPassword, displayName: `${firstName} ${lastName}` });
        // return
        return res.status(204);
    } catch (error) {
        console.log("Error creating user", error);
        return res.status(500).json({ message: error.message });
    }
};

export const signin = async (req, res) => {
    try {
        // lấy input từ request body
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ message: "All fields are required" });
        }

        // lấy hashed password từ database để so sánh với password đã hash
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ message: "Invalid username or password" });
        }
        const isPasswordValid = await bcrypt.compare(password, user.hashedPassword);
        if (!isPasswordValid) {
            return res.status(401).json({ message: "Invalid username or password" });
        }

        // nếu khớp, tạo accessToken với JWT
        const accessToken = jwt.sign({userid: user._id }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: ACCESS_TOKEN_TTL });

        // Tạo refresh token với JWT
        const refreshToken = crypto.randomBytes(64).toString("hex");

        // tạo session cookie để lưu refreshToken
        await Session.create({ userId: user._id, refreshToken, expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL) });

        // trả refresh token về trong cookie
        res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: true, sameSite: "none", maxAge: REFRESH_TOKEN_TTL });

        // trả response
        return res.status(200).json({ message: `User ${user.displayName} signed in successfully`, accessToken });
    }
    catch (error) {
        console.log("Error signing in", error);
        return res.status(500).json({ message: error.message });
    }
}