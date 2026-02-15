const express = require("express");
const cors = require("cors");
require("dotenv").config();

const jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

app.use(
    cors({
        origin: ["http://localhost:5173", process.env.CLIENT_URL].filter(Boolean),
        methods: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
    })
);

const uri = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.wxdswss.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});

const isValidObjectId = (id) => ObjectId.isValid(id);

const normalizeEmail = (email) => String(email || "").trim().toLowerCase();

const verifyJWT = (req, res, next) => {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : null;
    if (!token) return res.status(401).send({ message: "Unauthorized" });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err || !decoded?.email) return res.status(401).send({ message: "Unauthorized" });
        req.user = { email: normalizeEmail(decoded.email) };
        next();
    });
};

async function run() {
    await client.connect();

    const db = client.db("conteraDB");
    const usersCollection = db.collection("users");
    const contestsCollection = db.collection("contests");
    const registrationsCollection = db.collection("registrations");
    const submissionsCollection = db.collection("submissions");