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

    const getRoleByEmail = async (email) => {
            const u = await usersCollection.findOne(
                { email },
                { projection: { role: 1, name: 1, photoURL: 1, winsCount: 1 } }
            );
            return u || null;
        };
    
        const verifyAdmin = async (req, res, next) => {
            const email = req.user?.email;
            if (!email) return res.status(403).send({ message: "Forbidden" });
            const u = await getRoleByEmail(email);
            if (!u || u.role !== "admin") return res.status(403).send({ message: "Admin only" });
            next();
        };
    
        const verifyCreator = async (req, res, next) => {
            const email = req.user?.email;
            if (!email) return res.status(403).send({ message: "Forbidden" });
            const u = await getRoleByEmail(email);
            if (!u || u.role !== "creator") return res.status(403).send({ message: "Creator only" });
            next();
        };
    
        const canUserParticipate = async ({ email, contestId }) => {
            const userDoc = await usersCollection.findOne(
                { email },
                { projection: { role: 1 } }
            );
    
            const role = userDoc?.role || "user";
            if (role === "admin") {
                return { ok: false, code: 403, message: "Admins cannot participate in contests." };
            }
    
            const contest = await contestsCollection.findOne({ _id: new ObjectId(contestId) });
            if (!contest) return { ok: false, code: 404, message: "Contest not found." };
    
            const createdBy = normalizeEmail(contest.createdBy);
            if (createdBy && createdBy === email) {
                return { ok: false, code: 403, message: "You cannot participate in your own contest." };
            }
    
            if (contest.status !== "confirmed") {
                return { ok: false, code: 403, message: "This contest is not approved yet." };
            }
    
            const deadlineMs = contest.deadline ? new Date(contest.deadline).getTime() : 0;
            if (deadlineMs && Date.now() >= deadlineMs) {
                return { ok: false, code: 400, message: "Contest has ended." };
            }
    
            return { ok: true, contest, role };
        };

        app.post("/jwt", async (req, res) => {
                const email = normalizeEmail(req.body?.email);
                if (!email) return res.status(400).send({ message: "Email required" });
        
                await usersCollection.updateOne(
                    { email },
                    {
                        $setOnInsert: {
                            email,
                            role: "user",
                            winsCount: 0,
                            createdAt: new Date(),
                        },
                        $set: { updatedAt: new Date() },
                    },
                    { upsert: true }
                );
        
                const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "7d" });
                res.send({ token });
            });

        app.post("/users", async (req, res) => {
                const email = normalizeEmail(req.body?.email);
                if (!email) return res.status(400).send({ message: "Email is required" });
        
                const name = req.body?.name ? String(req.body.name).trim() : "";
                const photoURL = req.body?.photoURL ? String(req.body.photoURL).trim() : "";
        
                const result = await usersCollection.updateOne(
                    { email },
                    {
                        $set: { name, photoURL, updatedAt: new Date() },
                        $setOnInsert: { email, role: "user", winsCount: 0, createdAt: new Date() },
                    },
                    { upsert: true }
                );
        
                res.send(result);
            });
        
            app.get("/users/me", verifyJWT, async (req, res) => {
                const me = await usersCollection.findOne({ email: req.user.email });
                res.send(me);
            });
        
            app.patch("/users/me", verifyJWT, async (req, res) => {
                const email = req.user.email;
                const { name, photoURL, bio, address } = req.body || {};
        
                const update = {};
                if (name !== undefined) update.name = String(name).trim();
                if (photoURL !== undefined) update.photoURL = String(photoURL).trim();
                if (bio !== undefined) update.bio = String(bio).trim();
                if (address !== undefined) update.address = String(address).trim();
        
                if (Object.keys(update).length === 0) {
                    return res.status(400).send({ message: "No fields to update" });
                }
        
                const result = await usersCollection.updateOne(
                    { email },
                    { $set: { ...update, updatedAt: new Date() } }
                );
        
                res.send(result);
            });
        
            app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
                const users = await usersCollection.find().sort({ createdAt: -1 }).toArray();
                res.send(users);
            });
        
            app.patch("/users/:id/role", verifyJWT, verifyAdmin, async (req, res) => {
                const { id } = req.params;
                const role = String(req.body?.role || "").trim();
        
                if (!isValidObjectId(id)) return res.status(400).send({ message: "Invalid user ID" });
                if (!["user", "creator", "admin"].includes(role)) {
                    return res.status(400).send({ message: "Invalid role" });
                }
        
                const result = await usersCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { role, updatedAt: new Date() } }
                );
        
                res.send(result);
            });