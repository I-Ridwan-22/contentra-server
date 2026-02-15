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

    app.get("/contests", async (req, res) => {
        const { type, search, sort, limit } = req.query;

        const query = { status: "confirmed" };

        if (search && String(search).trim()) {
            query.contestType = { $regex: String(search).trim(), $options: "i" };
        } else if (type && String(type).trim() && String(type).trim() !== "All") {
            query.contestType = String(type).trim();
        }

        const lim = Math.min(parseInt(limit || "0", 10) || 0, 50);

        const sortDoc =
            String(sort).toLowerCase() === "popular"
                ? { participantsCount: -1, updatedAt: -1 }
                : { createdAt: -1 };

        let cursor = contestsCollection.find(query).sort(sortDoc);
        if (lim) cursor = cursor.limit(lim);

        const data = await cursor.toArray();
        res.send(data);
    });

    app.get("/contests/popular", async (req, res) => {
        const lim = Math.min(parseInt(req.query.limit || "5", 10) || 5, 20);
        const data = await contestsCollection
            .find({ status: "confirmed" })
            .sort({ participantsCount: -1, updatedAt: -1 })
            .limit(lim)
            .toArray();
        res.send(data);
    });

    app.get("/contests/recent-winners", async (req, res) => {
        const lim = Math.min(parseInt(req.query.limit || "6", 10) || 6, 20);
        const data = await contestsCollection
            .find({ status: "confirmed", "winner.email": { $exists: true, $ne: "" } })
            .sort({ winnerDeclaredAt: -1 })
            .limit(lim)
            .toArray();
        res.send(data);
    });

    app.get("/site-stats", async (req, res) => {
        const totalContests = await contestsCollection.countDocuments({ status: "confirmed" });
        const totalWinners = await contestsCollection.countDocuments({
            status: "confirmed",
            "winner.email": { $exists: true, $ne: "" },
        });

        const participantsAgg = await contestsCollection
            .aggregate([
                { $match: { status: "confirmed" } },
                { $group: { _id: null, totalParticipants: { $sum: { $ifNull: ["$participantsCount", 0] } } } },
            ])
            .toArray();

        const prizeAgg = await contestsCollection
            .aggregate([
                { $match: { status: "confirmed", "winner.email": { $exists: true, $ne: "" } } },
                { $group: { _id: null, totalPrizeMoney: { $sum: { $ifNull: ["$prizeMoney", 0] } } } },
            ])
            .toArray();

        res.send({
            totalContests,
            totalWinners,
            totalParticipants: participantsAgg?.[0]?.totalParticipants || 0,
            totalPrizeMoney: prizeAgg?.[0]?.totalPrizeMoney || 0,
        });
    });

    app.get("/contests/:id", async (req, res) => {
        const { id } = req.params;
        if (!isValidObjectId(id)) return res.status(400).send({ message: "Invalid contest ID" });

        const contest = await contestsCollection.findOne({
            _id: new ObjectId(id),
            status: "confirmed",
        });

        if (!contest) return res.status(404).send({ message: "Contest not found" });
        res.send(contest);
    });

    app.post("/contests", verifyJWT, verifyCreator, async (req, res) => {
        const c = req.body || {};

        const required = ["name", "image", "description", "price", "prizeMoney", "taskInstruction", "contestType", "deadline"];
        for (const k of required) {
            if (c[k] === undefined || c[k] === null || String(c[k]).trim() === "") {
                return res.status(400).send({ message: `Missing field: ${k}` });
            }
        }

        const doc = {
            name: String(c.name).trim(),
            image: String(c.image).trim(),
            description: String(c.description).trim(),
            taskInstruction: String(c.taskInstruction).trim(),
            contestType: String(c.contestType).trim(),
            deadline: String(c.deadline).trim(),
            price: Number(c.price),
            prizeMoney: Number(c.prizeMoney),
            status: "pending",
            participantsCount: 0,
            winner: null,
            createdBy: req.user.email,
            createdAt: new Date(),
            updatedAt: new Date(),
        };

        const result = await contestsCollection.insertOne(doc);
        res.send(result);
    });

    app.get("/creator/contests", verifyJWT, verifyCreator, async (req, res) => {
        const email = req.user.email;
        const data = await contestsCollection
            .find({ createdBy: email })
            .sort({ createdAt: -1 })
            .toArray();
        res.send(data);
    });

    app.patch("/contests/:id", verifyJWT, verifyCreator, async (req, res) => {
        const { id } = req.params;
        if (!isValidObjectId(id)) return res.status(400).send({ message: "Invalid contest ID" });

        const contest = await contestsCollection.findOne({ _id: new ObjectId(id) });
        if (!contest) return res.status(404).send({ message: "Contest not found" });

        if (normalizeEmail(contest.createdBy) !== req.user.email) {
            return res.status(403).send({ message: "Forbidden" });
        }

        if (contest.status !== "pending") {
            return res.status(403).send({ message: "Only pending contests can be edited" });
        }

        const up = req.body || {};
        const allowed = ["name", "image", "description", "price", "prizeMoney", "taskInstruction", "contestType", "deadline"];

        const updateFields = {};
        for (const k of allowed) {
            if (up[k] !== undefined) updateFields[k] = up[k];
        }

        if (Object.keys(updateFields).length === 0) {
            return res.status(400).send({ message: "No fields to update" });
        }

        updateFields.updatedAt = new Date();

        const result = await contestsCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: updateFields }
        );

        res.send(result);
    });

    app.delete("/contests/:id", verifyJWT, verifyCreator, async (req, res) => {
        const { id } = req.params;
        if (!isValidObjectId(id)) return res.status(400).send({ message: "Invalid contest ID" });

        const contest = await contestsCollection.findOne({ _id: new ObjectId(id) });
        if (!contest) return res.status(404).send({ message: "Contest not found" });

        if (normalizeEmail(contest.createdBy) !== req.user.email) {
            return res.status(403).send({ message: "Forbidden" });
        }

        if (contest.status !== "pending") {
            return res.status(403).send({ message: "Only pending contests can be deleted" });
        }

        const result = await contestsCollection.deleteOne({ _id: new ObjectId(id) });
        res.send(result);
    });

    app.get("/admin/contests", verifyJWT, verifyAdmin, async (req, res) => {
        const page = Math.max(parseInt(req.query.page || "1", 10) || 1, 1);
        const limit = Math.min(parseInt(req.query.limit || "10", 10) || 10, 50);
        const skip = (page - 1) * limit;

        const total = await contestsCollection.countDocuments();
        const data = await contestsCollection
            .find()
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .toArray();

        res.send({ total, page, limit, data });
    });

    app.patch("/admin/contests/:id/status", verifyJWT, verifyAdmin, async (req, res) => {
        const { id } = req.params;
        const status = String(req.body?.status || "").trim();

        if (!isValidObjectId(id)) return res.status(400).send({ message: "Invalid contest ID" });
        if (!["confirmed", "rejected"].includes(status)) {
            return res.status(400).send({ message: "Status must be confirmed or rejected" });
        }

        const result = await contestsCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { status, updatedAt: new Date() } }
        );

        res.send(result);
    });

    app.delete("/admin/contests/:id", verifyJWT, verifyAdmin, async (req, res) => {
        const { id } = req.params;
        if (!isValidObjectId(id)) return res.status(400).send({ message: "Invalid contest ID" });

        const result = await contestsCollection.deleteOne({ _id: new ObjectId(id) });
        res.send(result);
    });

    app.get("/contests/:id/registration-status", verifyJWT, async (req, res) => {
        const { id } = req.params;
        if (!isValidObjectId(id)) return res.status(400).send({ message: "Invalid contest ID" });

        const email = req.user.email;

        const reg = await registrationsCollection.findOne({
            contestId: String(id),
            userEmail: email,
            paymentStatus: "paid",
        });

        res.send({
            registered: !!reg,
            paymentStatus: reg?.paymentStatus || "unpaid",
            paidAt: reg?.paidAt || null,
        });
    });

    app.post("/create-checkout-session", verifyJWT, async (req, res) => {
        const contestId = String(req.body?.contestId || "").trim();
        if (!contestId) return res.status(400).send({ message: "contestId required" });
        if (!isValidObjectId(contestId)) return res.status(400).send({ message: "Invalid contest ID" });

        const email = req.user.email;

        const check = await canUserParticipate({ email, contestId });
        if (!check.ok) return res.status(check.code).send({ message: check.message });

        const contest = check.contest;

        const existing = await registrationsCollection.findOne({
            contestId: String(contestId),
            userEmail: email,
            paymentStatus: "paid",
        });
        if (existing) return res.status(400).send({ message: "Already registered (paid)" });

        const amount = Math.max(0, Number(contest.price || 0));
        const unitAmount = Math.round(amount * 100);

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ["card"],
            mode: "payment",
            customer_email: email,
            line_items: [
                {
                    price_data: {
                        currency: "usd",
                        product_data: { name: `Contera Contest Entry: ${contest.name}` },
                        unit_amount: unitAmount,
                    },
                    quantity: 1,
                },
            ],
            metadata: { contestId: String(contestId), userEmail: email },
            success_url: `${process.env.CLIENT_URL}/payment-success?session_id={CHECKOUT_SESSION_ID}&contestId=${contestId}`,
            cancel_url: `${process.env.CLIENT_URL}/payment-cancel?contestId=${contestId}`,
        });

        await registrationsCollection.updateOne(
            { contestId: String(contestId), userEmail: email },
            {
                $setOnInsert: { createdAt: new Date() },
                $set: {
                    contestId: String(contestId),
                    contestName: contest.name,
                    contestType: contest.contestType,
                    contestDeadline: contest.deadline,
                    contestImage: contest.image,
                    userEmail: email,
                    paymentStatus: "unpaid",
                    sessionId: session.id,
                    amount: Number(contest.price || 0),
                    currency: session.currency || "usd",
                    updatedAt: new Date(),
                },
            },
            { upsert: true }
        );

        res.send({ url: session.url });
    });

    app.post("/payments/confirm", verifyJWT, async (req, res) => {
        const sessionId = String(req.body?.sessionId || "").trim();
        const contestId = String(req.body?.contestId || "").trim();

        if (!sessionId || !contestId) {
            return res.status(400).send({ message: "sessionId and contestId required" });
        }
        if (!isValidObjectId(contestId)) return res.status(400).send({ message: "Invalid contest ID" });

        const email = req.user.email;

        const check = await canUserParticipate({ email, contestId });
        if (!check.ok) return res.status(check.code).send({ message: check.message });

        const contest = check.contest;

        const session = await stripe.checkout.sessions.retrieve(sessionId);
        if (!session || session.payment_status !== "paid") {
            return res.status(403).send({ message: "Payment not completed" });
        }

        if (session.customer_email && normalizeEmail(session.customer_email) !== email) {
            return res.status(403).send({ message: "Payment user mismatch" });
        }

        const alreadyPaid = await registrationsCollection.findOne({
            contestId: String(contestId),
            userEmail: email,
            paymentStatus: "paid",
        });

        if (alreadyPaid) return res.send({ success: true, message: "Already confirmed" });

        const updateRes = await registrationsCollection.updateOne(
            { contestId: String(contestId), userEmail: email, paymentStatus: { $ne: "paid" } },
            {
                $setOnInsert: { createdAt: new Date() },
                $set: {
                    contestId: String(contestId),
                    contestName: contest.name,
                    contestType: contest.contestType,
                    contestDeadline: contest.deadline,
                    contestImage: contest.image,
                    userEmail: email,
                    paymentStatus: "paid",
                    sessionId,
                    amount: Number(contest.price || 0),
                    currency: session.currency || "usd",
                    paidAt: new Date(),
                    updatedAt: new Date(),
                },
            },
            { upsert: true }
        );

        if (updateRes.modifiedCount > 0 || updateRes.upsertedCount > 0) {
            await contestsCollection.updateOne(
                { _id: new ObjectId(contestId) },
                { $inc: { participantsCount: 1 }, $set: { updatedAt: new Date() } }
            );
        }

        res.send({ success: true });
    });

    app.get("/registrations/me", verifyJWT, async (req, res) => {
        const email = req.user.email;
        const regs = await registrationsCollection
            .find({ userEmail: email, paymentStatus: "paid" })
            .sort({ paidAt: -1 })
            .toArray();
        res.send(regs);
    });

    app.get("/contests/won/me", verifyJWT, async (req, res) => {
        const email = req.user.email;
        const wins = await contestsCollection
            .find({ status: "confirmed", "winner.email": email })
            .sort({ winnerDeclaredAt: -1 })
            .toArray();
        res.send(wins);
    });

    app.post("/submissions", verifyJWT, async (req, res) => {
        const contestId = String(req.body?.contestId || "").trim();
        const submissionText = String(req.body?.submissionText || "").trim();

        if (!contestId || !submissionText) {
            return res.status(400).send({ message: "contestId and submissionText required" });
        }
        if (!isValidObjectId(contestId)) return res.status(400).send({ message: "Invalid contest ID" });

        const email = req.user.email;

        const reg = await registrationsCollection.findOne({
            contestId: String(contestId),
            userEmail: email,
            paymentStatus: "paid",
        });

        if (!reg) return res.status(403).send({ message: "Register first to submit" });

        const contest = await contestsCollection.findOne({ _id: new ObjectId(contestId), status: "confirmed" });
        if (!contest) return res.status(404).send({ message: "Contest not found" });

        const deadlineMs = contest.deadline ? new Date(contest.deadline).getTime() : 0;
        if (deadlineMs && Date.now() >= deadlineMs) {
            return res.status(403).send({ message: "Contest ended. Submission closed." });
        }

        const me = await usersCollection.findOne({ email });
        const doc = {
            contestId: String(contestId),
            contestName: contest.name,
            contestCreatorEmail: normalizeEmail(contest.createdBy),
            userEmail: email,
            userName: me?.name || "",
            userPhotoURL: me?.photoURL || "",
            submissionText,
            winner: false,
            updatedAt: new Date(),
        };

        const result = await submissionsCollection.updateOne(
            { contestId: String(contestId), userEmail: email },
            { $set: doc, $setOnInsert: { createdAt: new Date() } },
            { upsert: true }
        );

        res.send(result);
    });

    app.get("/creator/submissions", verifyJWT, verifyCreator, async (req, res) => {
        const creatorEmail = req.user.email;
        const contestId = req.query.contestId ? String(req.query.contestId).trim() : "";

        const query = { contestCreatorEmail: creatorEmail };
        if (contestId) query.contestId = contestId;

        const submissions = await submissionsCollection.find(query).sort({ updatedAt: -1 }).toArray();
        res.send(submissions);
    });

    app.patch("/creator/contests/:id/declare-winner", verifyJWT, verifyCreator, async (req, res) => {
        const { id } = req.params;
        const winnerEmailRaw = req.body?.winnerEmail;

        if (!isValidObjectId(id)) return res.status(400).send({ message: "Invalid contest ID" });
        if (!winnerEmailRaw) return res.status(400).send({ message: "winnerEmail required" });

        const winnerEmail = normalizeEmail(winnerEmailRaw);

        const contest = await contestsCollection.findOne({ _id: new ObjectId(id) });
        if (!contest) return res.status(404).send({ message: "Contest not found" });

        if (normalizeEmail(contest.createdBy) !== req.user.email) {
            return res.status(403).send({ message: "Forbidden" });
        }

        if (contest.status !== "confirmed") {
            return res.status(403).send({ message: "Contest must be confirmed before declaring winner" });
        }

        if (contest.winner?.email) {
            return res.status(403).send({ message: "Winner already declared" });
        }

        const deadlineMs = contest.deadline ? new Date(contest.deadline).getTime() : 0;
        if (deadlineMs && Date.now() < deadlineMs) {
            return res.status(403).send({ message: "You can declare winner only after deadline" });
        }

        const winningSubmission = await submissionsCollection.findOne({
            contestId: String(id),
            userEmail: winnerEmail,
        });

        if (!winningSubmission) {
            return res.status(404).send({ message: "Winner submission not found" });
        }

        const winnerUser = await usersCollection.findOne({ email: winnerEmail });
        const winnerObj = {
            name: winnerUser?.name || "",
            email: winnerEmail,
            photoURL: winnerUser?.photoURL || "",
        };

        const contestUpdate = await contestsCollection.updateOne(
            { _id: new ObjectId(id), "winner.email": { $exists: false } },
            { $set: { winner: winnerObj, winnerDeclaredAt: new Date(), updatedAt: new Date() } }
        );

        await submissionsCollection.updateMany({ contestId: String(id) }, { $set: { winner: false } });
        await submissionsCollection.updateOne(
            { contestId: String(id), userEmail: winnerEmail },
            { $set: { winner: true, updatedAt: new Date() } }
        );

        await usersCollection.updateOne(
            { email: winnerEmail },
            { $inc: { winsCount: 1 }, $set: { updatedAt: new Date() } }
        );

        res.send({ success: true, contestUpdate });
    });

    app.get("/leaderboard", async (req, res) => {
        const limit = Math.min(parseInt(req.query.limit || "50", 10) || 50, 100);

        const users = await usersCollection
            .find(
                { role: { $in: ["user", "creator"] } },
                { projection: { name: 1, email: 1, photoURL: 1, winsCount: 1, role: 1, updatedAt: 1 } }
            )
            .sort({ winsCount: -1, updatedAt: -1 })
            .limit(limit)
            .toArray();

        const ranked = users.map((u, i) => ({
            rank: i + 1,
            _id: u._id,
            name: u.name || "",
            email: u.email || "",
            photoURL: u.photoURL || "",
            winsCount: Number(u.winsCount || 0),
            role: u.role || "user",
        }));

        res.send(ranked);
    });

    app.get("/", (req, res) => {
        res.send("Contera Server is Running");
    });

    console.log("✅ MongoDB connected and routes ready");
}

run().catch((err) => {
    console.error("❌ Server startup error:", err);
});

process.on("SIGINT", async () => {
    try {
        await client.close();
        process.exit(0);
    } catch {
        process.exit(1);
    }
});

app.listen(port, () => {
    console.log(`Contera server is listening on port: ${port}`);
});
