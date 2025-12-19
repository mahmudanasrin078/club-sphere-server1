import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import { MongoClient, ServerApiVersion, ObjectId } from "mongodb";
import jwt from "jsonwebtoken";
import Stripe from "stripe";
import admin from "firebase-admin";
import dotenv from "dotenv";

dotenv.config();

//----Firebase admin----
const serviceAccountJson = Buffer.from(
  process.env.FIREBASE_SERVICE_ACCOUNT,
  "base64"
).toString("utf-8");

const serviceAccount = JSON.parse(serviceAccountJson);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Initialize Stripe
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Initialize Express
const app = express();
const port = process.env.PORT || 5000;

//----------MongoDB connection
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: false,
    deprecationErrors: true,
  },
});

let db;

//----------Middleware-----------
app.use(helmet());
app.use(
  cors({
    origin: [process.env.CLIENT_URL, "http://localhost:5173"],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

// Firebase Token Verification -----
const verifyFirebaseToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Unauthorized: Invalid token" });
  }
};

// JWT verification middleware
const verifyJWT = (req, res, next) => {
  const token = req.cookies.jwt || req.headers["x-jwt-token"];
  if (!token) {
    return res.status(401).json({ message: "Unauthorized: No JWT provided" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.jwtUser = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Unauthorized: Invalid JWT" });
  }
};

// Role verification middlewares
const verifyAdmin = async (req, res, next) => {
  const email = req.user?.email || req.jwtUser?.email;
  const user = await db.collection("users").findOne({ email });
  if (user?.role !== "admin") {
    return res
      .status(403)
      .json({ message: "Forbidden: Admin access required" });
  }
  req.dbUser = user;
  next();
};

const verifyManager = async (req, res, next) => {
  const email = req.user?.email || req.jwtUser?.email;
  const user = await db.collection("users").findOne({ email });
  if (user?.role !== "clubManager" && user?.role !== "admin") {
    return res
      .status(403)
      .json({ message: "Forbidden: Manager access required" });
  }
  req.dbUser = user;
  next();
};

const verifyMember = async (req, res, next) => {
  const email = req.user?.email || req.jwtUser?.email;
  const user = await db.collection("users").findOne({ email });
  if (!user) {
    return res
      .status(403)
      .json({ message: "Forbidden: Member access required" });
  }
  req.dbUser = user;
  next();
};

// Connect to mongoDB 
async function run() {
  try {
     // Connect the client to the server	(optional starting in v4.7)
    //await client.connect();
    db = client.db("clubsphere");
    console.log("Connected to MongoDB");

    // Create indexes
    await db.collection("users").createIndex({ email: 1 }, { unique: true });
    await db.collection("clubs").createIndex({ clubName: "text" });
    await db.collection("clubs").createIndex({ status: 1 });
    await db.collection("clubs").createIndex({ managerEmail: 1 });
    await db.collection("memberships").createIndex({ userEmail: 1 });
    await db.collection("memberships").createIndex({ clubId: 1 });
    await db.collection("events").createIndex({ clubId: 1 });
    await db.collection("events").createIndex({ eventDate: 1 });
    await db.collection("eventRegistrations").createIndex({ eventId: 1 });
    await db.collection("eventRegistrations").createIndex({ userEmail: 1 });

    // -----------auth route-----

    // firebase auth
    app.post("/auth/jwt", verifyFirebaseToken, async (req, res) => {
      const { email, name, picture } = req.user;

      // Upsert user in database
      const existingUser = await db.collection("users").findOne({ email });
      if (!existingUser) {
        await db.collection("users").insertOne({
          email,
          name: name || email.split("@")[0],
          photoURL: picture || "",
          role: "member",
          createdAt: new Date(),
        });
      }

      const user = await db.collection("users").findOne({ email });
      const token = jwt.sign(
        { email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: "7d" }
      );

      res.cookie("jwt", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.json({ token, user });
    });

    // Create user 
    app.post("/users", async (req, res) => {
      const { name, email, photoURL } = req.body;

      const existingUser = await db.collection("users").findOne({ email });
      if (existingUser) {
        return res.json({ message: "User already exists", user: existingUser });
      }

      const newUser = {
        name,
        email,
        photoURL: photoURL || "",
        role: "member",
        createdAt: new Date(),
      };

      await db.collection("users").insertOne(newUser);
      res.status(201).json({ message: "User created", user: newUser });
    });

    // Get current user
    app.get("/me", verifyFirebaseToken, verifyMember, async (req, res) => {
      res.json(req.dbUser);
    });

    // Logout
    app.post("/auth/logout", (req, res) => {
      res.clearCookie("jwt");
      res.json({ message: "Logged out successfully" });
    });

    //------admin route--------

    // Admin stats
    app.get(
      "/admin/stats",
      verifyFirebaseToken,
      verifyAdmin,
      async (req, res) => {
        const [
          totalUsers,
          pendingClubs,
          approvedClubs,
          rejectedClubs,
          totalMemberships,
          totalEvents,
          paymentsAgg,
        ] = await Promise.all([
          db.collection("users").countDocuments(),
          db.collection("clubs").countDocuments({ status: "pending" }),
          db.collection("clubs").countDocuments({ status: "approved" }),
          db.collection("clubs").countDocuments({ status: "rejected" }),
          db.collection("memberships").countDocuments(),
          db.collection("events").countDocuments(),
          db
            .collection("payments")
            .aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }])
            .toArray(),
        ]);

        const membershipsPerClub = await db
          .collection("memberships")
          .aggregate([
            { $group: { _id: "$clubId", count: { $sum: 1 } } },
            {
              $lookup: {
                from: "clubs",
                localField: "_id",
                foreignField: "_id",
                as: "club",
              },
            },
            { $unwind: "$club" },
            { $project: { clubName: "$club.clubName", count: 1 } },
            { $limit: 10 },
          ])
          .toArray();

        res.json({
          totalUsers,
          totalClubs: {
            pending: pendingClubs,
            approved: approvedClubs,
            rejected: rejectedClubs,
          },
          totalMemberships,
          totalEvents,
          totalPayments: paymentsAgg[0]?.total || 0,
          membershipsPerClub,
        });
      }
    );

    // Get all users admin
    app.get(
      "/admin/users",
      verifyFirebaseToken,
      verifyAdmin,
      async (req, res) => {
        const users = await db
          .collection("users")
          .find()
          .sort({ createdAt: -1 })
          .toArray();
        res.json(users);
      }
    );

    // Update user role
    app.patch(
      "/admin/users/:email/role",
      verifyFirebaseToken,
      verifyAdmin,
      async (req, res) => {
        const { email } = req.params;
        const { role } = req.body;

        if (email === req.dbUser.email) {
          return res
            .status(400)
            .json({ message: "Cannot change your own role" });
        }

        if (!["admin", "clubManager", "member"].includes(role)) {
          return res.status(400).json({ message: "Invalid role" });
        }

        await db.collection("users").updateOne({ email }, { $set: { role } });

        res.json({ message: "Role updated successfully" });
      }
    );

    // Get all clubs admin
    app.get(
      "/admin/clubs",
      verifyFirebaseToken,
      verifyAdmin,
      async (req, res) => {
        const clubs = await db
          .collection("clubs")
          .aggregate([
            {
              $lookup: {
                from: "memberships",
                localField: "_id",
                foreignField: "clubId",
                as: "members",
              },
            },
            {
              $lookup: {
                from: "events",
                localField: "_id",
                foreignField: "clubId",
                as: "events",
              },
            },
            {
              $addFields: {
                membersCount: { $size: "$members" },
                eventsCount: { $size: "$events" },
              },
            },
            {
              $project: { members: 0, events: 0 },
            },
          ])
          .sort({ createdAt: -1 })
          .toArray();

        res.json(clubs);
      }
    );

    // Update club status approve/reject
    app.patch(
      "/admin/clubs/:id/status",
      verifyFirebaseToken,
      verifyAdmin,
      async (req, res) => {
        const { id } = req.params;
        const { status } = req.body;

        if (!["pending", "approved", "rejected"].includes(status)) {
          return res.status(400).json({ message: "Invalid status" });
        }

        await db
          .collection("clubs")
          .updateOne(
            { _id: new ObjectId(id) },
            { $set: { status, updatedAt: new Date() } }
          );

        res.json({ message: "Club status updated successfully" });
      }
    );

    // Get all payments admin
    app.get(
      "/admin/payments",
      verifyFirebaseToken,
      verifyAdmin,
      async (req, res) => {
        const payments = await db
          .collection("payments")
          .aggregate([
            {
              $lookup: {
                from: "clubs",
                localField: "clubId",
                foreignField: "_id",
                as: "club",
              },
            },
            { $unwind: { path: "$club", preserveNullAndEmptyArrays: true } },
          ])
          .sort({ createdAt: -1 })
          .toArray();

        res.json(payments);
      }
    );

    // ----------- CLUBS ROUTES --------

    // approved clubs public
    app.get("/clubs", async (req, res) => {
      const { search, category, sort } = req.query;

      const query = { status: "approved" };

      if (search) {
        query.$text = { $search: search };
      }
      if (category) {
        query.category = category;
      }

      let sortOption = { createdAt: -1 };
      if (sort === "oldest") sortOption = { createdAt: 1 };
      if (sort === "fee-high") sortOption = { membershipFee: -1 };
      if (sort === "fee-low") sortOption = { membershipFee: 1 };
      if (sort === "name-az") sortOption = { clubName: 1 };
      if (sort === "name-za") sortOption = { clubName: -1 };

      const clubs = await db
        .collection("clubs")
        .find(query)
        .sort(sortOption)
        .toArray();

      res.json(clubs);
    });

    // Get single club 
    app.get("/clubs/:id", async (req, res) => {
      const { id } = req.params;
      const club = await db
        .collection("clubs")
        .aggregate([
          { $match: { _id: new ObjectId(id) } },
          {
            $lookup: {
              from: "memberships",
              localField: "_id",
              foreignField: "clubId",
              as: "members",
            },
          },
          {
            $lookup: {
              from: "events",
              localField: "_id",
              foreignField: "clubId",
              as: "events",
            },
          },
          {
            $addFields: {
              membersCount: { $size: "$members" },
              eventsCount: { $size: "$events" },
            },
          },
          { $project: { members: 0, events: 0 } },
        ])
        .toArray();

      if (!club[0]) {
        return res.status(404).json({ message: "Club not found" });
      }

      res.json(club[0]);
    });

    // Create club manager
    app.post("/clubs", verifyFirebaseToken, verifyManager, async (req, res) => {
      const {
        clubName,
        description,
        category,
        location,
        bannerImage,
        membershipFee,
      } = req.body;

      const newClub = {
        clubName,
        description,
        category,
        location,
        bannerImage: bannerImage || "",
        membershipFee: membershipFee || 0,
        status: "pending",
        managerEmail: req.dbUser.email,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await db.collection("clubs").insertOne(newClub);
      res
        .status(201)
        .json({ message: "Club created", clubId: result.insertedId });
    });

    // Update club manager owner
    app.patch(
      "/clubs/:id",
      verifyFirebaseToken,
      verifyManager,
      async (req, res) => {
        const { id } = req.params;
        const club = await db
          .collection("clubs")
          .findOne({ _id: new ObjectId(id) });

        if (!club) {
          return res.status(404).json({ message: "Club not found" });
        }

        if (
          club.managerEmail !== req.dbUser.email &&
          req.dbUser.role !== "admin"
        ) {
          return res
            .status(403)
            .json({ message: "Not authorized to update this club" });
        }

        const {
          clubName,
          description,
          category,
          location,
          bannerImage,
          membershipFee,
        } = req.body;

        await db.collection("clubs").updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              ...(clubName && { clubName }),
              ...(description && { description }),
              ...(category && { category }),
              ...(location && { location }),
              ...(bannerImage !== undefined && { bannerImage }),
              ...(membershipFee !== undefined && { membershipFee }),
              updatedAt: new Date(),
            },
          }
        );

        res.json({ message: "Club updated successfully" });
      }
    );

    // Get manager's clubs
    app.get(
      "/manager/clubs",
      verifyFirebaseToken,
      verifyManager,
      async (req, res) => {
        const clubs = await db
          .collection("clubs")
          .aggregate([
            { $match: { managerEmail: req.dbUser.email } },
            {
              $lookup: {
                from: "memberships",
                localField: "_id",
                foreignField: "clubId",
                as: "members",
              },
            },
            {
              $addFields: { membersCount: { $size: "$members" } },
            },
            { $project: { members: 0 } },
          ])
          .sort({ createdAt: -1 })
          .toArray();

        res.json(clubs);
      }
    );

    // Get club members manager/admin
    app.get(
      "/clubs/:id/members",
      verifyFirebaseToken,
      verifyManager,
      async (req, res) => {
        const { id } = req.params;
        const club = await db
          .collection("clubs")
          .findOne({ _id: new ObjectId(id) });

        if (!club) {
          return res.status(404).json({ message: "Club not found" });
        }

        if (
          club.managerEmail !== req.dbUser.email &&
          req.dbUser.role !== "admin"
        ) {
          return res.status(403).json({ message: "Not authorized" });
        }

        const members = await db
          .collection("memberships")
          .aggregate([
            { $match: { clubId: new ObjectId(id) } },
            {
              $lookup: {
                from: "users",
                localField: "userEmail",
                foreignField: "email",
                as: "user",
              },
            },
            { $unwind: "$user" },
          ])
          .toArray();

        res.json(members);
      }
    );
//---------------------------------
   


//---------------------------------
    // Health check
    app.get("/health", (req, res) => {
      res.json({ status: "ok", timestamp: new Date() });
    });

    // 404 handler
    app.use((req, res) => {
      res.status(404).json({ message: "Route not found" });
    });

    // Error handler
    app.use((err, req, res, next) => {
      console.error(err.stack);
      res.status(500).json({ message: "Internal server error" });
    });
//-----------------------
    app.listen(port, () => {
      console.log(`ClubSphere server running on port ${port}`);
    });
  } catch (error) {
    console.error("Failed to connect to MongoDB:", error);
    process.exit(1);
  }
}

run();
