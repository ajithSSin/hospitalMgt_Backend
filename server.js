import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";

import dotenv from "dotenv";
dotenv.config();


import http from "http";
import { Server } from "socket.io";

const app = express();
app.use(express.json());
app.use(cors());

//MongoDB connection

//locally mongoDb Compass
// mongoose.connect("mongodb://127.0.0.1:27017/hospital")
//   .then(() => console.log('DB connected'))
//   .catch(() => console.log('DB failed'));

//MongoDB Atlas connection
const DB_URI=process.env.MONGO_URI

console.log(process.env.MONGO_URI);


mongoose.connect(DB_URI);
const conn=mongoose.connection;
conn.once('open',()=>{
  console.log("Successfully Connected to Database MongoDB ");  
})
conn.on("error",()=>{
  console.log("Failed to Connect");
  
})

// ////////////////////MODELS ////////////////
//user login
const userSchema = new mongoose.Schema({
  name: String,
  user: String,
  password: String,
  role: String // admin | doctor | patient
});
const User = mongoose.model("User", userSchema);

// ADD userId TO LINK WITH User
const doctorSchema = new mongoose.Schema({
  name: String,
  specialization: String,
  userId: { type: mongoose.Schema.Types.ObjectId, //refer to another collection
            ref: "User", 
            required: true, 
            unique: true 
          }
});
const Doctor = mongoose.model("Doctor", doctorSchema);

const appointmentSchema = new mongoose.Schema({
  patientId: String,
  doctorId: String,          // references Doctor._id
  date: String,
  time: String,
  status: { type: String, default: "Pending" }
});
const Appointment = mongoose.model("Appointment", appointmentSchema);

// //////////////// SOCKET.IO //////////////////
const server = http.createServer(app);
//const io=socketIo(server)
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Socket.io authentication
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error("Authentication error"));
  try {
    const decoded = jwt.verify(token, process.env.SECRET_KEY);
    socket.user = decoded; // contains { id, role, doctorId } if doctor
    next();
  } catch {
    next(new Error("Invalid token"));
  }
});

io.on("connection", (socket) => {
  console.log("User connected:", socket.user.id, "role:", socket.user.role);

  // If doctor, join a private room with their doctorId
  if (socket.user.role === "doctor" && socket.user.doctorId) {
    const room = `doctor:${socket.user.doctorId}`;
    socket.join(room);
    console.log(`Doctor joined room: ${room}`);
  }

  socket.on("disconnect", () => console.log("User disconnected"));
});

// //////////////// MIDDLEWARE //////////////////
function auth(req, res, next) {
  const authHeader = req.headers.authorization;
  console.log("authHeader in fn auth",authHeader);
  
  if (!authHeader) return res.json({ message: "Login required" });
  const token = authHeader.split(" ")[1];
  console.log("token",token);
  
  if (!token) return res.json({ message: "Malformed token" });

  try {
    const decoded = jwt.verify(token, process.env.SECRET_KEY);
    req.result = decoded;
    next();
  } catch {
    res.json({ message: "Invalid token" });
  }
}

function checkRole(role) {
  return function (req, res, next) {
    if (req.result.role !== role) {
      return res.json({ message: "Access denied" });
    }
    next();
  };
}

// //////////// AUTH ROUTES////////////////
app.post("/register", async (req, res) => {
  const { name, user, password, role } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const result = await User.create({ name, user, password: hashed, role });
  res.json(result);
});

app.post("/login", async (req, res) => {
  try {
    const { user, password } = req.body;
    const result = await User.findOne({ user });
    if (!result) return res.json({ message: "User not found" });

    const match = await bcrypt.compare(password, result.password);
    if (!match) return res.json({ message: "Wrong password" });

    // Base payload
    const payload = { id: result._id, role: result.role };
    console.log(payload);
    
    let userIdToSend = result._id; // default

    //  If doctor, fetch their Doctor record and use doctor._id as userId
    if (result.role === "doctor") {
      const doctor = await Doctor.findOne({ userId: result._id });
      if (!doctor) {
        return res.json({ message: "No doctor profile linked. Contact admin." });
      }
      payload.doctorId = doctor._id;
      userIdToSend = doctor._id; // Use doctor._id instead of user._id
    }

    const token = jwt.sign(payload, process.env.SECRET_KEY);

    res.json({
      token,
      role: result.role,
      userId: userIdToSend // send the correct ID
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});


// //////////////// ADMIN ROUTES ////////////////////
// Get all users with role "doctor" (for admin dropdown)
app.get("/doctor-users", auth, checkRole("admin"), async (req, res) => {
  const users = await User.find({ role: "doctor" }, "_id name user");
  res.json(users);
});

// Add Doctor (Admin only) - now requires userId
app.post("/add-doctor", auth, checkRole("admin"), async (req, res) => {
  try {
    const { name, specialization, userId } = req.body;

    // Check if user exists and is a doctor
    const user = await User.findById(userId);
    if (!user || user.role !== "doctor") {
      return res.json({ message: "Invalid user or user is not a doctor" });
    }

    // Check if doctor already exists for this user
    const existing = await Doctor.findOne({ userId });
    if (existing) {
      return res.json({ message: "Doctor already exists for this user" });
    }

    const doctor = await Doctor.create({ name, specialization, userId });
    res.json(doctor);
  } catch (error) {
    res.status(500).json({ message: "Failed to add doctor" });
  }
});

// //////////////// PATIENT ROUTES //////////////////
app.post("/book", auth, checkRole("patient"), async (req, res) => {
  try {
    const { doctorId, date, time } = req.body;

    const exists = await Appointment.findOne({ doctorId,
                                                date,
                                                time,
                                                status: { $in: ["Pending", "Accepted"] }
                                            });

    if (exists) {
      return res.json({ message: "Slot already booked" });
    }

    const appointment = await Appointment.create({
      patientId: req.result.id,
      doctorId,
      date,
      time
    });

    //For Notification:Notify ONLY the specific doctor (via their private room)
    io.to(`doctor:${doctorId}`).emit("new-appointment", appointment);

    res.json(appointment);
  } catch (error) {
    res.status(500).json({ message: "Booking failed" });
  }
});

app.put("/cancel/:id", auth, checkRole("patient"), async (req, res) => {
  try {
    const appointment = await Appointment.findById(req.params.id);
    if (appointment.patientId !== req.result.id) {
      return res.json({ message: "Unauthorized" });
    }
    appointment.status = "Cancelled";
    await appointment.save();
    res.json({ message: "Cancelled" });
  } catch (error) {
    res.status(500).json({ message: "Cancel failed" });
  }
});

// //////////////////// DOCTOR ROUTES //////////////////////
app.get("/doctor-appointments", auth, checkRole("doctor"), async (req, res) => {
  try {
    // Get doctorId from token (set during login)
    const doctorId = req.result.doctorId;
    if (!doctorId) {
      return res.json({ message: "No doctor profile linked" });
    }
    // Fetch ONLY appointments for this doctor
    const appointments = await Appointment.find({ doctorId });
    res.json(appointments);
  } catch (error) {
    res.status(500).json({ message: "Failed to load appointments" });
  }
});

app.put("/update-status/:id", auth, checkRole("doctor"), async (req, res) => {
  try {
    const { status } = req.body;
    await Appointment.findByIdAndUpdate(req.params.id, { status });
    res.json({ message: "Status Updated" });
  } catch (error) {
    res.status(500).json({ message: "Update failed" });
  }
});

// ////////////////////// VIEW ROUTES ////////////////////////
app.get("/doctors", async (req, res) => {
  try {
    const doctors = await Doctor.find();
    res.json(doctors);
  } catch (error) {
    res.status(500).json({ message: "Failed to load doctors" });
  }
});

app.get("/my-appointments", auth, checkRole("patient"), async (req, res) => {
  try {
    const appointments = await Appointment.find({ patientId: req.result.id });
    res.json(appointments);
  } catch (error) {
    res.status(500).json({ message: "Failed to load appointments" });
  }
});

// ////////////////// START SERVER //////////////////////
server.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});