import "dotenv/config";
import express from "express";
import mysql from "mysql2";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import multer from "multer"; // <--- KEEP THIS LINE
import nodemailer from "nodemailer";
import fs from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// 🟢 OPTIMIZED: Disk Storage (Saves file to 'uploads/' folder)
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Ensure this folder exists!
    const dir = "uploads/";
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir);
    }
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    // Give every file a unique name (timestamp + original name)
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    // Sanitize filename to remove spaces
    const cleanName = file.originalname.replace(/\s+/g, "-");
    cb(null, uniqueSuffix + "-" + cleanName);
  },
});
// 🟢 MISSING MIDDLEWARE: Paste this near the top of index.js 🟢
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null)
    return res
      .status(401)
      .json({ success: false, message: "No token provided" });

  // Use your JWT_SECRET (it might be 'your_secret_key' or process.env.JWT_SECRET)
  jwt.verify(
    token,
    process.env.JWT_SECRET || "your_secret_key",
    (err, user) => {
      if (err)
        return res
          .status(403)
          .json({ success: false, message: "Invalid token" });
      req.user = user;
      next();
    }
  );
};
// ------------------- THIS IS THE FIX -------------------
// Secure file filter to only allow images
const imageFileFilter = (req, file, cb) => {
  if (file.mimetype === "image/jpeg" || file.mimetype === "image/png") {
    cb(null, true);
  } else {
    // Reject file
    cb(
      new Error("Invalid file type. Only JPEG, PNG, or GIF are allowed."),
      false
    );
  }
};

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB file size limit
  },
  fileFilter: imageFileFilter,
});
// ----------------- END OF FIX ------------------

// Serve static files from the 'uploads' directory
// This allows dashboard.html to show the image using a URL like /uploads/filename.jpg
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
// --- NEW: Multer config for service requirements (allows docs, pdf, images) ---
const documentFileFilter = (req, file, cb) => {
  const allowedMimes = [
    "image/jpeg",
    "image/png",
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document", // .docx
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", // .xlsx
  ];
  if (allowedMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(
      new Error(
        "Invalid file type. Only images, PDF, Word, or Excel files are allowed."
      ),
      false
    );
  }
};

const requirementsUpload = multer({
  storage: storage,
  limits: {
    fileSize: 2 * 1024 * 1024, // 🟢 CHANGE TO 2MB (Was 10MB)
  },
  fileFilter: documentFileFilter,
});
// --- END OF NEW BLOCK ---

// JWT Secret for Admin/User Login
const JWT_SECRET = process.env.JWT_SECRET || "rsu-reqs-admin-secret-key-2024";

// NEW: JWT Secret for Password Resets (use a different secret!)
const JWT_RESET_SECRET =
  process.env.JWT_RESET_SECRET || "rsu-reqs-reset-secret-key-9a8b7c6d";

// --- 🟢 UPDATED MAIL CONFIGURATION (Service Mode) 🟢 ---
const transporter = nodemailer.createTransport({
  service: "gmail", // Let Nodemailer handle the ports automatically
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  // Increase timeout to 30 seconds to prevent early cutoffs
  connectionTimeout: 30000,
  greetingTimeout: 30000,
  socketTimeout: 30000,
});

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  ssl: {
    rejectUnauthorized: false,
  },
  waitForConnections: true,
  connectionLimit: 5,
  queueLimit: 0,
});

// Test connection
db.getConnection((err, connection) => {
  if (err) {
    console.error("❌ AIVEN HARDCODE FAILED:", err.code, err.message);
  } else {
    console.log("✅ CONNECTED TO AIVEN (HARDCODED)!");
    connection.release();

    // 1. Init Tables
    createServiceRequestsTable();
    createQueueTable();
    createAdminStaffTable();
    createFeedbackTable();

    // 2. === FIX: ADD MISSING COLUMNS ===
    // This adds the columns so the "N/A" will be replaced by real data
    addColumnIfNotExists("service_requests", "campus", "VARCHAR(255)");
    addColumnIfNotExists("service_requests", "dob", "DATE");
    addColumnIfNotExists("service_requests", "pob", "VARCHAR(255)");
    addColumnIfNotExists("service_requests", "nationality", "VARCHAR(100)");
    addColumnIfNotExists("service_requests", "home_address", "TEXT");
    addColumnIfNotExists("service_requests", "school_id_picture", "LONGTEXT");
    addColumnIfNotExists(
      "service_requests",
      "requirements_confirmed",
      "TINYINT(1) DEFAULT 0"
    );

    // 3. Keep existing columns
    addColumnIfNotExists("service_requests", "claim_details", "TEXT");
    addColumnIfNotExists("queue", "claim_details", "TEXT");
    addColumnIfNotExists("queue", "progress_data", "JSON");
    addColumnIfNotExists("queue", "window_number", "VARCHAR(50)");
    addColumnIfNotExists("admin_staff", "assigned_window", "VARCHAR(50)");
  }
});

// Paste this function near the top of index.js, after the imports
function addColumnIfNotExists(tableName, columnName, columnDefinition) {
  const dbName = process.env.DB_NAME || "rsu_reqs_db";
  const checkColumnSql = `
    SELECT * FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_SCHEMA = ? 
    AND TABLE_NAME = ? 
    AND COLUMN_NAME = ?
  `;

  db.query(checkColumnSql, [dbName, tableName, columnName], (err, results) => {
    if (err) {
      console.error(
        `❌ Error checking column ${tableName}.${columnName}:`,
        err
      );
      return;
    }

    if (results.length === 0) {
      // Column does not exist, so add it
      const addColumnSql = `
        ALTER TABLE ${tableName} 
        ADD COLUMN ${columnName} ${columnDefinition}
      `;
      db.query(addColumnSql, (addErr) => {
        if (addErr) {
          console.error(
            `❌ Error adding column ${tableName}.${columnName}:`,
            addErr
          );
        } else {
          console.log(
            `✅ Column ${tableName}.${columnName} added successfully.`
          );
        }
      });
    } else {
      // Column already exists
      console.log(`✅ Column ${tableName}.${columnName} already exists.`);
    }
  });
}
// --- END OF NEW FUNCTION ---

// Create or update service_requests table
function createServiceRequestsTable() {
  const serviceRequestsTable = `
    CREATE TABLE IF NOT EXISTS service_requests (
      request_id VARCHAR(100) PRIMARY KEY,
      user_id INT NOT NULL,
      user_name VARCHAR(255) NOT NULL,
      student_id VARCHAR(50),
      course VARCHAR(255),
      year_level VARCHAR(50),
      services JSON,
      total_amount DECIMAL(10,2) DEFAULT 0,
      requirements JSON,
      status ENUM('pending', 'approved', 'declined') DEFAULT 'pending',
      queue_status VARCHAR(50) DEFAULT 'pending',
      queue_number VARCHAR(50),
      submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      approved_by VARCHAR(255),
      approved_by_id INT,
      approved_at DATETIME,
      approve_notes TEXT,
      declined_by VARCHAR(255),
      declined_by_id INT,
      declined_at DATETIME,
      decline_reason TEXT,
      is_viewed_by_user TINYINT(1) DEFAULT 0,
      contact_email VARCHAR(255),
      contact_phone VARCHAR(20),
      claim_details TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (approved_by_id) REFERENCES admin_staff(id),
      FOREIGN KEY (declined_by_id) REFERENCES admin_staff(id)
    )
  `;

  db.query(serviceRequestsTable, (err) => {
    if (err) console.error("Error creating service_requests table:", err);
    else console.log("✅ service_requests table ready");
  });
}
// -------------------------------------------------------------------
// Get the next global queue number (A-001, A-002, …)
// Returns a string like "A-001"
// -------------------------------------------------------------------
// -------------------------------------------------------------------
// FIX: Get the next global queue number (Continuous)
// This looks at ALL history to find the highest number, preventing duplicates.
// -------------------------------------------------------------------
function getNextQueueNumber(callback) {
  const sql = `
    SELECT queue_number 
    FROM queue 
    WHERE queue_number REGEXP '^A-[0-9]+$' 
    -- REMOVED DATE CHECK to ensure unique numbers globally
    ORDER BY CAST(SUBSTRING(queue_number, 3) AS UNSIGNED) DESC 
    LIMIT 1
  `;

  db.query(sql, (err, rows) => {
    if (err) return callback(err);

    let nextSeq = 1;
    if (rows.length > 0) {
      const last = rows[0].queue_number; // e.g. "A-193"
      const num = parseInt(last.split("-")[1], 10);
      nextSeq = num + 1;
    }

    // Format as A-XXX (e.g., A-194)
    const nextNumber = `A-${String(nextSeq).padStart(3, "0")}`;
    callback(null, nextNumber);
  });
}

// Create admin_staff table
function createAdminStaffTable() {
  const staffTable = `
    CREATE TABLE IF NOT EXISTS admin_staff (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      full_name VARCHAR(255) NOT NULL,
      phone VARCHAR(20),
      department VARCHAR(100),
      role ENUM('super_admin', 'admin', 'staff') DEFAULT 'staff',
      is_active BOOLEAN DEFAULT TRUE,
      last_login DATETIME,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `;

  db.query(staffTable, (err) => {
    if (err) {
      console.error("Error creating admin_staff table:", err);
    } else {
      console.log("✅ admin_staff table ready");
      createDefaultAdmin();
    }
  });
}

// Create default admin account
async function createDefaultAdmin() {
  const checkAdmin =
    "SELECT * FROM admin_staff WHERE email = 'admin@rsu.edu.ph'";

  db.query(checkAdmin, async (err, results) => {
    if (err) {
      console.error("Error checking admin account:", err);
      return;
    }

    if (results.length === 0) {
      const hashedPassword = await bcrypt.hash("admin123", 10);
      const insertAdmin = `
        INSERT INTO admin_staff (email, password, full_name, role) 
        VALUES (?, ?, ?, 'super_admin')
      `;

      db.query(
        insertAdmin,
        ["admin@rsu.edu.ph", hashedPassword, "System Administrator"],
        (err) => {
          if (err) {
            console.error("Error creating default admin:", err);
          } else {
            console.log(
              "✅ Default admin account created - Email: admin@rsu.edu.ph, Password: admin123"
            );
          }
        }
      );
    }
  });
}

// Create queue table
function createQueueTable() {
  const queueTable = `
    CREATE TABLE IF NOT EXISTS queue (
      queue_id INT AUTO_INCREMENT PRIMARY KEY,
      queue_number VARCHAR(50) UNIQUE NOT NULL,
      user_id INT NOT NULL,
      user_name VARCHAR(255) NOT NULL,
      student_id VARCHAR(50),
      course VARCHAR(255),
      year_level VARCHAR(50),
      request_id VARCHAR(50),
      services JSON,
      total_amount DECIMAL(10,2) DEFAULT 0,
      status ENUM('waiting', 'processing', 'ready', 'completed') DEFAULT 'waiting',
      is_priority BOOLEAN DEFAULT FALSE,
      priority_type VARCHAR(100),
      submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      started_at DATETIME,
      completed_at DATETIME,
      processed_by VARCHAR(255),
      processed_by_id INT DEFAULT NULL,
      completed_by VARCHAR(255),
      completed_by_id INT,
      added_by VARCHAR(255),
      added_by_id INT,
      claim_details TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (request_id) REFERENCES service_requests(request_id) ON DELETE CASCADE,
      FOREIGN KEY (processed_by_id) REFERENCES admin_staff(id),
      FOREIGN KEY (completed_by_id) REFERENCES admin_staff(id),
      FOREIGN KEY (added_by_id) REFERENCES admin_staff(id)
    )
  `;

  db.query(queueTable, (err) => {
    if (err) console.error("Error creating queue table:", err);
    else console.log("✅ queue table ready");
  });
}

// --- 🟢 NEW: Create Feedback Table 🟢 ---
function createFeedbackTable() {
  const query = `
    CREATE TABLE IF NOT EXISTS feedback (
      id INT AUTO_INCREMENT PRIMARY KEY,
      request_id VARCHAR(50) NOT NULL,
      user_id INT NOT NULL,
      sqd0_satisfaction INT NOT NULL, 
      sqd_responses JSON, -- Stores SQD 1-8 answers
      cc_responses JSON, -- Stores Citizen Charter answers
      comments TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (request_id) REFERENCES service_requests(request_id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `;
  db.query(query, (err) => {
    if (err) console.error("Error creating feedback table:", err);
    else console.log("✅ feedback table ready");
  });
}

// Admin Authentication Middleware
const authenticateAdmin = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Access denied. No token provided.",
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (error) {
    res.status(401).json({
      success: false,
      message: "Invalid token",
    });
  }
};

// Serve static files
app.use("/assets", express.static(path.join(__dirname, "assets")));
app.use(express.json());

// Service hours check middleware
function checkServiceHoursHTML(req, res, next) {
  const now = new Date();
  const hours = now.getHours();
  const openHour = 0;
  const closeHour = 24;

  if (req.path === "/admin" || req.path === "/adminlogin") {
    return next();
  }

  if (hours >= openHour && hours < closeHour) {
    next();
  } else {
    res.redirect("/");
  }
}

const protectedRoutes = ["/login", "/register", "/queue", "/dashboard"];
app.use(protectedRoutes, checkServiceHoursHTML);

// HTML Routes
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "welcome.html"));
});

app.get("/privacy", (req, res) => {
  res.sendFile(path.join(__dirname, "privacy.html"));
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "register.html"));
});

app.get("/queue", (req, res) => {
  res.sendFile(path.join(__dirname, "queue.html"));
});

app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "dashboard.html"));
});

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admindashb.html"));
});

app.get("/adminLogin", (req, res) => {
  res.sendFile(path.join(__dirname, "adminlogin.html"));
});

app.get("/adminRegister.html", (req, res) => {
  res.sendFile(path.join(__dirname, "adminRegister.html"));
});
// --- 🟢 PASTE these with your other app.get() routes 🟢 ---

app.get("/forgot", (req, res) => {
  res.sendFile(path.join(__dirname, "forgot.html"));
});

app.get("/reset-password", (req, res) => {
  // This page is only useful if there's a token
  const token = req.query.token;
  if (!token) {
    return res.redirect("/forgot");
  }
  res.sendFile(path.join(__dirname, "reset-password.html"));
});

// --- 🟢 END OF NEW BLOCK 🟢 ---

// ADMIN AUTHENTICATION API ROUTES
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: "Email and password are required",
    });
  }

  try {
    db.query(
      "SELECT * FROM admin_staff WHERE email = ? AND is_active = 1",
      [email],
      async (err, results) => {
        if (err) {
          console.error("Admin login database error:", err);
          return res.status(500).json({
            success: false,
            message: "Database error",
          });
        }

        if (results.length === 0) {
          return res.json({
            success: false,
            message: "Invalid email or password",
          });
        }

        const admin = results[0];
        const isPasswordValid = await bcrypt.compare(password, admin.password);

        if (!isPasswordValid) {
          return res.json({
            success: false,
            message: "Invalid email or password",
          });
        }

        db.query("UPDATE admin_staff SET last_login = NOW() WHERE id = ?", [
          admin.id,
        ]);

        const token = jwt.sign(
          {
            adminId: admin.id,
            email: admin.email,
            role: admin.role,
            full_name: admin.full_name,
          },
          JWT_SECRET,
          { expiresIn: "8h" }
        );

        const { password: _, ...adminWithoutPassword } = admin;

        res.json({
          success: true,
          message: "Login successful",
          admin: adminWithoutPassword,
          token,
        });
      }
    );
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({
      success: false,
      message: "Server error occurred",
    });
  }
});

// === API: ADMIN REGISTRATION (SECURED: Super Admin Only) ===
app.post("/api/admin/register", authenticateAdmin, async (req, res) => {
  // 1. Security Check: Only Super Admins can create new staff
  if (req.admin.role !== "super_admin") {
    return res.status(403).json({
      success: false,
      message: "Access denied. Only Super Admins can register staff.",
    });
  }

  const {
    email,
    password,
    lastName,
    firstName,
    middleInitial,
    phone,
    sex,
    address,
    full_name,
  } = req.body;

  // Basic Validation
  if (!email || !password || !lastName || !firstName) {
    return res
      .status(400)
      .json({ success: false, message: "Missing required fields." });
  }

  try {
    // 2. Check if email already exists
    db.query(
      "SELECT id FROM admin_staff WHERE email = ?",
      [email],
      async (err, results) => {
        if (err) {
          console.error("Registration DB check error:", err);
          return res
            .status(500)
            .json({ success: false, message: "Database error." });
        }

        if (results.length > 0) {
          return res.json({
            success: false,
            message: "Email already registered.",
          });
        }

        // 3. Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // 4. Insert the new staff member
        const insertSql = `
            INSERT INTO admin_staff 
            (email, password, last_name, first_name, middle_initial, phone, sex, permanent_address, full_name, role, is_active) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'staff', 1)
        `;

        db.query(
          insertSql,
          [
            email,
            hashedPassword,
            lastName,
            firstName,
            middleInitial || "",
            phone,
            sex,
            address,
            full_name,
          ],
          (insertErr, result) => {
            if (insertErr) {
              console.error("Registration Insert Error:", insertErr);
              return res.status(500).json({
                success: false,
                message: "Failed to register account.",
              });
            }

            res.json({
              success: true,
              message: "New staff account created successfully!",
            });
          }
        );
      }
    );
  } catch (error) {
    console.error("Server error during registration:", error);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

app.get("/api/admin/me", authenticateAdmin, (req, res) => {
  db.query(
    "SELECT id, email, full_name, phone, department, role, created_at, last_login FROM admin_staff WHERE id = ?",
    [req.admin.adminId],
    (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({
          success: false,
          message: "Database error",
        });
      }

      if (results.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Admin not found",
        });
      }

      res.json({
        success: true,
        admin: results[0],
      });
    }
  );
});

// Add this route for admin profile updates
app.post("/api/admin/update-me", authenticateAdmin, async (req, res) => {
  // Get the admin's ID from the token, not the body
  const adminId = req.admin.adminId;
  const { email, full_name, phone, newPassword } = req.body;

  if (!email || !full_name) {
    return res
      .status(400)
      .json({ success: false, message: "Email and Full Name are required." });
  }

  try {
    // 1. Check if the new email is already taken by ANOTHER admin
    const [existingAdmin] = await db
      .promise()
      .query("SELECT id FROM admin_staff WHERE email = ? AND id != ?", [
        email,
        adminId,
      ]);

    if (existingAdmin.length > 0) {
      return res.json({
        success: false,
        message: "This email is already in use by another account.",
      });
    }

    let hashedPassword = null;
    if (newPassword && newPassword.trim() !== "") {
      // 2. If a new password is provided, hash it
      hashedPassword = await bcrypt.hash(newPassword, 10);
    }

    // 3. Build the update query
    let updateQuery = `
      UPDATE admin_staff 
      SET email = ?, full_name = ?, phone = ? 
    `;
    const queryParams = [email, full_name, phone || null];

    if (hashedPassword) {
      // Add password to the query if it was changed
      updateQuery += ", password = ? ";
      queryParams.push(hashedPassword);
    }

    updateQuery += " WHERE id = ? ";
    queryParams.push(adminId);

    // 4. Execute the update
    await db.promise().query(updateQuery, queryParams);

    res.json({
      success: true,
      message: "Profile updated successfully.",
    });
  } catch (error) {
    console.error("Admin profile update error:", error);
    res.status(500).json({ success: false, message: "Database error" });
  }
});

// === API: GET ALL ACTIVE WINDOWS (for locking logic) ===
app.get("/api/admin/active-windows", authenticateAdmin, (req, res) => {
  const query = `
    SELECT assigned_window 
    FROM admin_staff 
    WHERE assigned_window IS NOT NULL AND is_active = 1
  `;
  db.query(query, (err, results) => {
    if (err) {
      console.error("Database error fetching active windows:", err);
      return res
        .status(500)
        .json({ success: false, message: "Database error" });
    }
    const activeWindows = results.map((row) => row.assigned_window);
    res.json({ success: true, activeWindows });
  });
});

// === API: LOCK/ASSIGN WINDOW ===
app.post("/api/admin/assign-window", authenticateAdmin, (req, res) => {
  const { windowNumber } = req.body;
  const adminId = req.admin.adminId;

  if (!windowNumber) {
    return res
      .status(400)
      .json({ success: false, message: "Window number is required." });
  }

  // Check if the window is already assigned to someone else
  const checkQuery = `
    SELECT full_name 
    FROM admin_staff 
    WHERE assigned_window = ? AND id != ?
  `;
  db.query(checkQuery, [windowNumber, adminId], (err, results) => {
    if (err) {
      console.error("Database error checking window lock:", err);
      return res
        .status(500)
        .json({ success: false, message: "Database error" });
    }

    if (results.length > 0) {
      return res.json({
        success: false,
        message: `${windowNumber} is already taken by ${results[0].full_name}.`,
      });
    }

    // Assign the window
    const assignQuery = `
      UPDATE admin_staff 
      SET assigned_window = ? 
      WHERE id = ?
    `;
    db.query(assignQuery, [windowNumber, adminId], (updateErr) => {
      if (updateErr) {
        console.error("Database error assigning window:", updateErr);
        return res
          .status(500)
          .json({ success: false, message: "Database error" });
      }
      res.json({ success: true, message: "Window assigned successfully." });
    });
  });
});

// === API: UNLOCK WINDOW (on logout/refresh) ===
app.post("/api/admin/unassign-window", authenticateAdmin, (req, res) => {
  const adminId = req.admin.adminId;

  const unassignQuery = `
    UPDATE admin_staff 
    SET assigned_window = NULL 
    WHERE id = ?
  `;
  db.query(unassignQuery, [adminId], (err) => {
    if (err) {
      console.error("Database error unassigning window:", err);
      return res
        .status(500)
        .json({ success: false, message: "Database error" });
    }
    res.json({ success: true, message: "Window unassigned successfully." });
  });
});

const adminApiRoutes = [
  "/api/admin/service-requests",
  "/api/admin/add-to-queue",
  "/api/admin/queues",
  "/api/admin/start-processing",
  "/api/admin/mark-done",
  "/api/admin/notify-student",
  "/api/admin/manual-queue-entry",
];

app.use(adminApiRoutes, authenticateAdmin);

function addToQueueSystem(requestId) {
  console.log(`[DEBUG] Starting addToQueueSystem for requestId: ${requestId}`);

  const requestQuery = "SELECT * FROM service_requests WHERE request_id = ?";
  db.query(requestQuery, [requestId], (err, requests) => {
    if (err || requests.length === 0) {
      console.error("[ERROR] Request not found or DB error:", err);
      return;
    }

    const request = requests[0];

    // Check if it's already in the queue to prevent duplicates
    db.query(
      "SELECT queue_id FROM queue WHERE request_id = ?",
      [requestId],
      (checkErr, existingQueue) => {
        if (checkErr) {
          console.error("[ERROR] Error checking existing queue:", checkErr);
          return;
        }
        if (existingQueue.length > 0) {
          console.log(
            `[INFO] Request ${requestId} already in queue. Skipping.`
          );
          return;
        }

        // Generate queue number
        getNextQueueNumber((err, queueNumber) => {
          if (err) {
            console.error("Error generating queue number:", err);
            return; // Exit early
          }

          const isPriority = false;
          const priorityType = null;

          const insertQueueQuery = `
    INSERT INTO queue (
      queue_number, user_id, user_name, student_id, course, year_level,
      request_id, services, total_amount, status, is_priority, priority_type, submitted_at, claim_details
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'waiting', ?, ?, NOW(), ?)
  `;

          db.query(
            insertQueueQuery,
            [
              queueNumber,
              request.user_id,
              request.user_name,
              request.student_id,
              request.course,
              request.year_level,
              requestId,
              request.services,
              request.total_amount,
              isPriority,
              priorityType,
              request.claim_details || null, // Use claim details from service_requests if available
            ],
            (err, result) => {
              if (err) {
                console.error("Database error during queue insertion:", err);
                return; // Exit early
              }

              const updateRequestQuery = `
  UPDATE service_requests 
  SET status = 'waiting', queue_status = 'in_queue', queue_number = ? 
  WHERE request_id = ?
`;

              db.query(updateRequestQuery, [queueNumber, requestId], (err) => {
                if (err) console.error("Error updating service request:", err);
                else
                  console.log(
                    `[SUCCESS] Request ${requestId} queued as ${queueNumber}`
                  );
              });
            }
          );
        });
      }
    );
  });
}

// EXISTING STUDENT ROUTES
app.post("/api/login", (req, res) => {
  const { emailOrPhone, password } = req.body;

  db.query(
    "SELECT * FROM users WHERE email = ? OR phone = ?",
    [emailOrPhone, emailOrPhone],
    async (err, results) => {
      if (err)
        return res
          .status(500)
          .json({ success: false, message: "Database error" });

      if (results.length === 0) {
        return res.json({ success: false, message: "Invalid credentials" });
      }

      const user = results[0];
      const isMatch = await bcrypt.compare(password, user.password);

      if (isMatch) {
        console.log("User from DB:", user);

        return res.json({
          success: true,
          message: "Login successful",
          userId: user.id,
          fullname: user.fullname,
          phone: user.phone,
          email: user.email,
        });
      } else {
        return res.json({ success: false, message: "Invalid credentials" });
      }
    }
  );
});

app.post("/api/register", async (req, res) => {
  const { lastName, firstName, middleName, gender, email, phone, password } =
    req.body;

  if (!lastName || !firstName || !gender || !email || !phone || !password) {
    return res
      .status(400)
      .json({ success: false, message: "All fields are required" });
  }

  db.query(
    "SELECT * FROM users WHERE email = ? OR phone = ?",
    [email, phone],
    async (err, results) => {
      if (err)
        return res
          .status(500)
          .json({ success: false, message: "Database error" });

      if (results.length > 0) {
        return res.json({
          success: false,
          message: "Email or phone already registered",
        });
      }

      try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const fullName = `${lastName}, ${firstName}${
          middleName ? " " + middleName : ""
        }`; // Construct full name

        // --- UPDATED INSERT QUERY ---
        db.query(
          `INSERT INTO users (last_name, first_name, middle_name, gender, fullname, email, phone, password) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            lastName,
            firstName,
            middleName || null,
            gender,
            fullName,
            email,
            phone,
            hashedPassword,
          ],
          (err, result) => {
            if (err) {
              console.error("Database error during registration:", err);
              return res
                .status(500)
                .json({ success: false, message: "Database error" });
            }

            return res.json({
              success: true,
              message: "User registered successfully",
            });
          }
        );
      } catch (hashErr) {
        return res
          .status(500)
          .json({ success: false, message: "Error securing password" });
      }
    }
  );
});

app.get("/api/user/profile", (req, res) => {
  const userId = req.query.userId;

  if (!userId) {
    return res
      .status(400)
      .json({ success: false, message: "User ID is required" });
  }

  db.query(
    // --- UPDATED SQL QUERY ---
    `SELECT *, last_name, first_name, middle_name, gender, school_id_picture,
        campus, dob, pob, nationality, home_address, previous_school,
        primary_school, secondary_school 
        FROM users WHERE id = ?`,
    // --- END UPDATE ---
    [userId],
    (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res
          .status(500)
          .json({ success: false, message: "Database error" });
      }

      if (results.length === 0) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }

      const user = results[0];
      res.json({
        success: true,
        user: {
          id: user.id,
          fullname: user.fullname,
          first_name: user.first_name,
          last_name: user.last_name,
          middle_name: user.middle_name,
          gender: user.gender,
          email: user.email,
          phone: user.phone,
          student_id: user.student_id,
          course: user.course, // This field holds the "program"
          major: user.major,
          year_level: user.year_level,
          school_year: user.school_year,
          year_graduated: user.year_graduated,
          profile_complete: user.profile_complete,
          school_id_picture: user.school_id_picture,
          // --- ADDED NEW FIELDS ---
          campus: user.campus,
          dob: user.dob,
          pob: user.pob,
          nationality: user.nationality,
          home_address: user.home_address,
          previous_school: user.previous_school,
          primary_school: user.primary_school,
          secondary_school: user.secondary_school,
          // --- END ADDED FIELDS ---
        },
      });
    }
  );
});

// This REPLACES your old /api/user/update-profile route
app.post(
  "/api/user/update-profile",
  upload.single("school_id_picture"),
  async (req, res) => {
    // req.body contains the text fields
    // req.file contains the 'school_id_picture' file
    const {
      userId,
      lastName,
      firstName,
      middleName,
      gender,
      phone,
      studentId,
      course, // This will be the "program" value from the form
      major,
      yearLevel,
      schoolYear,
      yearGraduated,
      email,
      // --- ADDED NEW FIELDS ---
      campus,
      dob,
      pob,
      nationality,
      home_address,
      previous_school,
      primary_school,
      secondary_school,
      // --- END ADDED FIELDS ---
    } = req.body;

    // ⬇️ PASTE THIS BLOCK RIGHT AFTER 'req.body' ⬇️

    // Fix: Convert string 'null' or empty strings to real NULL for the database
    const safeYearGraduated =
      yearGraduated && yearGraduated !== "null" && yearGraduated !== ""
        ? parseInt(yearGraduated)
        : null;

    // ⬆️ END OF PASTE ⬆️

    // --- Validation ---
    if (
      !userId ||
      !lastName ||
      !firstName ||
      !gender ||
      !studentId ||
      !course ||
      !yearLevel ||
      !schoolYear ||
      !email ||
      // --- ADDED VALIDATION ---
      !campus ||
      !dob ||
      !pob ||
      !nationality ||
      !home_address ||
      !primary_school ||
      !secondary_school
      // 'previous_school' is optional
      // --- END ADDED VALIDATION ---
    ) {
      return res.status(400).json({
        success: false,
        message: "All required fields must be filled",
      });
    }

    const fullName = `${lastName}, ${firstName}${
      middleName ? " " + middleName : ""
    }`;

    // --- 🟢 START OF BLOCK TO REPLACE 🟢 ---
    // REPLACE your existing 'try...catch' block with this one
    try {
      // --- 1. Check for duplicate email FIRST ---
      const [existingUser] = await db
        .promise()
        .query("SELECT id FROM users WHERE email = ? AND id != ?", [
          email,
          userId,
        ]);

      if (existingUser.length > 0) {
        return res.json({
          success: false,
          message: "This email is already in use by another account.",
        });
      }

      // --- 2. Continue with existing logic if email is OK ---
      let schoolIdPictureFilename = null;

      // 1. Check if a new file was uploaded
      let schoolIdPictureValue = null;

      if (req.file) {
        // 🟢 FIX: Save the FILENAME, not the Base64 string
        schoolIdPictureValue = req.file.filename;
      } else {
        // 2. If NO new file, keep the old one
        const [user] = await db
          .promise()
          .query("SELECT school_id_picture FROM users WHERE id = ?", [userId]);
        if (user.length > 0) {
          schoolIdPictureValue = user[0].school_id_picture;
        }
      }

      // --- UPDATED SQL QUERY (This is your existing query) ---
      await db.promise().query(
        `UPDATE users 
              SET 
                  last_name = ?, 
                  first_name = ?, 
                  middle_name = ?, 
                  gender = ?,
                  phone = ?,
                  fullname = ?,
                  student_id = ?, 
                  course = ?, 
                  major = ?, 
                  year_level = ?, 
                  school_year = ?, 
                  year_graduated = ?, 
                  email = ?,
                  school_id_picture = ?,
                  campus = ?,
                  dob = ?,
                  pob = ?,
                  nationality = ?,
                  home_address = ?,
                  previous_school = ?,
                  primary_school = ?,
                  secondary_school = ?,
                  profile_complete = 1 
              WHERE id = ?`,
        [
          lastName,
          firstName,
          middleName || null,
          gender,
          phone,
          fullName,
          studentId,
          course, // This is the "program" value
          major,
          yearLevel,
          schoolYear,
          safeYearGraduated,
          email, // The email we just validated
          schoolIdPictureValue,
          campus,
          dob,
          pob,
          nationality,
          home_address,
          previous_school || null,
          primary_school,
          secondary_school,
          userId,
        ]
      );
      // --- END UPDATE ---

      res.json({
        success: true,
        message: "Profile updated successfully",
      });
    } catch (error) {
      console.error("Database error:", error);
      // Add a specific check for duplicate entry errors
      if (error.code === "ER_DUP_ENTRY") {
        return res
          .status(400)
          .json({ success: false, message: "That email is already in use." });
      }
      return res
        .status(500)
        .json({ success: false, message: "Database error" });
    }
  }
);
app.get("/api/user/can-join-queue", (req, res) => {
  const userId = req.query.userId;

  if (!userId) {
    return res
      .status(400)
      .json({ success: false, message: "User ID is required" });
  }

  db.query(
    "SELECT profile_complete FROM users WHERE id = ?",
    [userId],
    (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res
          .status(500)
          .json({ success: false, message: "Database error" });
      }

      if (results.length === 0) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }

      res.json({
        success: true,
        canJoinQueue: results[0].profile_complete === 1,
      });
    }
  );
});

// --- 🟢 FIXED SUBMIT ROUTE 🟢 ---
app.post(
  "/api/queue/submit-request",
  requirementsUpload.array("requirements_files", 10),
  (req, res) => {
    // 1. Get Fields (Handle both 'services' and legacy 'services[]' just in case)
    const userId = req.body.userId;
    let rawServices = req.body.services || req.body["services[]"];
    let rawReqNames =
      req.body.requirement_names || req.body["requirement_names[]"];

    const files = req.files;
    // 🟢 READ THE VALUE 🟢
    // Convert string "true" to integer 1, otherwise 0
    const reqConfirmed = req.body.requirements_confirmed === "true" ? 1 : 0;

    // 2. Validation
    if (!userId || !rawServices) {
      return res.status(400).json({
        success: false,
        message: "User ID and services are required",
      });
    }

    // 3. Force Services to be an Array
    let parsedServices = [];
    if (Array.isArray(rawServices)) {
      parsedServices = rawServices;
    } else if (typeof rawServices === "string") {
      parsedServices = [rawServices];
    }

    // 4. Force Requirement Names to be an Array
    let reqNamesArray = [];
    if (Array.isArray(rawReqNames)) {
      reqNamesArray = rawReqNames;
    } else if (typeof rawReqNames === "string") {
      reqNamesArray = [rawReqNames];
    }

    // 5. Structure Files (Map files to their names)
    const structuredRequirements = files
      ? files.map((file, index) => {
          return {
            name: reqNamesArray[index] || "Requirement",
            file: file.filename, // Saves the filename
          };
        })
      : [];

    const requirementsPaths = JSON.stringify(structuredRequirements);
    const requirementsText = JSON.stringify(reqNamesArray || []);
    const requestId =
      "REQ-" + Date.now() + "-" + Math.random().toString(36).substr(2, 9);

    // 6. Get User Info
    db.query(
      `SELECT fullname, student_id, course, year_level, email, phone,
        campus, dob, pob, nationality, home_address, previous_school,
        primary_school, secondary_school, school_id_picture 
       FROM users WHERE id = ?`,
      [userId],
      (err, userResults) => {
        if (err)
          return res
            .status(500)
            .json({ success: false, message: "Database error" });
        if (userResults.length === 0)
          return res
            .status(404)
            .json({ success: false, message: "User not found" });

        const user = userResults[0];

        // 7. Insert into Database
        db.query(
          `INSERT INTO service_requests 
          (request_id, user_id, user_name, student_id, course, year_level, 
          services, total_amount, requirements, requirements_paths, status, queue_status, submitted_at, contact_email, contact_phone,
          campus, dob, pob, nationality, home_address, previous_school, 
          primary_school, secondary_school, school_id_picture) 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'waiting', 'in_queue', NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            requestId,
            userId,
            user.fullname,
            user.student_id,
            user.course,
            user.year_level,
            JSON.stringify(parsedServices), // ✅ Correctly saves as ["Service A", "Service B"]
            0,
            requirementsText,
            requirementsPaths,
            user.email,
            user.phone,
            user.campus,
            user.dob,
            user.pob,
            user.nationality,
            user.home_address,
            user.previous_school,
            user.primary_school,
            user.secondary_school,
            user.school_id_picture,
            reqConfirmed, // 🟢 Added this variable at the end
          ],
          (err, result) => {
            if (err) {
              console.error("❌ SUBMIT ERROR:", err);
              return res
                .status(500)
                .json({ success: false, message: "DB Error: " + err.message });
            }

            // 8. Add to Queue Logic (Fire and forget)
            if (typeof addToQueueSystem === "function") {
              addToQueueSystem(requestId);
            }

            res.json({
              success: true,
              requestId: requestId,
              message: "Service request submitted successfully!",
            });
          }
        );
      }
    );
  }
);

// === API: START PROCESSING REQUEST ===
app.post("/api/admin/start-processing", authenticateAdmin, (req, res) => {
  const { queueId, windowNumber } = req.body;
  const adminId = req.admin.adminId;
  const adminName = req.admin.full_name;

  if (!queueId || !windowNumber) {
    return res.status(400).json({
      success: false,
      message: "Queue ID and Window Number are required.",
    });
  }

  const updateQuery = `
UPDATE queue 
SET status = 'processing', 
started_at = NOW(),
processed_by = ?,
processed_by_id = ?,
window_number = ?
WHERE queue_id = ? AND status = 'waiting'
`;

  // index.js (Inside the db.query callback)

  db.query(
    updateQuery,
    [adminName, adminId, windowNumber, queueId],
    (err, result) => {
      if (err) {
        console.error("Database error starting processing (DETAIL):", err);
        // 🟢 Also log the query and parameters 🟢
        console.error(
          "Failing Query:",
          updateQuery.replace(/\s+/g, " ").trim()
        );
        console.error("Failing Params:", [
          adminName,
          adminId,
          windowNumber,
          queueId,
        ]);
        return res.status(500).json({
          success: false,
          message: "Database error occurred during processing update.",
        });
      }
      // ... (the rest of the code is unchanged) ...

      if (result.affectedRows === 0) {
        return res.json({
          success: false,
          message:
            "Request not found, already processing, or already completed.",
        });
      }

      res.json({
        success: true,
        message: "Request moved to processing successfully.",
      });
    }
  );
});
app.get("/api/admin/service-requests", authenticateAdmin, (req, res) => {
  // 🟢 MEMORY FIX: Exclude heavy image columns
  const query = `
    SELECT 
      request_id, user_id, user_name, student_id, course, year_level, 
      services, total_amount, status, queue_status, queue_number, 
      submitted_at, approved_by, approved_at, declined_by, declined_at, 
      contact_email, contact_phone, claim_details
    FROM service_requests 
    ORDER BY 
     CASE 
       WHEN status = 'pending' THEN 1
       WHEN status = 'approved' THEN 2
       WHEN status = 'declined' THEN 3
     END, submitted_at DESC
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res
        .status(500)
        .json({ success: false, message: "Database error" });
    }

    const requests = results.map((request) => {
      try {
        return {
          ...request,
          services: JSON.parse(request.services || "[]"),
          // Initialize empty arrays to save RAM (we fetch files only in details view)
          requirements: [],
          requirements_paths: [],
        };
      } catch (e) {
        return { ...request, services: [], requirements: [] };
      }
    });

    res.json({
      success: true,
      requests: requests,
    });
  });
});

app.post("/api/admin/add-to-queue", authenticateAdmin, (req, res) => {
  const { requestId } = req.body;

  if (!requestId) {
    return res.status(400).json({
      success: false,
      message: "Request ID is required",
    });
  }

  const requestQuery = "SELECT * FROM service_requests WHERE request_id = ?";
  db.query(requestQuery, [requestId], (err, requests) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({
        success: false,
        message: "Database error",
      });
    }

    if (requests.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Request not found",
      });
    }

    const request = requests[0];

    const checkQueueQuery = "SELECT * FROM queue WHERE request_id = ?";
    db.query(checkQueueQuery, [requestId], (err, existingQueue) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({
          success: false,
          message: "Database error",
        });
      }

      if (existingQueue.length > 0) {
        return res.json({
          success: false,
          message: "Request already in queue",
        });
      }

      const queueNumberQuery = `
        SELECT COUNT(*) as count 
        FROM queue 
        WHERE DATE(submitted_at) = CURDATE()
      `;

      db.query(queueNumberQuery, (err, countResult) => {
        if (err) {
          console.error("Database error:", err);
          return res.status(500).json({
            success: false,
            message: "Database error",
          });
        }

        const queueCount = countResult[0].count + 1;
        const isPriority = false;
        const priorityType = null;
        const queueNumber = isPriority
          ? `P-${String(queueCount).padStart(3, "0")}`
          : `A-${String(queueCount).padStart(3, "0")}`;

        const insertQueueQuery = `
          INSERT INTO queue (
            queue_number, 
            user_id, 
            user_name,
            student_id,
            course,
            year_level,
            request_id,
            services,
            total_amount,
            status,
            is_priority,
            priority_type,
            submitted_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'waiting', ?, ?, NOW())
        `;

        db.query(
          insertQueueQuery,
          [
            queueNumber,
            request.user_id,
            request.user_name,
            request.student_id,
            request.course,
            request.year_level,
            requestId,
            request.services,
            request.total_amount,
            isPriority,
            priorityType,
          ],
          (err, result) => {
            if (err) {
              console.error("Database error:", err);
              return res.status(500).json({
                success: false,
                message: "Database error",
              });
            }

            const updateRequestQuery = `
              UPDATE service_requests 
              SET queue_status = 'in_queue', 
                  queue_number = ? 
              WHERE request_id = ?
            `;

            db.query(updateRequestQuery, [queueNumber, requestId], (err) => {
              if (err) {
                console.error("Error updating service request:", err);
              }

              res.json({
                success: true,
                message: "Request added to queue successfully",
                queueNumber: queueNumber,
              });
            });
          }
        );
      });
    });
  });
});

app.get("/api/admin/queues", authenticateAdmin, (req, res) => {
  const query = `
    SELECT 
      queue_id, queue_number, user_name, student_id, course,
      year_level, services, status, is_priority, 
      submitted_at, started_at, completed_at, 
      window_number,
      completed_by,
      progress_data
    FROM queue
    WHERE 
      (DATE(submitted_at) = CURDATE()) 
      OR 
      (status IN ('waiting', 'reviewing', 'processing', 'ready', 'completed'))
      OR
      (status = 'claimed' AND DATE(completed_at) = CURDATE())
    ORDER BY 
      CASE 
        WHEN status = 'processing' THEN 1
        WHEN status = 'waiting' THEN 2
        ELSE 3
      END ASC,
      CASE 
        WHEN status = 'processing' THEN started_at 
        ELSE NULL 
      END DESC,
      is_priority DESC,
      submitted_at ASC
  `;

  db.query(query, (err, queues) => {
    if (err) {
      console.error("Database error:", err);
      return res
        .status(500)
        .json({ success: false, message: "Database error" });
    }

    const processedQueues = queues.map((queue) => {
      try {
        return {
          ...queue,
          services:
            typeof queue.services === "string"
              ? JSON.parse(queue.services)
              : queue.services,
        };
      } catch (parseErr) {
        return { ...queue, services: [] };
      }
    });

    const organizedQueues = {
      waiting: processedQueues.filter(
        (q) => q.status === "waiting" && !q.is_priority
      ),
      // Add 'reviewing' here so it gets sent to the frontend
      processing: processedQueues.filter(
        (q) => q.status === "processing" || q.status === "reviewing"
      ),
      ready: processedQueues.filter((q) => q.status === "ready"),
      completed: processedQueues.filter((q) => q.status === "completed"), // Keep this strictly 'completed' for the "Ready to Claim" list
      claimed: processedQueues.filter((q) => q.status === "claimed"), // 🟢 New category for stats
      priority: processedQueues.filter(
        (q) => q.is_priority && q.status === "waiting"
      ),
    };

    res.json({ success: true, queues: organizedQueues });
  });
});

app.post("/api/admin/notify-student", authenticateAdmin, (req, res) => {
  const { queueId } = req.body;

  if (!queueId) {
    return res.status(400).json({
      success: false,
      message: "Queue ID is required",
    });
  }

  const queueQuery = "SELECT * FROM queue WHERE queue_id = ?";
  db.query(queueQuery, [queueId], (err, queues) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({
        success: false,
        message: "Database error",
      });
    }

    if (queues.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Queue not found",
      });
    }

    const queue = queues[0];

    console.log(
      `Notifying student ${queue.user_name} for queue ${queue.queue_number}`
    );

    res.json({
      success: true,
      message: `Student ${queue.user_name} notified for queue ${queue.queue_number}`,
    });
  });
});

app.get("/api/user/service-requests", (req, res) => {
  const userId = req.query.userId;

  if (!userId) {
    return res.status(400).json({
      success: false,
      message: "User ID is required",
    });
  }

  // 🟢 FIX: Added 'COLLATE utf8mb4_general_ci' to the JOIN conditions
  const query = `
    SELECT sr.*, 
           q.progress_data, 
           q.status AS live_queue_status,
           q.window_number,
           q.completed_by,
           COALESCE(q.claim_details, sr.claim_details) as final_claim_details,
           f.id as feedback_id
    FROM service_requests sr
    LEFT JOIN queue q ON sr.request_id = q.request_id COLLATE utf8mb4_general_ci
    LEFT JOIN feedback f ON sr.request_id = f.request_id COLLATE utf8mb4_general_ci
    WHERE sr.user_id = ? 
    ORDER BY sr.submitted_at DESC
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({
        success: false,
        message: "Database error",
      });
    }

    const requests = results.map((request) => {
      try {
        let reqs = JSON.parse(request.requirements || "[]");
        let paths = JSON.parse(request.requirements_paths || "[]");

        if (typeof reqs === "string") reqs = JSON.parse(reqs);
        if (typeof paths === "string") paths = JSON.parse(paths);

        // Parse Progress
        let progress = null;
        if (request.progress_data) {
          progress =
            typeof request.progress_data === "string"
              ? JSON.parse(request.progress_data)
              : request.progress_data;
        }

        // 🟢 FIX: Use LIVE status if available, otherwise fallback 🟢
        // This ensures the frontend sees 'processing' instead of 'in_queue'
        const activeStatus = request.live_queue_status || request.queue_status;

        return {
          ...request,
          queue_status: activeStatus, // <--- Send the correct status
          services: JSON.parse(request.services || "[]"),
          requirements: reqs,
          requirements_paths: paths,
          progress: progress,
        };
      } catch (parseErr) {
        console.error("Error parsing JSON for request:", request.request_id);
        return {
          ...request,
          services: [],
          requirements: [],
          progress: null,
        };
      }
    });

    res.json({
      success: true,
      requests: requests,
    });
  });
});

app.get("/api/user/request-details", (req, res) => {
  const { requestId } = req.query;
  const userId = req.query.userId; // Added userId for security

  if (!requestId || !userId) {
    return res
      .status(400)
      .json({ success: false, message: "Request ID and User ID are required" });
  }

  db.query(
    // We also check user_id to make sure a user can only see their own request
    "SELECT services FROM service_requests WHERE request_id = ? AND user_id = ?",
    [requestId, userId],
    (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res
          .status(500)
          .json({ success: false, message: "Database error" });
      }

      if (results.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Request not found or access denied",
        });
      }

      try {
        res.json({
          success: true,
          services: JSON.parse(results[0].services || "[]"),
        });
      } catch (parseErr) {
        res.json({
          success: true,
          services: [], // Send empty on parse error
        });
      }
    }
  );
});

// --- NEW: API to check for unread notifications ---
app.get("/api/user/notifications-status", (req, res) => {
  const userId = req.query.userId;
  if (!userId) {
    return res
      .status(400)
      .json({ success: false, message: "User ID is required" });
  }

  const query = `
    SELECT 1 
    FROM service_requests 
    WHERE user_id = ? 
      AND is_viewed_by_user = 0
      AND (status IN ('approved', 'declined') OR queue_status = 'completed')
    LIMIT 1
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res
        .status(500)
        .json({ success: false, message: "Database error" });
    }

    res.json({
      success: true,
      hasUnread: results.length > 0,
    });
  });
});

// --- NEW: API to mark notifications as read ---
app.post("/api/user/mark-notifications-read", (req, res) => {
  const { userId } = req.body;
  if (!userId) {
    return res
      .status(400)
      .json({ success: false, message: "User ID is required" });
  }

  const query = `
    UPDATE service_requests 
    SET is_viewed_by_user = 1 
    WHERE user_id = ? AND is_viewed_by_user = 0
  `;

  db.query(query, [userId], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res
        .status(500)
        .json({ success: false, message: "Database error" });
    }
    res.json({ success: true, message: "Notifications marked as read" });
  });
});
// === MANUAL QUEUE ENTRY ===
app.post("/api/admin/manual-queue-entry", authenticateAdmin, (req, res) => {
  const {
    user_name,
    student_id,
    course,
    year_level,
    services,
    total_amount = 0.0,
  } = req.body;

  if (!user_name || !student_id || !course || !year_level || !services) {
    return res
      .status(400)
      .json({ success: false, message: "All fields are required." });
  }

  // Generate queue number for today
  // Generate queue number
  getNextQueueNumber((err, queueNumber) => {
    if (err) {
      console.error("Queue count error:", err);
      return res
        .status(500)
        .json({ success: false, message: "Database error" });
    }

    // Insert into queue
    const insertQuery = `
    INSERT INTO queue (
      queue_number, user_id, user_name, student_id, course, year_level,
      request_id, services, total_amount, status, is_priority, priority_type,
      submitted_at, added_by, added_by_id
    ) VALUES (?, NULL, ?, ?, ?, ?, NULL, ?, ?, 'waiting', 0, NULL, NOW(), ?, ?)
  `;

    const adminName = req.admin.full_name || "System Administrator";
    const adminId = req.admin.id;

    db.query(
      insertQuery,
      [
        queueNumber,
        user_name,
        student_id,
        course,
        year_level,
        services,
        total_amount,
        adminName,
        adminId,
      ],
      (err, result) => {
        if (err) {
          console.error("Manual queue insert error:", err);
          return res.status(500).json({ success: false, message: err.message });
        }

        res.json({
          success: true,
          message: "Manual entry added to queue",
          queueNumber: queueNumber,
          queueId: result.insertId,
        });
      }
    );
  });
});
// --- 🟢 NEW: TV DASHBOARD QUEUE STATUS API 🟢 ---
app.get("/api/queue/status", (req, res) => {
  const today = new Date().toISOString().split("T")[0]; // YYYY-MM-DD

  // 1. Get tickets:
  // - Submitted Today (Waiting)
  // - Processing (Any date, in case it carried over)
  // - Completed/Ready (Any date, UNTIL it is marked claimed)
  const query = `
    SELECT queue_number, status, window_number, submitted_at, started_at, completed_at
    FROM queue 
    WHERE 
      (DATE(submitted_at) = ? AND status = 'waiting')
      OR 
      status IN ('processing', 'completed')
    ORDER BY 
      CASE status
        WHEN 'processing' THEN 1
        WHEN 'waiting' THEN 2
        WHEN 'completed' THEN 3
      END ASC,
      started_at DESC,
      completed_at DESC
  `;

  db.query(query, [today, today], (err, results) => {
    if (err) {
      console.error("Database error (queue status):", err);
      return res
        .status(500)
        .json({ success: false, message: "Database error" });
    }

    // 2. Process Data for Frontend
    // 🟢 CHANGE: processing is now an ARRAY [], not null
    const data = {
      window1: { processing: [], completed: [] },
      window2: { processing: [], completed: [] },
      window3: { processing: [], completed: [] },
      window4: { processing: [], completed: [] },
      comingUp: [],
    };

    results.forEach((ticket) => {
      let winNum = "0";
      if (ticket.window_number) {
        const match = ticket.window_number.match(/(\d+)/);
        if (match) winNum = match[0];
      }

      const targetWindow = data[`window${winNum}`];

      // -- PROCESSING --
      if (ticket.status === "processing") {
        if (targetWindow) {
          // 🟢 PUSH to array instead of overwriting
          targetWindow.processing.push(ticket.queue_number);
        }
      }
      // -- COMPLETED --
      else if (ticket.status === "completed") {
        if (targetWindow) {
          // 🟢 REMOVED LIMIT: Send all completed tickets so frontend can batch them
          targetWindow.completed.push(ticket.queue_number);
        }
      }
      // -- WAITING --
      else if (ticket.status === "waiting") {
        if (data.comingUp.length < 5) {
          data.comingUp.push(ticket.queue_number);
        }
      }
    });

    res.json({ success: true, data });
  });
});
// 🟢 FIXED: FETCH HISTORY (Gets Major from User Profile) 🟢
// 🟢 FIXED: FETCH HISTORY (With Staff Name) 🟢
app.get("/api/admin/history", authenticateAdmin, (req, res) => {
  const query = `
    SELECT 
      q.queue_number,
      q.user_name AS client_name,
      q.student_id,
      q.course,
      q.year_level,
      sr.campus AS department,
      u.major, 
      q.services,
      q.status,
      q.completed_at,
      q.completed_by,  -- 🟢 FETCH WHO FINISHED IT
      q.processed_by   -- 🟢 FETCH WHO STARTED IT (Fallback)
    FROM queue q
    LEFT JOIN service_requests sr ON q.request_id = sr.request_id
    LEFT JOIN users u ON q.user_id = u.id 
    WHERE q.status IN ('completed', 'claimed')
    ORDER BY q.completed_at DESC
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching history:", err);
      return res.status(500).json({ success: false, message: "DB Error" });
    }

    const parseServices = (servicesData) => {
      try {
        if (typeof servicesData === "string") return JSON.parse(servicesData);
        if (Array.isArray(servicesData)) return servicesData;
        return [];
      } catch (e) {
        return [String(servicesData)];
      }
    };

    const history = results.map((row) => ({
      ...row,
      services: parseServices(row.services),
      completed_at: row.completed_at || new Date(),
    }));

    res.json({ success: true, history });
  });
});

// Helper to safely parse services
function parseServices(servicesData) {
  try {
    if (typeof servicesData === "string") return JSON.parse(servicesData);
    if (Array.isArray(servicesData)) return servicesData;
    return [];
  } catch (e) {
    return [String(servicesData)];
  }
}

// === API: MARK AS DONE (Complete) ===
app.post("/api/admin/mark-done", authenticateAdmin, (req, res) => {
  const { queueId, claimDetails } = req.body; // <--- Now accepts claimDetails
  if (!queueId) {
    return res
      .status(400)
      .json({ success: false, message: "Queue ID is required" });
  }

  const completedBy = req.admin.full_name;
  const completedById = req.admin.adminId;

  // 1. Update Queue Table
  const updateQueueQuery = `
    UPDATE queue
    SET status = 'completed', 
        completed_at = NOW(), 
        completed_by = ?, 
        completed_by_id = ?,
        claim_details = ? 
    WHERE queue_id = ?
  `;

  db.query(
    updateQueueQuery,
    [completedBy, completedById, claimDetails || null, queueId],
    (err, result) => {
      if (err) {
        console.error("Database error marking done:", err);
        return res
          .status(500)
          .json({ success: false, message: "Database error" });
      }

      if (result.affectedRows === 0) {
        return res
          .status(404)
          .json({ success: false, message: "Queue not found." });
      }

      // 2. Sync to Service Requests Table (So record stays even if queue is cleared)
      // We also need to get the request_id first to update the correct row
      db.query(
        "SELECT request_id FROM queue WHERE queue_id = ?",
        [queueId],
        (qErr, qRows) => {
          if (!qErr && qRows.length > 0) {
            const reqId = qRows[0].request_id;
            const updateReqQuery = `
                UPDATE service_requests 
                SET queue_status = 'completed', 
                    claim_details = ? 
                WHERE request_id = ?
            `;
            db.query(updateReqQuery, [claimDetails || null, reqId]);
          }
        }
      );

      res.json({ success: true, message: "Request marked as completed." });
    }
  );
});

// === API: MARK AS CLAIMED (Removes from TV) ===
app.post("/api/admin/mark-claimed", authenticateAdmin, (req, res) => {
  const { queueId } = req.body;

  if (!queueId) {
    return res
      .status(400)
      .json({ success: false, message: "Queue ID is required" });
  }

  // Update status to 'claimed' (This status is NOT selected by the TV API)
  const updateQuery = "UPDATE queue SET status = 'claimed' WHERE queue_id = ?";

  db.query(updateQuery, [queueId], (err, result) => {
    if (err) {
      console.error("Database error marking claimed:", err);
      return res
        .status(500)
        .json({ success: false, message: "Database error" });
    }

    // Also update the service_request status to keep them synced
    db.query(
      "UPDATE service_requests SET queue_status = 'claimed' WHERE queue_number = (SELECT queue_number FROM queue WHERE queue_id = ?)",
      [queueId]
    );

    res.json({
      success: true,
      message: "Request marked as claimed (removed from screen).",
    });
  });
});
// === API: FORGOT PASSWORD ===
app.post("/api/forgot-password", (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, message: "Email required" });
  }

  // 1. Find the user by their email
  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ message: "Database error" });
      }

      // 2. IMPORTANT: Always send a success message.
      // This prevents "email enumeration" attacks, where hackers
      // can guess which emails are registered in your system.
      if (results.length === 0) {
        console.log(`Password reset attempt for non-existent email: ${email}`);
        return res.json({
          success: true,
          message: "If an account exists, a reset link has been sent.",
        });
      }

      const user = results[0];

      // 3. Create a short-lived (15 min) JWT for password reset
      const resetToken = jwt.sign(
        { userId: user.id, email: user.email },
        JWT_RESET_SECRET, // Use the *reset* secret
        { expiresIn: "15m" } // Token is only valid for 15 minutes
      );
      // 4. Create the reset link
      // Make sure you use process.env.SITE_URL here
      const siteUrl = process.env.SITE_URL || "http://localhost:3000";
      const resetLink = `${siteUrl}/reset-password?token=${resetToken}`;

      // 5. Send the email
      try {
        await transporter.sendMail({
          from: `"RSU REQS" <${process.env.EMAIL_USER}>`, // Sender address
          to: user.email, // List of receivers
          subject: "Password Reset Request for RSU REQS", // Subject line
          html: `
            <p>Hello ${user.first_name},</p>
            <p>You requested a password reset for your RSU REQS account.</p>
            <p>Please click the link below to set a new password. This link is valid for 15 minutes.</p>
            <a href="${resetLink}" style="background-color: #0d6efd; color: white; padding: 10px 15px; text-decoration: none; border-radius: 5px;">Reset Your Password</a>
            <br>
            <p>If you did not request this, please ignore this email.</p>
          `,
        });

        res.json({
          success: true,
          message: "If an account exists, a reset link has been sent.",
        });
      } catch (emailErr) {
        console.error("Error sending password reset email:", emailErr);
        res
          .status(500)
          .json({ success: false, message: "Error sending email." });
      }
    }
  );
});

// === API: RESET PASSWORD ===
app.post("/api/reset-password", async (req, res) => {
  const { token, password } = req.body;

  if (!token || !password) {
    return res
      .status(400)
      .json({ success: false, message: "Token and password are required." });
  }

  // 1. Verify the reset token
  try {
    const decoded = jwt.verify(token, JWT_RESET_SECRET);
    const userId = decoded.userId;

    // 2. Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 3. Update the user's password in the database
    db.query(
      "UPDATE users SET password = ? WHERE id = ?",
      [hashedPassword, userId],
      (err, result) => {
        if (err) {
          console.error("Database error:", err);
          return res
            .status(500)
            .json({ success: false, message: "Database error." });
        }
        res.json({ success: true, message: "Password reset successfully." });
      }
    );
  } catch (error) {
    // This will catch expired or invalid tokens
    console.error("Invalid or expired token:", error.message);
    return res
      .status(401)
      .json({ success: false, message: "Invalid or expired reset link." });
  }
});
// --- 🟢 END OF NEW BLOCK 🟢 ---

// === API: GET ALL STAFF (Super Admin Only) ===
app.get("/api/admin/all-staff", authenticateAdmin, (req, res) => {
  if (req.admin.role !== "super_admin") {
    return res.status(403).json({ success: false, message: "Access denied." });
  }

  // Fetch all staff except the one requesting (optional, or fetch all)
  db.query(
    "SELECT id, full_name, email, phone, department, role, is_active, assigned_window, last_login FROM admin_staff ORDER BY created_at DESC",
    (err, results) => {
      if (err) {
        console.error("Error fetching staff:", err);
        return res
          .status(500)
          .json({ success: false, message: "Database error" });
      }
      res.json({ success: true, staff: results });
    }
  );
});

// === API: UPDATE STAFF ACCOUNT (Super Admin Only) ===
app.post(
  "/api/admin/update-staff-account",
  authenticateAdmin,
  async (req, res) => {
    if (req.admin.role !== "super_admin") {
      return res
        .status(403)
        .json({ success: false, message: "Access denied." });
    }

    const { id, full_name, email, phone, department, role, password } =
      req.body;

    try {
      let query =
        "UPDATE admin_staff SET full_name=?, email=?, phone=?, department=?, role=? WHERE id=?";
      let params = [full_name, email, phone, department, role, id];

      // If password is provided, hash it and update
      if (password && password.trim() !== "") {
        const hashedPassword = await bcrypt.hash(password, 10);
        query =
          "UPDATE admin_staff SET full_name=?, email=?, phone=?, department=?, role=?, password=? WHERE id=?";
        params = [
          full_name,
          email,
          phone,
          department,
          role,
          hashedPassword,
          id,
        ];
      }

      db.query(query, params, (err, result) => {
        if (err) {
          console.error("Error updating staff:", err);
          return res
            .status(500)
            .json({ success: false, message: "Database error" });
        }
        res.json({
          success: true,
          message: "Staff account updated successfully.",
        });
      });
    } catch (error) {
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);
// === API: DELETE STAFF ACCOUNT (Super Admin Only) ===
app.delete("/api/admin/delete-staff/:id", authenticateAdmin, (req, res) => {
  // 1. Security Check
  if (req.admin.role !== "super_admin") {
    return res.status(403).json({ success: false, message: "Access denied." });
  }

  const staffId = parseInt(req.params.id);

  // 2. Prevent Self-Deletion (Important!)
  if (staffId === req.admin.adminId) {
    return res
      .status(400)
      .json({ success: false, message: "You cannot delete your own account." });
  }

  // 3. Delete from Database
  const query = "DELETE FROM admin_staff WHERE id = ?";

  db.query(query, [staffId], (err, result) => {
    if (err) {
      // Handle Foreign Key constraints (if staff has records in other tables)
      if (err.code === "ER_ROW_IS_REFERENCED_2") {
        return res.status(400).json({
          success: false,
          message:
            "Cannot delete: This staff member has associated records (requests/queues). Consider deactivating them instead.",
        });
      }
      console.error("Error deleting staff:", err);
      return res
        .status(500)
        .json({ success: false, message: "Database error" });
    }

    if (result.affectedRows === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Staff member not found." });
    }

    res.json({ success: true, message: "Staff account deleted successfully." });
  });
});

// --- 🟢 NEW: Beacon Unlock Route (For Tab Closing) 🟢 ---
// This route accepts the token in the body because sendBeacon cannot send Auth headers.
app.post("/api/admin/beacon-unlock", (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res
      .status(400)
      .json({ success: false, message: "No token provided" });
  }

  try {
    // Manually verify token since we skipped the middleware
    const decoded = jwt.verify(token, JWT_SECRET);
    const adminId = decoded.adminId;

    const unassignQuery =
      "UPDATE admin_staff SET assigned_window = NULL WHERE id = ?";

    db.query(unassignQuery, [adminId], (err) => {
      if (err) {
        console.error("Beacon unlock DB error:", err);
      } else {
        console.log(`[Beacon] Window unlocked for Admin ID ${adminId}`);
      }
    });
  } catch (error) {
    console.error("Beacon token verification failed:", error.message);
  }

  // Beacon requests don't wait for responses, but we send one anyway
  res.status(200).send("OK");
});

// === API: UPDATE QUEUE PROGRESS ===
app.post("/api/admin/update-progress", authenticateAdmin, (req, res) => {
  const { queueId, progressData } = req.body;

  if (!queueId || !progressData) {
    return res.status(400).json({ success: false, message: "Missing data" });
  }

  // progressData should be a JSON object like { current: 2, total: 5, checked: [...] }
  const updateQuery = "UPDATE queue SET progress_data = ? WHERE queue_id = ?";

  db.query(
    updateQuery,
    [JSON.stringify(progressData), queueId],
    (err, result) => {
      if (err) {
        console.error("Error updating progress:", err);
        return res
          .status(500)
          .json({ success: false, message: "Database error" });
      }
      res.json({ success: true, message: "Progress updated successfully" });
    }
  );
});

// === API: SUBMIT FEEDBACK ===
app.post("/api/user/submit-feedback", (req, res) => {
  const { requestId, userId, sqd0, sqdData, ccData, comments } = req.body;

  if (!requestId || !userId || !sqd0) {
    return res
      .status(400)
      .json({ success: false, message: "Missing required fields" });
  }

  const query = `
    INSERT INTO feedback (request_id, user_id, sqd0_satisfaction, sqd_responses, cc_responses, comments)
    VALUES (?, ?, ?, ?, ?, ?)
  `;

  db.query(
    query,
    [
      requestId,
      userId,
      sqd0,
      JSON.stringify(sqdData),
      JSON.stringify(ccData),
      comments,
    ],
    (err, result) => {
      if (err) {
        console.error("Feedback submit error:", err);
        return res
          .status(500)
          .json({ success: false, message: "Database error" });
      }
      res.json({ success: true, message: "Feedback submitted successfully" });
    }
  );
});

// === API: GET SATISFACTION STATS (For Admin Graph) ===
app.get("/api/admin/satisfaction-stats", authenticateAdmin, (req, res) => {
  // Get count of each rating (1-5) for SQD0
  const query = `
    SELECT sqd0_satisfaction as rating, COUNT(*) as count 
    FROM feedback 
    GROUP BY sqd0_satisfaction
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Stats error:", err);
      return res.status(500).json({ success: false, message: "DB Error" });
    }
    res.json({ success: true, stats: results });
  });
});
// 🟢 NEW: INSTANT FETCH FOR REVIEW MODAL 🟢
app.get(
  "/api/admin/request-details-by-queue/:queueId",
  authenticateAdmin,
  (req, res) => {
    const queueId = req.params.queueId;

    // 1. Get the Link (Request ID) from the Ticket
    db.query(
      "SELECT request_id, queue_number, user_name FROM queue WHERE queue_id = ?",
      [queueId],
      (err, qRows) => {
        if (err)
          return res.status(500).json({ success: false, message: "DB Error" });
        if (qRows.length === 0)
          return res.json({ success: false, message: "Ticket not found." });

        const ticket = qRows[0];

        // 2. Fetch the Full Details (Files, etc) from Service Requests
        db.query(
          "SELECT * FROM service_requests WHERE request_id = ?",
          [ticket.request_id],
          (err, rRows) => {
            if (err)
              return res
                .status(500)
                .json({ success: false, message: "DB Error" });

            // If data is missing, send basic info so the modal doesn't crash
            const requestData = rRows.length > 0 ? rRows[0] : {};

            // Safe File Parsing
            let files = [];
            try {
              const rawPaths = requestData.requirements_paths;
              if (typeof rawPaths === "string") files = JSON.parse(rawPaths);
              else if (Array.isArray(rawPaths)) files = rawPaths;
            } catch (e) {
              files = [];
            }

            // Send Combined Data
            res.json({
              success: true,
              data: {
                ...requestData,
                user_name: ticket.user_name, // Ensure we have a name
                queue_number: ticket.queue_number,
                requirements_paths: files, // Send parsed files
              },
            });
          }
        );
      }
    );
  }
);
// === API: LOCK REQUEST (Review Mode - Solves the Conflict) ===
app.post("/api/admin/lock-request", authenticateAdmin, (req, res) => {
  const { queueId, windowNumber } = req.body;
  const adminId = req.admin.adminId;
  const adminName = req.admin.full_name;

  // 1. Try to update ONLY if status is still 'waiting'
  // This prevents two people from grabbing it at the same time.
  const query = `
    UPDATE queue 
    SET status = 'reviewing', 
        window_number = ?, 
        processed_by = ?, 
        processed_by_id = ? 
    WHERE queue_id = ? AND status = 'waiting'
  `;

  db.query(
    query,
    [windowNumber, adminName, adminId, queueId],
    (err, result) => {
      if (err) {
        console.error("Database error locking request:", err);
        return res.status(500).json({ success: false, message: "DB Error" });
      }

      // 2. Check if we actually locked it
      if (result.affectedRows === 0) {
        return res.json({
          success: false,
          message: "This request is already being reviewed by another window.",
        });
      }

      // 3. Sync service_requests table for Client View
      // We need the request_id first
      db.query(
        "SELECT request_id FROM queue WHERE queue_id = ?",
        [queueId],
        (err, rows) => {
          if (rows.length > 0) {
            db.query(
              "UPDATE service_requests SET status = 'reviewing', queue_status = 'reviewing' WHERE request_id = ?",
              [rows[0].request_id]
            );
          }
        }
      );

      res.json({ success: true, message: "Locked for review" });
    }
  );
});

// 🟢 STEP 1 FIX: CRASH-PROOF REVIEW DECISION
app.post("/api/admin/review-decision", authenticateAdmin, (req, res) => {
  const { queueId, action, reason } = req.body;

  // 🛡️ SAFETY: Use NULL if ID is missing. Database allows NULL, but hates 0.
  const adminObj = req.user || req.admin || {};
  const adminName =
    adminObj.full_name || adminObj.fullname || "Registrar Staff";
  const adminId = adminObj.id || null; // <--- This prevents the "Foreign Key" crash

  // 1. Get Request ID
  db.query(
    "SELECT request_id FROM queue WHERE queue_id = ?",
    [queueId],
    (err, rows) => {
      if (err || rows.length === 0)
        return res
          .status(500)
          .json({ success: false, message: "Request not found." });

      const requestId = rows[0].request_id;

      if (action === "decline") {
        // 2. DECLINE: Save Status + Staff Name + Reason
        const updateQueue =
          "UPDATE queue SET status = 'cancelled', processed_by = ?, processed_by_id = ?, completed_at = NOW() WHERE queue_id = ?";

        // We use 'declined' here to match your student dashboard logic
        const updateRequest =
          "UPDATE service_requests SET status = 'declined', queue_status = 'declined', decline_reason = ? WHERE request_id = ?";

        db.query(updateQueue, [adminName, adminId, queueId], (err) => {
          if (err) {
            console.error("Queue Error:", err);
            return res
              .status(500)
              .json({ success: false, message: "DB Error" });
          }

          // Sync Student Data
          db.query(updateRequest, [reason, requestId], (err) => {
            if (err) console.error("Sync Error:", err);
          });

          res.json({ success: true, message: "Request declined." });
        });
      } else if (action === "process") {
        // 3. ACCEPT Logic
        const updateQueue =
          "UPDATE queue SET status = 'processing', processed_by = ?, processed_by_id = ?, started_at = NOW() WHERE queue_id = ?";
        const updateRequest =
          "UPDATE service_requests SET status = 'processing', queue_status = 'processing' WHERE request_id = ?";

        db.query(updateQueue, [adminName, adminId, queueId], (err) => {
          if (err)
            return res
              .status(500)
              .json({ success: false, message: "DB Error" });
          db.query(updateRequest, [requestId]);
          res.json({ success: true, message: "Request accepted." });
        });
      }
    }
  );
});
// // 🟢 NEW: LOCK REQUEST (Sets status to 'reviewing' so student sees it)
// app.post("/api/admin/lock-request", authenticateAdmin, (req, res) => {
//   const { queueId } = req.body;
//   const adminName = req.user.fullname; // Assuming token has fullname
//   const adminId = req.user.id;

//   // 1. Get the Request ID first
//   db.query(
//     "SELECT request_id FROM queue WHERE queue_id = ?",
//     [queueId],
//     (err, rows) => {
//       if (err || rows.length === 0) {
//         return res
//           .status(500)
//           .json({ success: false, message: "Queue item not found." });
//       }
//       const requestId = rows[0].request_id;

//       // 2. Update Queue Status
//       const updateQueue =
//         "UPDATE queue SET status = 'reviewing', processed_by = ?, processed_by_id = ? WHERE queue_id = ? AND status = 'waiting'";

//       db.query(updateQueue, [adminName, adminId, queueId], (err, result) => {
//         if (err)
//           return res.status(500).json({ success: false, message: "DB Error" });

//         if (result.affectedRows > 0) {
//           // 3. Update Service Request Status (Sync for Student Dashboard)
//           const updateRequest =
//             "UPDATE service_requests SET status = 'reviewing', queue_status = 'reviewing' WHERE request_id = ?";
//           db.query(updateRequest, [requestId]);

//           res.json({ success: true, message: "Request locked for review." });
//         } else {
//           // If rows affected is 0, someone else might have clicked it
//           res.json({
//             success: false,
//             message: "Request is already being reviewed or processed.",
//           });
//         }
//       });
//     }
//   );
// });
// 🟢 GET ALL REQUESTS FOR A STUDENT (Main Dashboard Table)
app.get("/api/student/requests", authenticateToken, (req, res) => {
  const userId = req.user.id;

  const query = `
        SELECT * FROM service_requests 
        WHERE user_id = ? 
        ORDER BY submitted_at DESC
    `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Error fetching student requests:", err);
      return res.status(500).json({ success: false, message: "DB Error" });
    }
    res.json({ success: true, requests: results });
  });
});
// 🟢 STEP 2 FIX: FETCH UPDATES WITH STAFF & WINDOW INFO
app.get("/api/student/updates", authenticateToken, (req, res) => {
  const userId = req.user.id;

  // We LEFT JOIN 'queue' to get processed_by (Staff Name) and window_number
  const query = `
        SELECT 
            sr.request_id, 
            sr.status, 
            sr.decline_reason, 
            sr.submitted_at,
            q.processed_by, 
            q.window_number
        FROM service_requests sr
        LEFT JOIN queue q ON sr.request_id = q.request_id
        WHERE sr.user_id = ? 
        ORDER BY sr.submitted_at DESC 
        LIMIT 5
    `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Error fetching updates:", err);
      return res.status(500).json({ success: false });
    }
    res.json({ success: true, updates: results });
  });
});

// --- 🟢 RENDER SERVER START 🟢 ---
// Use PORT from environment (Render assigns this automatically)
const PORT = process.env.PORT || 3000;

// Listen on 0.0.0.0 (Required for Render to route traffic)
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

// REQUIRED: Export the 'app' so Vercel can run it
export default app;

// Export 'db' as a named export (in case other files need it)
export { db };
