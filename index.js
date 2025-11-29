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

// --- ⬇️ PASTE THE NEW CODE BLOCK HERE ⬇️ ---
// Configure Multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/"); // Files will be saved in the 'uploads/' directory
  },
  filename: function (req, file, cb) {
    // Create a unique filename to prevent conflicts
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const extension = path.extname(file.originalname);
    cb(null, file.fieldname + "-" + uniqueSuffix + extension);
  },
});

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
  storage: storage, // We re-use the same storage destination
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit for documents
  },
  fileFilter: documentFileFilter,
});
// --- END OF NEW BLOCK ---

// JWT Secret for Admin/User Login
const JWT_SECRET = process.env.JWT_SECRET || "rsu-reqs-admin-secret-key-2024";

// NEW: JWT Secret for Password Resets (use a different secret!)
const JWT_RESET_SECRET =
  process.env.JWT_RESET_SECRET || "rsu-reqs-reset-secret-key-9a8b7c6d";

// NEW: Nodemailer "Transporter"
// This configures how you send emails.
// We use environment variables for security (see final step)
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || "smtp.gmail.com", // Example: smtp.gmail.com
  port: parseInt(process.env.EMAIL_PORT || "587"), // 587 for TLS, 465 for SSL
  secure: process.env.EMAIL_PORT === "465", // true for 465, false for other ports
  auth: {
    user: process.env.EMAIL_USER, // Your email address
    pass: process.env.EMAIL_PASS, // Your email password or App Password
  },
});

// MySQL connection
// const db = mysql.createConnection({
//   host: process.env.DB_HOST || "localhost",
//   user: process.env.DB_USER || "root",
//   password: process.env.DB_PASSWORD || "",
//   database: process.env.DB_NAME || "rsu_reqs_db",
//   port: process.env.DB_PORT || 3306,
// });
// MySQL connection - CORRECTED FOR TIDB CLOUD
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  ssl: {
    rejectUnauthorized: false, // <--- THIS IS THE MAGIC LINE
  },
});

db.connect((err) => {
  // ... existing code ...
  createServiceRequestsTable();
  addColumnIfNotExists("service_requests", "claim_details", "TEXT");
  addColumnIfNotExists("queue", "claim_details", "TEXT");

  // 🟢 CRITICAL: This column saves which ticket goes to which window.
  addColumnIfNotExists("queue", "window_number", "VARCHAR(50)");

  // 🟢 CRITICAL: This column saves which window the staff is assigned to.
  addColumnIfNotExists("admin_staff", "assigned_window", "VARCHAR(50)");
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
        SET status = 'approved', queue_status = 'in_queue', queue_number = ? 
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
      if (req.file) {
        schoolIdPictureFilename = req.file.filename;
      } else {
        // 2. If NO new file, keep the old one
        const [user] = await db
          .promise()
          .query("SELECT school_id_picture FROM users WHERE id = ?", [userId]);
        if (user.length > 0) {
          schoolIdPictureFilename = user[0].school_id_picture;
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
          yearGraduated || null,
          email, // The email we just validated
          schoolIdPictureFilename,
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

// --- REPLACED API ROUTE to handle file uploads ---
app.post(
  "/api/queue/submit-request",
  requirementsUpload.array("requirements_files", 10), // "requirements_files" is the key from FormData, 10 files max
  (req, res) => {
    // Text fields are in req.body, files are in req.files
    const { userId, services } = req.body;
    const files = req.files;

    if (!userId || !services || !Array.isArray(services)) {
      // If validation fails, delete any files that were uploaded
      if (files) {
        files.forEach((file) =>
          fs.unlink(
            file.path,
            (err) => err && console.error("Error cleaning up file:", err)
          )
        );
      }
      return res.status(400).json({
        success: false,
        message: "User ID and services are required",
      });
    }

    // Create an array of file paths (just the filename)
    // Get the requirement names sent from the form
    const { requirement_names } = req.body;

    // Create a structured array: [ {name: "Clearance", file: "file-123.jpg"}, ... ]
    const structuredRequirements = files
      ? files.map((file, index) => {
          return {
            name: requirement_names[index], // The name from the form
            file: file.filename, // The saved filename
          };
        })
      : [];

    // Save this new structure in requirements_paths
    const requirementsPaths = JSON.stringify(structuredRequirements);

    // Save just the names in the old 'requirements' column for compatibility

    const requestId =
      "REQ-" + Date.now() + "-" + Math.random().toString(36).substr(2, 9);

    db.query(
      `SELECT fullname, student_id, course, year_level, email, phone,
        campus, dob, pob, nationality, home_address, previous_school,
        primary_school, secondary_school, school_id_picture 
  FROM users WHERE id = ?`,
      [userId],
      (err, userResults) => {
        if (err) {
          console.error("Database error:", err);
          return res
            .status(500)
            .json({ success: false, message: "Database error" });
        }

        if (userResults.length === 0) {
          return res
            .status(404)
            .json({ success: false, message: "User not found" });
        }

        const user = userResults[0];

        // Note: The 'requirements' column now stores the *names* of the requirements
        // The new 'requirements_paths' column stores the *filenames*

        // --- THIS LINE WAS THE BUG, IT'S NOW FIXED ---
        // --- THIS LINE WAS THE BUG, IT'S NOW FIXED ---
        const requirementsText = JSON.stringify(requirement_names || []);
        // --- END OF FIX ---

        // 1. Insert into service_requests with status 'approved' and queue_status 'in_queue'
        db.query(
          `INSERT INTO service_requests 
  (request_id, user_id, user_name, student_id, course, year_level, 
  services, total_amount, requirements, requirements_paths, status, queue_status, submitted_at, contact_email, contact_phone,
  campus, dob, pob, nationality, home_address, previous_school, 
  primary_school, secondary_school, school_id_picture) 
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved', 'in_queue', NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            requestId,
            userId,
            user.fullname,
            user.student_id,
            user.course,
            user.year_level,
            JSON.stringify(services), // ["Transcript of Records"]
            0, // Total amount is 0 for now as per your original code
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
          ],
          (err, result) => {
            if (err) {
              console.error("Database error:", err);
              return res
                .status(500)
                .json({ success: false, message: "Database error" });
            }

            // 2. Immediately add to the queue system
            addToQueueSystem(requestId, true); // Pass true to skip unnecessary checks

            res.json({
              success: true,
              requestId: requestId,
              // Message now reflects the new streamlined flow
              message: "Service request submitted and added to the queue!",
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
// === END API: START PROCESSING REQUEST ===
// --- END OF REPLACED ROUTE ---
app.get("/api/admin/service-requests", authenticateAdmin, (req, res) => {
  db.query(
    `SELECT * FROM service_requests ORDER BY 
     CASE 
       WHEN status = 'pending' THEN 1
       WHEN status = 'approved' THEN 2
       WHEN status = 'declined' THEN 3
     END, submitted_at DESC`,
    (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res
          .status(500)
          .json({ success: false, message: "Database error" });
      }

      const requests = results.map((request) => {
        try {
          let reqs = JSON.parse(request.requirements || "[]");
          let paths = JSON.parse(request.requirements_paths || "[]");

          // Fix for old, double-stringified data
          if (typeof reqs === "string") reqs = JSON.parse(reqs);
          if (typeof paths === "string") paths = JSON.parse(paths);

          return {
            ...request,
            services: JSON.parse(request.services || "[]"),
            requirements: reqs,
            requirements_paths: paths,
          };
        } catch (e) {
          console.error(
            "Failed to parse JSON for request:",
            request.request_id,
            e
          );
          return {
            ...request, // Return partial data
            services: [],
            requirements: [],
            requirements_paths: [],
          };
        }
      });

      res.json({
        success: true,
        requests: requests,
      });
    }
  );
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
      window_number, -- CRITICAL: We need this to count completed per window
      completed_by
    FROM queue
    WHERE 
      (DATE(submitted_at) = CURDATE()) 
      OR 
      (status IN ('waiting', 'processing', 'ready')) 
      OR
      (DATE(completed_at) = CURDATE() AND status = 'completed') -- Ensure we get today's completed
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
      processing: processedQueues.filter((q) => q.status === "processing"),
      ready: processedQueues.filter((q) => q.status === "ready"),
      completed: processedQueues.filter((q) => q.status === "completed"),
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

  db.query(
    "SELECT * FROM service_requests WHERE user_id = ? ORDER BY submitted_at DESC",
    [userId],
    (err, results) => {
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

          // Fix for old, double-stringified data
          if (typeof reqs === "string") reqs = JSON.parse(reqs);
          if (typeof paths === "string") paths = JSON.parse(paths);

          return {
            ...request,
            services: JSON.parse(request.services || "[]"),
            requirements: reqs,
            requirements_paths: paths,
          };
        } catch (parseErr) {
          console.error("Error parsing JSON for request:", request.request_id);
          return {
            ...request,
            services: [],
            requirements: [],
          };
        }
      });

      res.json({
        success: true,
        requests: requests,
      });
    }
  );
});

// Add this with your other user API routes (e.g., after /api/user/service-requests)

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
// === END MANUAL QUEUE ENTRY ===
// New public API endpoint for queue status (no authentication needed) - FIXED DAILY RESET
app.get("/api/queue/status", (req, res) => {
  const today = new Date().toISOString().split("T")[0]; // YYYY-MM-DD

  // --- 🟢 FIX: Sort by Priority, then Time 🟢 ---
  const nowServingQuery = `
    SELECT queue_number 
    FROM queue 
    WHERE status = 'processing' 
      AND DATE(submitted_at) = ?
    ORDER BY is_priority DESC, started_at ASC 
    LIMIT 1
  `;

  db.query(nowServingQuery, [today], (err, nowServingResult) => {
    if (err) {
      console.error("Database error (nowServing):", err);
      return res
        .status(500)
        .json({ success: false, message: "Database error" });
    }
    const nowServing =
      nowServingResult.length > 0 ? nowServingResult[0].queue_number : "None";

    // --- 🟢 FIX: Sort by Priority, then Time 🟢 ---
    const comingNextQuery = `
      SELECT queue_number 
      FROM queue 
      WHERE status = 'processing' 
        AND DATE(submitted_at) = ?
      ORDER BY is_priority DESC, started_at ASC 
      LIMIT 3 OFFSET 1
    `;
    db.query(comingNextQuery, [today], (err, comingNextResult) => {
      if (err) {
        console.error("Database error (comingNext):", err);
        return res
          .status(500)
          .json({ success: false, message: "Database error" });
      }
      const comingNext = comingNextResult.map((row) => row.queue_number);

      // READY TO CLAIM: Only today's completed
      const readyToClaimQuery = `
        SELECT queue_number 
        FROM queue 
        WHERE status = 'completed' 
          AND DATE(completed_at) = ?
        ORDER BY completed_at DESC
      `;

      db.query(readyToClaimQuery, [today], (err, readyToClaimResult) => {
        if (err) {
          console.error("Database error (readyToClaim):", err);
          return res
            .status(500)
            .json({ success: false, message: "Database error" });
        }
        const readyToClaim = readyToClaimResult.map((row) => row.queue_number);

        res.json({
          success: true,
          nowServing,
          comingNext,
          readyToClaim,
        });
      });
    });
  });
});

// Add/Complete protected admin route for marking done (sets to 'ready')
// app.post("/api/admin/mark-done", authenticateAdmin, (req, res) => {
//   const { queueId } = req.body;
//   if (!queueId) {
//     return res
//       .status(400)
//       .json({ success: false, message: "Queue ID is required" });
//   }

//   const completedBy = req.admin.full_name;
//   const completedById = req.admin.adminId;

//   const updateQuery = `
//     UPDATE queue
//     SET status = 'ready', completed_at = NOW(), completed_by = ?, completed_by_id = ?
//     WHERE queue_id = ? AND status = 'processing'
//   `;

//   db.query(
//     updateQuery,
//     [completedBy, completedById, queueId],
//     (err, result) => {
//       if (err) {
//         console.error("Database error:", err);
//         return res
//           .status(500)
//           .json({ success: false, message: "Database error" });
//       }

//       if (result.affectedRows === 0) {
//         return res.status(404).json({
//           success: false,
//           message: "Queue not found or not in processing",
//         });
//       }

//       res.json({ success: true, message: "Request marked as ready to claim" });
//     }
//   );
// });
// --- 🟢 PASTE this entire block before your app.listen() call 🟢 ---

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
      const resetLink = `${process.env.SITE_URL}/reset-password?token=${resetToken}`;

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
// --- 🟢 END NEW ROUTE 🟢 ---

// Start server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📊 Admin dashboard: http://localhost:${PORT}/admin`);
  console.log(`🔑 Admin login: http://localhost:${PORT}/adminLogin`);
  console.log(`👤 Default admin: admin@rsu.edu.ph / admin123`);
});

// export default db;
// --- 🟢 VERCEL FIX STARTS HERE 🟢 ---

// Only listen to port 3000 if we are running LOCALLY (not on Vercel)
// if (process.env.NODE_ENV !== "production") {
//   const PORT = process.env.PORT || 3000;
//   app.listen(PORT, () => {
//     console.log(`🚀 Server running on http://localhost:${PORT}`);
//     console.log(`📊 Admin dashboard: http://localhost:${PORT}/admin`);
//   });
// }
// if (process.env.NODE_ENV !== "production") {
//   const PORT = process.env.PORT || 3000;
//   app.listen(PORT, () => {
//     console.log(`🚀 Server running on http://localhost:${PORT}`);
//   });
// }

// REQUIRED: Export the 'app' so Vercel can run it
export default app;

// Export 'db' as a named export (in case other files need it)
export { db };

// --- 🟢 VERCEL FIX ENDS HERE 🟢 ---
