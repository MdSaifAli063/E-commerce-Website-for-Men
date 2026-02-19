require("dotenv").config();
const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const session = require("express-session");
const nodemailer = require("nodemailer");
const { User, mongoose } = require("./config");

const app = express();

// Config
const PORT = process.env.PORT || 3210;
const HOST = process.env.HOST || "127.0.0.1";
const MONGO_URI = process.env.MONGO_URI || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret-change-me";

// SMTP config (set these in your environment for real email delivery)
const SMTP_HOST = process.env.SMTP_HOST || "";
const SMTP_PORT = parseInt(process.env.SMTP_PORT || "587", 10);
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = process.env.SMTP_PASS || "";
const SMTP_FROM =
  process.env.SMTP_FROM || process.env.SMTP_USER || "no-reply@example.com";

// Mailer transport
let mailerTransport;
if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
  mailerTransport = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
  // Optional: verify connection on startup
  mailerTransport.verify().then(
    () => console.log("SMTP: transporter verified"),
    (err) => console.warn("SMTP: verification failed:", err.message),
  );
} else {
  console.warn(
    "SMTP not fully configured; using JSON transport (emails will be logged, not sent).",
  );
  mailerTransport = nodemailer.createTransport({ jsonTransport: true });
}

/**
 * Helper: send password reset email
 */
async function sendPasswordResetEmail({ to, name, link, ip }) {
  const safeName = name || "there";
  const subject = "Reset your password";
  const text =
    `Hello ${safeName},\n\n` +
    `We received a request to reset your password. Click the link below to set a new password:\n\n` +
    `${link}\n\n` +
    `This link will expire in 1 hour. If you didn't request this, you can ignore this email.\n\n` +
    `Request IP: ${ip || "unknown"}\n` +
    `Thanks,\nSupport Team`;
  const html =
    `<div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#0f172a;line-height:1.6">` +
    `<h2 style="margin:0 0 12px">Reset your password</h2>` +
    `<p>Hello ${safeName},</p>` +
    `<p>We received a request to reset your password. Click the button below to set a new password.</p>` +
    `<p style="margin:20px 0"><a href="${link}" style="display:inline-block;background:#111827;color:#fff;text-decoration:none;padding:12px 18px;border-radius:10px">Reset password</a></p>` +
    `<p>Or copy and paste this link into your browser:<br><a href="${link}">${link}</a></p>` +
    `<p style="color:#475569;font-size:14px">This link will expire in 1 hour. If you didn't request this, you can ignore this email.</p>` +
    `<hr style="border:0;border-top:1px solid #e5e7eb;margin:16px 0" />` +
    `<p style="color:#64748b;font-size:12px">Request IP: ${ip || "unknown"}</p>` +
    `</div>`;

  const info = await mailerTransport.sendMail({
    from: SMTP_FROM,
    to,
    subject,
    text,
    html,
  });

  if (info.messageId) {
    console.log("Password reset email queued, messageId:", info.messageId);
  } else {
    console.log("Password reset email sent:", info);
  }
}

// View engine: all EJS templates live in project-root/public
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "..", "public"));

// Parsers
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Sessions
app.use(
  session({
    name: "sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    },
  }),
);

// Expose user to all templates
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// Expose current page to all templates
app.use((req, res, next) => {
  const path = req.path;
  let currentPage = "home"; // default
  if (path === "/products") currentPage = "products";
  else if (path === "/services") currentPage = "services";
  else if (path === "/booking") currentPage = "booking";
  else if (path === "/about") currentPage = "about";
  else if (path === "/contact") currentPage = "contact";
  else if (path === "/profile") currentPage = "profile";
  else if (path === "/orders") currentPage = "orders";
  else if (path === "/cart") currentPage = "cart";
  else if (path === "/wishlist") currentPage = "wishlist";
  res.locals.currentPage = currentPage;
  next();
});

// Logs
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Diagnostics
app.get("/health", (_req, res) => res.json({ ok: true }));
app.get("/whoami", (req, res) =>
  res.json({
    hostHeader: req.headers.host,
    url: req.originalUrl,
    nodePid: process.pid,
  }),
);
app.get("/session", (req, res) => {
  res.json({ user: req.session.user || null, sessionID: req.sessionID });
});

// Static assets served from public at /static
app.use("/static", express.static(path.join(__dirname, "..", "public")));

// Body normalizer: map common/odd field names to email/password
app.use((req, res, next) => {
  const isPost = req.method === "POST";
  const isForm = req.is("application/x-www-form-urlencoded");
  const isJson = req.is("application/json");
  if (isPost && (isForm || isJson)) {
    const b = req.body || {};
    const keys = Object.keys(b || {});
    const findBy = (substrs) =>
      keys.find((k) => substrs.some((s) => k.toLowerCase().includes(s)));

    if (!b.email) {
      const k = findBy(["email", "user", "login"]);
      b.email = k ? b[k] : b.Email || b.username || b.user || b.login || null;
    }
    if (!b.password) {
      const k = findBy(["password", "pass", "pwd"]);
      b.password = k ? b[k] : b.Password || b.pass || b.pwd || null;
    }

    req.body = b;
  }
  next();
});

// Helpers
function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}
function sanitizeUsername(name) {
  return String(name || "").trim();
}
function validateSignup({ username, email, password, termsAccepted }) {
  const errors = [];
  const fieldErrors = {};

  const uname = sanitizeUsername(username);
  if (!/^[a-zA-Z0-9_]{3,24}$/.test(uname)) {
    fieldErrors.username =
      "Username must be 3–24 chars: letters, numbers, or underscore.";
    errors.push(fieldErrors.username);
  }

  const mail = normalizeEmail(email);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail)) {
    fieldErrors.email = "Enter a valid email address.";
    errors.push(fieldErrors.email);
  }

  if (!password || String(password).length < 8) {
    fieldErrors.password = "Password must be at least 8 characters.";
    errors.push(fieldErrors.password);
  }

  if (
    !(
      termsAccepted === true ||
      termsAccepted === "on" ||
      termsAccepted === "true"
    )
  ) {
    fieldErrors.termsAccepted = "You must accept the Terms and Conditions.";
    errors.push(fieldErrors.termsAccepted);
  }

  return { errors, fieldErrors, uname, mail };
}

function validateLogin({ email, password }) {
  const errors = [];
  const fieldErrors = {};
  const mail = normalizeEmail(email);

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail)) {
    fieldErrors.email = "Enter a valid email address.";
    errors.push(fieldErrors.email);
  }
  if (!password || String(password).length < 8) {
    fieldErrors.password = "Password must be at least 8 characters.";
    errors.push(fieldErrors.password);
  }
  return { errors, fieldErrors, mail };
}

// Route guards
function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  return next();
}
function redirectIfAuth(req, res, next) {
  if (req.session.user) return res.redirect("/"); // send logged-in users to home
  return next();
}

// Routes

// Home (default) — renders public/home.ejs
app.get("/", (_req, res) => {
  res.render("home");
});

// Also serve /home for convenience
app.get("/home", (_req, res) => {
  res.render("home");
});

// Auth pages
app.get("/login", redirectIfAuth, (req, res) => {
  const success = req.query.m || null;
  res.render("login", { success, errors: [], fieldErrors: {}, formData: {} });
});

app.get("/signup", redirectIfAuth, (_req, res) => {
  res.render("signup", {
    success: null,
    errors: [],
    fieldErrors: {},
    formData: {},
  });
});

// Signup
app.post("/signup", async (req, res) => {
  try {
    const { username, email, password, termsAccepted } = req.body;
    const { errors, fieldErrors, uname, mail } = validateSignup({
      username,
      email,
      password,
      termsAccepted,
    });

    if (errors.length) {
      return res.status(400).render("signup", {
        success: null,
        errors,
        fieldErrors,
        formData: { username, email, termsAccepted },
      });
    }

    const existing = await User.findOne({
      $or: [{ name: uname }, { email: mail }],
    }).lean();

    if (existing) {
      const msg =
        existing.email === mail
          ? "An account with this email already exists."
          : "Username is already taken.";
      return res.status(409).render("signup", {
        success: null,
        errors: [msg],
        fieldErrors: {
          ...(existing.email === mail ? { email: msg } : {}),
          ...(existing.name === uname ? { username: msg } : {}),
        },
        formData: { username, email, termsAccepted },
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({
      name: uname,
      email: mail,
      password: hashedPassword,
      termsAccepted: !!(
        termsAccepted === true ||
        termsAccepted === "on" ||
        termsAccepted === "true"
      ),
    });

    return res.redirect(
      "/login?m=" + encodeURIComponent("Signup successful! Please log in."),
    );
  } catch (err) {
    console.error("Signup error:", err);
    return res.status(500).render("signup", {
      success: null,
      errors: ["An unexpected error occurred. Please try again."],
      fieldErrors: {},
      formData: {
        username: req.body.username,
        email: req.body.email,
        termsAccepted: req.body.termsAccepted,
      },
    });
  }
});

// Login (single definition)
app.post("/login", async (req, res) => {
  try {
    // Safe debug: show which fields we received (not their values)
    const keys = Object.keys(req.body || {});
    console.log("POST /login body keys:", keys);

    const rawEmail = (req.body.email ?? "").toString();
    const rawPassword = (req.body.password ?? "").toString();

    const { errors, fieldErrors, mail } = validateLogin({
      email: rawEmail,
      password: rawPassword,
    });

    if (errors.length) {
      return res.status(400).render("login", {
        success: null,
        errors,
        fieldErrors,
        formData: { email: rawEmail },
      });
    }

    const user = await User.findOne({ email: mail });
    if (!user) {
      const msg = "Email not found.";
      return res.status(404).render("login", {
        success: null,
        errors: [msg],
        fieldErrors: { email: msg },
        formData: { email: rawEmail },
      });
    }

    const ok = await bcrypt.compare(rawPassword, user.password);
    if (!ok) {
      const msg = "Incorrect password.";
      return res.status(401).render("login", {
        success: null,
        errors: [msg],
        fieldErrors: { password: msg },
        formData: { email: rawEmail },
      });
    }

    // Success: regenerate session, set user and redirect to home
    req.session.regenerate((err) => {
      if (err) {
        console.error("Session regenerate failed:", err);
        return res.status(500).render("login", {
          success: null,
          errors: ["Login failed due to a session error. Please try again."],
          fieldErrors: {},
          formData: { email: rawEmail },
        });
      }
      req.session.user = {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
      };
      req.session.save((saveErr) => {
        if (saveErr) {
          console.error("Session save failed:", saveErr);
          return res.status(500).render("login", {
            success: null,
            errors: ["Login failed due to a session error. Please try again."],
            fieldErrors: {},
            formData: { email: rawEmail },
          });
        }
        console.log("Login OK -> redirecting to /");
        // Use 302 (default) for broad compatibility
        return res.redirect("/");
      });
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).render("login", {
      success: null,
      errors: ["An unexpected error occurred. Please try again."],
      fieldErrors: {},
      formData: { email: (req.body && req.body.email) || "" },
    });
  }
});

// Forgot password: now sends an SMTP email with the reset link
app.get("/forgot-password", (_req, res) => {
  res.render("forgot-password", {
    success: null,
    errors: [],
    fieldErrors: {},
    formData: {},
  });
});

app.post("/forgot-password", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const genericMsg = "If that email exists, we've sent a reset link.";

    // Lookup user silently
    const user = await User.findOne({ email });
    if (!user) {
      // Do not reveal whether user exists
      return res.render("forgot-password", {
        success: genericMsg,
        errors: [],
        fieldErrors: {},
        formData: {},
      });
    }

    // Create token (1 hour)
    const token = crypto.randomBytes(32).toString("hex");
    user.resetPasswordToken = token;
    user.resetPasswordExpires = new Date(Date.now() + 1000 * 60 * 60);
    await user.save();

    // Absolute link
    const baseUrl = `${req.protocol}://${req.get("host")}`;
    const link = `${baseUrl}/reset-password/${token}`;

    // Send email (await)
    try {
      await sendPasswordResetEmail({
        to: email,
        name: user.name,
        link,
        ip: req.ip,
      });
    } catch (mailErr) {
      console.error("Failed to send reset email:", mailErr);
      // Keep response generic to avoid account enumeration
    }

    return res.render("forgot-password", {
      success: genericMsg,
      errors: [],
      fieldErrors: {},
      formData: {},
    });
  } catch (err) {
    console.error("Forgot password error:", err);
    return res.status(500).render("forgot-password", {
      success: null,
      errors: ["An unexpected error occurred. Please try again."],
      fieldErrors: {},
      formData: { email: req.body.email },
    });
  }
});

// Reset password
app.get("/reset-password/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: new Date() },
    }).lean();

    if (!user) {
      return res.status(400).render("forgot-password", {
        success: null,
        errors: ["Reset link is invalid or has expired."],
        fieldErrors: {},
        formData: {},
      });
    }

    return res.render("reset-password", {
      token,
      success: null,
      errors: [],
      fieldErrors: {},
      formData: {},
    });
  } catch (err) {
    console.error("Reset token lookup error:", err);
    return res.status(500).render("forgot-password", {
      success: null,
      errors: ["An unexpected error occurred. Please try again."],
      fieldErrors: {},
      formData: {},
    });
  }
});

app.post("/reset-password/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    if (!password || String(password).length < 8) {
      return res.status(400).render("reset-password", {
        token,
        success: null,
        errors: ["Password must be at least 8 characters."],
        fieldErrors: { password: "Password must be at least 8 characters." },
        formData: {},
      });
    }

    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: new Date() },
    });
    if (!user) {
      return res.status(400).render("forgot-password", {
        success: null,
        errors: ["Reset link is invalid or has expired."],
        fieldErrors: {},
        formData: {},
      });
    }

    user.password = await bcrypt.hash(password, 10);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    return res.redirect(
      "/login?m=" +
        encodeURIComponent("Password has been reset. Please log in."),
    );
  } catch (err) {
    console.error("Reset password error:", err);
    return res.status(500).render("reset-password", {
      token: req.params.token,
      success: null,
      errors: ["An unexpected error occurred. Please try again."],
      fieldErrors: {},
      formData: {},
    });
  }
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Session destroy error:", err);
    }
    res.clearCookie("sid");
    return res.redirect("/");
  });
});

// Protected routes for all pages except home
app.get("/products", requireAuth, (_req, res) => {
  res.render("products");
});

app.get("/services", requireAuth, (_req, res) => {
  res.render("services");
});

// Booking page - simple form
app.get("/booking", requireAuth, (req, res) => {
  const formData = {};
  if (req.query && req.query.service) {
    formData.service = req.query.service;
  }
  res.render("booking", { success: null, errors: [], formData });
});

app.post("/booking", requireAuth, (req, res) => {
  const { name, email, phone, service, date, message } = req.body;
  const errors = [];
  if (!name) errors.push("Name is required.");
  if (!email) errors.push("Email is required.");
  if (!service) errors.push("Please select a service.");
  if (errors.length) {
    return res.render("booking", { success: null, errors, formData: req.body });
  }
  // in a real app we'd save to DB or send an email
  console.log("Booking submitted:", req.body);
  res.render("booking", {
    success: "Your booking has been submitted. We'll be in touch soon!",
    errors: [],
    formData: {},
  });
});

app.get("/about", requireAuth, (_req, res) => {
  res.render("about");
});

app.get("/contact", requireAuth, (_req, res) => {
  res.render("contact");
});

app.get("/profile", requireAuth, (req, res) => {
  res.render("profile");
});

app.get("/orders", requireAuth, (req, res) => {
  res.render("orders");
});

app.get("/cart", requireAuth, (req, res) => {
  res.render("cart");
});

app.get("/wishlist", requireAuth, (req, res) => {
  res.render("wishlist");
});

// Category routes
app.get("/components/suits", requireAuth, (_req, res) => {
  res.render("components/suits");
});

app.get("/components/coats", requireAuth, (_req, res) => {
  res.render("components/coats");
});

app.get("/components/blazers", requireAuth, (_req, res) => {
  res.render("components/blazers");
});

app.get("/components/sharwani", requireAuth, (_req, res) => {
  res.render("components/sharwani");
});

app.get("/components/kurtas", requireAuth, (_req, res) => {
  res.render("components/kurtas");
});

app.get("/components/waistcoats", requireAuth, (_req, res) => {
  res.render("components/waistcoats");
});

app.get("/components/shirts", requireAuth, (_req, res) => {
  res.render("components/shirts");
});

app.get("/components/pants", requireAuth, (_req, res) => {
  res.render("components/pants");
});

// New Arrivals page (public)
app.get("/new-arrivals", (_req, res) => {
  res.render("new-arrivals");
});

// 404
app.use((req, res) => res.status(404).send("Not Found"));

// Start: listen first, then connect DB (so UI still works if DB is down)
function startServer() {
  app.listen(PORT, HOST, () => {
    console.log(
      `Server running at http://${HOST}:${PORT}/ (pid ${process.pid})`,
    );
    console.log(`Views directory:`, app.get("views"));
  });

  mongoose
    .connect(MONGO_URI)
    .then(() => console.log("Database Connected Successfully"))
    .catch((err) =>
      console.error("Database connection failed (app still running):", err),
    );
}

startServer();
