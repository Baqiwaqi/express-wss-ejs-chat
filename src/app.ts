import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import cors from "cors";
import crypto from "crypto";
import express from "express";
import session from "express-session";
import http from "http";
import logger from "morgan";
import passport from "passport";
import { Strategy } from "passport-local";
import path from "path";
import reload from "reload";
import WebSocket from "ws";
import { z } from "zod";
import db from "./db/client";

const SQLiteStore = require("connect-sqlite3")(session);

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

reload(app);

// view engine setup
app.use(express.static(path.join(__dirname, "../public")));

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(logger("dev"));

// add cors middleware
app.use(cors());
// app.use(csurf());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
// session
app.use(
  session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: false,
    store: new SQLiteStore({
      db: "session.db",
      dir: "./src/db",
    }),
  })
);

app.use(passport.authenticate("session"));

const userSchema = z.object({
  id: z.number().optional(),
  username: z.string(),
  hashed_password: z.any(),
  salt: z.any(),
});

type User = z.infer<typeof userSchema>;

// local strategy setup
passport.use(
  new Strategy((username, password, done) => {
    db.get(
      "SELECT * FROM users WHERE username = ?",
      [username],
      (err, user: User) => {
        if (err) {
          return done(err);
        }

        if (!user) {
          return done(null, false, { message: "User doesn't exsist" });
        }

        crypto.pbkdf2(
          password,
          user.salt,
          310000,
          32,
          "sha256",
          function (err, hashedPassword) {
            if (err) return done(err);

            if (!crypto.timingSafeEqual(user.hashed_password, hashedPassword)) {
              return done(null, false, {
                message: "Incorrect username or password",
              });
            }

            return done(null, user);
          }
        );
      }
    );
  })
);

passport.serializeUser((user, cb) => {
  process.nextTick(() => {
    cb(null, user);
  });
});

passport.deserializeUser((user, cb) => {
  process.nextTick(() => {
    return cb(null, user as Express.User);
  });
});

app.get(
  "/",
  (req, res, next) => {
    if (req.user) {
      return res.render("dashboard", { user: req.user });
    }
    next();
  },
  (req, res) => {
    res.render("index");
  }
);

app.get("/dashboard", (req, res, next) => {
  if (req.user) {
    return res.render("dashboard", { user: req.user });
  }

  res.redirect("/");
});

app.get("/register", (req, res) => {
  res.render("/register");
});

app.post("/register", (req, res) => {
  res.status(201).send("User registrated");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post(
  "/login/password",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
  })
);

app.post("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }

    res.redirect("/");
  });
});

app;

wss.on("connection", (w, req) => {
  w.on("message", (message) => {
    wss.clients.forEach((client) => {
      if (client !== w && client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  });
});

server.listen(3000, () => {
  console.log("Server started running on port: 3000");
});

// const clients = {} as { [key: string]: net.Socket };

// const server = net.createServer((socket) => {
//   socket.write("Hello, welcome to the server\n");

//   const clientId = `${socket.remoteAddress}:${socket.remotePort}`;

//   clients[clientId] = socket;

//   let username = "";
//   let isAuth = false;

//   socket.on("data", (data) => {
//     const message = data.toString().trim();

//     if (!isAuth) {
//       if (!username) {
//         username = message;
//         isAuth = true;

//         socket.write(`You are now authenticated as ${username}\n`);

//         broadcast(`${username} has joined the chat`, clientId);
//       } else {
//         socket.write(`You are already authenticated as ${username}\n`);
//       }
//     } else {
//       broadcast(message, username);
//     }
//   });

//   socket.on("end", () => {
//     if (isAuth) {
//       broadcast(`${username} has left the chat`, clientId);
//       delete clients[clientId];
//     }
//   });
// });

// function broadcast(message: string, senderId: string) {
//   Object.keys(clients).forEach((clientId) => {
//     if (clientId !== senderId) {
//       clients[clientId]!.write(`${senderId}: ${message}\n`);
//     }
//   });
// }

// server.listen(3000, () => {
//   console.log("Server started");
// });
