const express = require("express");
const app = express();
const http = require("http");
const server = http.createServer(app);
var mysql = require("mysql");
const bodyParser = require("body-parser");
var path = require("path");
var multer = require("multer");
var crypto = require("crypto");
const jwt = require("jsonwebtoken");

const secret = "EnHeltGalenHemlighetSomBaraJagVetXyz123%&/";

var storage = multer.diskStorage({
  destination: "./public/profPics/",
  filename: function (req, file, cb) {
    crypto.pseudoRandomBytes(16, function (err, raw) {
      if (err) return cb(err);

      cb(null, raw.toString("hex") + path.extname(file.originalname));
    });
  },
});

var upload = multer({ storage: storage });

const conn = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "root",
  database: "api_projekt",
});

conn.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL database: " + err.stack);
    return;
  }
  console.log("Connected to MySQL database");
});

app.use(express.json());
app.use("/public", express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

function processUserInput(inputArray) {
  for (let input of inputArray) {
    if (!/^[a-zA-Z0-9.@#]+$/.test(input)) {
      return false;
    }
  }
  return true;
}

function hash(data) {
  const hash = crypto.createHash("sha256");
  hash.update(data);
  return hash.digest("hex");
}

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

let newToken = "";

function getToken(tokenName) {
  newToken = tokenName;
}

function verifyToken(req, res, next) {
  const vertoken = newToken;
  if (!vertoken)
    return res
      .status(401)
      .send("Access denied. No token found or it may be expired.");

  jwt.verify(vertoken, secret, (err, decoded) => {
    if (err)
      return res.status(401).send("Invalid token. Token may be expired.");
    req.user = decoded;
    next();
  });
}

app.post("/addUser", upload.single("profilePic"), (req, res) => {
  const { username, passwd, email } = req.body;
  const profilePic = null;
  if (profilePic != null || "") {
    profilePic = req.file.filename;
  }
  // OBS! Profilepic-delen kan endast genomföras ifall en fil har laddats upp!
  // Filuppladdning fungerar inte i Insomnia, därför blir profilePic = null!
  const insertQuery = `INSERT INTO users (username, passwd, email, profilepic) VALUES (?, ?, ?, ?)`;
  const values = [username, hash(passwd), email, profilePic];
  const isValid = processUserInput(values);

  if (!isValid) {
    console.error("Error inserting data into the database: Invalid input. ");
    res.status(422).send("Invalid input, try again.");
    return;
  }

  conn.query(insertQuery, values, (err, result) => {
    if (err) {
      console.error(
        "There was an error with inserting data into the database: " + err.stack
      );
      res
        .status(500)
        .send(
          "Error when attempting to create user. Values may already be in use. Try again."
        );
      return;
    }

    if (result.length == 0) {
      res.status(403).send("The value structure was incorrect. Try again.");
      return;
    }

    console.log("Inserted into database with ID: " + result.insertId);
    res.status(200).send("Success!");
  });
});

app.post("/logInUser", (req, res) => {
  const { username, passwd } = req.body;
  const passwdHash = hash(passwd);
  const logValues = [username, passwdHash];
  const findUserQuery = `SELECT * FROM users WHERE username = ? AND passwd = ?`;

  const isValid = processUserInput(logValues);

  if (!isValid) {
    console.error("Error locating into the database: Invalid input. ");
    res.status(422).send("Invalid input, try again.");
    return;
  }
  conn.query(findUserQuery, logValues, (err, result) => {
    if (err) {
      console.error("Login incorrect: " + err.stack);
      res.status(401).send("There was an error with the database.");
      return;
    }
    if (result.length == 0) {
      res.status(401).send("Incorrect login values, try again.");
      return;
    }
    let payload = {
      sub: result[0].id,
      username: result[0].username,
      passwd: result[0].passwd,
      exp: Math.floor(Date.now() / 1000) + 2 * 60 * 60 + 5 * 60,
    };
    token = jwt.sign(payload, secret);
    res.json({ token });
    getToken(token);
  });
});

app.put("/editUserInfo", verifyToken, (req, res) => {
  var { username, passwd, newusername, newpasswd } = req.body;
  var editValues = [];
  let editInfoQuery = ``;
  if (newusername == null) {
    editValues = [hash(newpasswd), username, hash(passwd)];
    editInfoQuery = `UPDATE users SET passwd = ? WHERE username = ? AND passwd = ?`;
  } else if (newpasswd == null) {
    editValues = [hash(newusername), username, hash(passwd)];
    editInfoQuery = `UPDATE users SET username = ? WHERE username = ? AND passwd = ?`;
  } else {
    editValues = [newusername, hash(newpasswd), username, hash(passwd)];
    editInfoQuery = `UPDATE users SET username = ?, passwd = ? WHERE username = ? AND passwd = ?`;
  }

  const isValid = processUserInput(editValues);
  if (!isValid) {
    console.error("Error locating into the database: Invalid input. ");
    res.status(422).send("Invalid input, try again.");
    return;
  }

  conn.query(editInfoQuery, editValues, function (err, results) {
    if (err) {
      console.error("Error in editing user info: Server error.", err.stack);
      res
        .status(500)
        .send("Incorrect input. New values may already be in use. Try again.");
      return;
    }
    if (results.length == 0) {
      res
        .status(403)
        .send(
          "The values were incorrect or your new login values may already be in use, try again."
        );
      return;
    }
    res.json(newToken);
  });
});

app.get("/displayUserInfo", verifyToken, (req, res) => {
  const userId = req.user.sub;
  const UNQuery = `SELECT username, profilepic FROM users WHERE id = ?`;
  conn.query(UNQuery, userId, (err, results) => {
    if (err) {
      console.error("Error retrieving data from the database: " + err.stack);
      res.status(500).send("Invalid token, it may have expired. Try again.");
      return;
    }
    if (results.length == 0) {
      res
        .status(404)
        .send(
          "Information for this user was not found, values may have been changed or deleted, or login has expired. Try again."
        );
      return;
    }
    console.log("Successfully displayed information! (Maybe)");
    res.json(results);
  });
});

server.listen(5000, () => {
  console.log("listening on localhost:5000");
});
