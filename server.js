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

var thisUserId = "";
app.post("/addUser", upload.single("profilePic"), (req, res) => {
  const { username, passwd, email } = req.body;
  const profilePic = null;
  // OBS! Profilepic-delen kan endast genomföras ifall en fil har laddats upp! Fungerar troligen inte i Insomnia!
  if (profilePic != null) {
    profilePic = req.file.filename;
  }

  const insertQuery = `INSERT INTO users (username, passwd, email, profilepic) VALUES (?, ?, ?, ?)`;
  const values = [username, hash(passwd), email, profilePic];
  const isValid = processUserInput(values);

  if (!isValid) {
    console.error("Error inserting data into the database: Invalid input. ");
    res.sendStatus(422);
    return;
  }

  conn.query(insertQuery, values, (err, result) => {
    if (err) {
      console.error("Error inserting data into the database: " + err.stack);
      res.sendStatus(500);
      return;
    }

    console.log("Inserted into database with ID: " + result.insertId);
    res.redirect("/");
    thisUserId = result.insertId;
  });
});

app.post("/logInUser", (req, res) => {
  const { username, passwd } = req.body;
  const passwdHash = hash(passwd);
  const logValues = [ username, passwdHash ];
  const findUserQuery = `SELECT * FROM users WHERE username = ? AND passwd = ?`

  const isValid = processUserInput(logValues);

  if (!isValid) {
    console.error("Error locating into the database: Invalid input. ");
    res.sendStatus(422);
    return;
  }

  conn.query(findUserQuery, logValues, (err, result) => {
    if (err) {
      console.error("Login incorrect: " + err.stack);
      res.sendStatus(401);
      return;
    }

    if (result[0].passwd = passwdHash) {
      let payload = {
        sub: result[0].id,
        username: result[0].username,
        passwd: result[0].passwd,
        exp: Math.floor(Date.now() / 1000) + (2 * 60 * 60) + (5 * 60),
      };
      let token = jwt.sign(payload, secret);
      res.json(token);
      // console.log("Located user " + username + " from database with ID: " + result[0].id);
      // res.redirect("/");
      // thisUserId = result[0].id;
      // return username, thisUserId;
    } else {
      res.sendStatus(401);
    }
  });
});

app.put("/editUserInfo", (req, res) => {
  var { username, passwd, newusername, newpasswd } = req.body;
  var editValues = [];
  var editInfoQuery = ``;
  if (newusername == null) {
    editValues = [hash(newpasswd), username, passwd];
    editInfoQuery = `UPDATE users SET passwd = ? WHERE username = ? AND passwd = ?`;
  } else if (newpasswd == null) {
    editValues = [newusername, username, passwd];
    editInfoQuery = `UPDATE users SET username = ? WHERE username = ? AND passwd = ?`;
  } else {
    editValues = [newusername, hash(newpasswd), username, passwd];
    editInfoQuery = `UPDATE users SET username = ?, passwd = ? WHERE username = ? AND passwd = ?`;
  }

  const isValid = processUserInput(editValues);
  if (!isValid) {
    console.error("Error locating into the database: Invalid input. ");
    res.sendStatus(422);
    return;
  }
  
  conn.query(editInfoQuery, editValues, function (err, result) {
    if (err) {
      console.error("Error in editing user info: Server error.", err.stack);
      res.sendStatus(500);
      return;
    }
    res.sendStatus(200);
  });
});

app.get("/displayUserInfo", (req, res) => {
  const searchId = thisUserId;
  const UNQuery = `SELECT username, profilepic FROM users WHERE id = ?`;
  conn.query(UNQuery, searchId, (err, results) => {
    if (err) {
      console.error("Error retrieving data from the database: " + err.stack);
      res.sendStatus(500);
      return;
    }
    res.json(results);
  });
});

server.listen(5000, () => {
  console.log("listening on *:5000");
});