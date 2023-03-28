const express = require("express");
const bodyParser = require("body-parser");
const passport = require("passport");
const JWTStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();
const port = 8080;

// Setting up jwt secret key
const your_jwt_secret = crypto.randomBytes(64).toString("hex");

// Setting up body-parser middleware
app.use(bodyParser.json());

// Setting up JWT authentication strategy
const jwtOpts = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: your_jwt_secret
}

passport.use(new JWTStrategy(jwtOpts, (payload, done) => {
    // Checking if user exists and has the required permissions
    const user = {
        id: payload.id,
        email: payload.email,
        role: payload.role
    };

    if (user && user.role === "admin") {
        done (null, user);
    }  else {
        done (null, false);
    }
}));

// Setting up authentication middleware
const authenticate = passport.authenticate("jwt", {session: false});

// Setting up authorization middleware
const authorize = (req, res, next) => {
    if (req.user && req.user.role === "admin") {
      next();
    } else {
      res.status(401).send("Unauthorized");
    }
};

// Setting up login endpoint
app.post("/login", (req, res) => {
    // Check if user credentials are valid
    const user = {
      id: 1,
      email: "admin@example.com",
      role: "admin"
    };

    const token = jwt.sign(user, your_jwt_secret);
    res.json({token});
});
  
// Setting up protected endpoint
app.get("/protected", authenticate, authorize, (req, res) => {
    res.send("Hello, user!");
});
  
// Starting the server
app.listen(port, () => {
    console.log(`Server is listening on port ${port}`);
});