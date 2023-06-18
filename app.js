require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const port = process.env.PORT;

const app = express();

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb+srv://"+process.env.MDBUSERNAME+":"+process.env.MDBPASSWORD+"@cluster0.tuathop.mongodb.net/userDB?retryWrites=true&w=majority", {useNewUrlParser:true});


const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
});
  
passport.deserializeUser(function(id, done) {
    User.findById(id).then((user) => {
      done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://secrets-ayush.onrender.com/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req, res) => {
    res.render("home");
})
app.get("/login", (req, res) => {
    res.render("login");
})
app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/secrets", (req, res) => {
    User.find({"secret": {$ne: null}}).then((foundUsers) => {
        if(foundUsers){
            res.render("secrets", {usersWithSecrets: foundUsers})
        }
    })
})

app.get("/logout", (req, res) => {
    req.logout(function(err) {
        if (err){
            console.log(err);
        }
        else{
            res.redirect('/');
        }
    });
})

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
});

app.get("/submit", (req, res) => {
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login");
    }
});

app.post("/submit", (req, res) => {
    const submittedSecret = req.body.secret;

    // console.log(req.user.id);

    User.findById(req.user.id).then((foundUser) => {
        if(foundUser){
            foundUser.secret = submittedSecret;
            foundUser.save().then(() => {
                res.redirect("secrets");
            })
        }
    })
})


// ///////////////////////////////// Post request using passport ////////////////////////////////

app.post("/register", (req, res) => {
    User.register({username:req.body.username}, req.body.password, (err, user)=>{
        if(err){
            console.log(err);
            res.redirect("/register");
        }
        else{
            const authenticate = User.authenticate();
            authenticate('username', 'password', function(err, result) {
                if (!err) { 
                    res.redirect("/secrets");
                }
            })
        }
    })
})
app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })

    req.login(user, function(err){
        if(err){
            console.log(err);
        }
        else{
            const authenticate = User.authenticate();
            authenticate('username', 'password', function(err, result) {
                if (!err) { 
                    res.redirect("/secrets");
                }
            })
        }
    })
})

app.listen(port, () => console.log("Server Started at port "+port))