const express = require('express');
const cors = require("cors");
const multer = require("multer");
const mongoose = require("mongoose");
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const session = require("express-session");
const fs = require('fs');
const path = require('path');

const main = async () => {
  try {
    await mongoose.connect('mongodb://localhost:27017/leadpreneurs');
    console.log("db connected");
  } catch (error) {
    console.error(error);
  }
}

main();

const userSchema = mongoose.Schema({
  username: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  tokens: [
    {
      token: {
        type: String,
        required: true
      }
    }
  ],
  likedPosts: [
    {
      type: String,
      ref: 'post'
    }
  ]
});

const SECRET_KEY = "mynameischetansharmaistudyinbcagnecollegeludhiana";

userSchema.methods.generateAuthToken = async function () {
  try {
    const token = jwt.sign({ _id: this._id }, SECRET_KEY);
    this.tokens = this.tokens.concat({ token });
    await this.save();
    return token;
  } catch (error) {
    console.error(error);
  }
}

const User = mongoose.model('User', userSchema);

const bodyParser = require("body-parser");

const server = express();
server.use(cors());
server.use(bodyParser.json());
server.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false
}));

const verifyTokenAndSession = (req, res, next) => {
  const token = req.cookies.jwttoken;
  const sessionUser = req.session.user;

  if (!token || !sessionUser) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const userId = decoded._id;

    if (userId !== sessionUser._id) {
      return res.status(401).json({ message: 'User mismatch' });
    }

    next();
  });
};
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: "chetansharma9878600494@gmail.com",
    pass: "licehfezffyutbzi"
  }
});
const generateOTP = () => {
  // Generate a random 6-digit OTP
  return Math.floor(100000 + Math.random() * 900000);
};
const sendOTPByEmail = async (email, otp) => {
  try {
    let info = await transporter.sendMail({
      from: 'chetansharma9878600499@gmail.com',
      to: email,
      subject: 'OTP for Registration',
      text: `Your OTP for registration is: ${otp}`,
    });
    console.log('Message sent: %s', info.messageId);
  } catch (error) {
    console.error('Error sending email:', error);
  }
};
// Your existing imports and setup code...
let otp;
server.post("/sendOTP", async (req, res) => {
  try {
    const { username } = req.body;

    // Generate OTP
    const otp = generateOTP();

    // Send OTP to user's email using Nodemailer
    await sendOTPByEmail(username, otp);

    // Generate a token for OTP verification
    const token = jwt.sign({ otp }, SECRET_KEY);

    // Return the OTP and token to the client
    res.json({ success: true, message: "OTP sent successfully", otp, token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
  }
});
server.post("/sendOTPforpass", async (req, res) => {
  try {
    const { username } = req.body;

    // Generate OTP
    const otp = generateOTP();

    // Send OTP to user's email using Nodemailer
    const userexist=await User.findOne({username:username});
    // console.log
    if(userexist){
      await sendOTPByEmail(username, otp);
      const token = jwt.sign({ otp }, SECRET_KEY);
      res.json({ success: true, message: "OTP sent successfully", otp, token });
    }
    else{
      console.log("user not exists");
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
  }
});



server.post("/register", async (req, res) => {
  try {
    const { username, password, userotp, token } = req.body;
    const user = await User.findOne({ username });

    // Verify the token to get the OTP
    jwt.verify(token, SECRET_KEY, async (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Invalid token' });
      }

      const storedOTP = String(decoded.otp); // Trim stored OTP
      const storedotp = storedOTP.trim();
      const providedOTP = userotp.trim(); // Trim provided OTP
      // Check if the provided OTP matches the stored OTP
      if (user) {
        console.log("User already exists");
      } else {
        if (providedOTP === storedotp) {
          console.log("OTP Matched");
          const newUser = new User({ username, password });
          await newUser.save();
          console.log("User saved");
          res.status(201).json({ success: true, message: "User registered successfully" });
        } else {
          res.status(400).json({ error: "Invalid OTP" });
        }
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
  }
});

// Your existing routes and server setup...


server.post("/Login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    const admin = user.admin == true;

    if (!user || user.password !== password) {
      return res.status(401).json({ message: 'Authentication failed' });
    }

    const token = await user.generateAuthToken();
    const id = user._id;

    console.log('User ID:', id); // Log the user ID for debugging

    req.session.user = user;
    res.cookie("jwttoken", token, {
      expires: new Date(Date.now() + 100000),
      httpOnly: true
    });

    // Send user details along with the token and admin status
    res.json({ user, id, token, admin });
  } catch (error) {
    console.error('Error in /Login:', error);
    res.status(500).json({ error: "Server error" });
  }
});


server.get('/user/home', verifyTokenAndSession, (req, res) => {
  // Handle protected route logic here
});

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, 'uploads'));
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

const uploads = multer({ storage: storage });

const postschema = mongoose.Schema({
  desc: {
    type: String,
    required: true
  },
  imageUrl: {
    type: String,
    required: true
  },
  likes: {
    type: Number,
    required: true
  }
});

const postnew = mongoose.model('post', postschema);

server.post('/posts', uploads.single('image'), async (req, res) => {
  const imagePath = req.file.path.replace(/\\/g, '/');
  const imageUrl = `/uploads/${path.basename(imagePath)}`;
  const likes = 0;
  const desc = req.body.content;
  const post = new postnew({ desc, imageUrl, likes });
  const doc = await post.save();
  res.json(doc);
});

server.get("/posts_new", uploads.single('image'), async (req, res) => {
  try {
    const posts = await postnew.find({});
    res.json(posts);
  } catch (error) {
    console.error("Error fetching posts:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
server.post('/like', async (req, res) => {
  try {
    const { postId, userId } = req.body;
    console.log(userId);
    // Check if the user has already liked the post
    const user = await User.findById(userId);
    if (user.likedPosts.includes(postId)) {
      return res.status(400).json({ error: 'Post already liked by this user' });
    }

    // Increment the likes count for the post
    const updatedPost = await postnew.findByIdAndUpdate(postId, { $inc: { likes: 1 } }, { new: true });

    // Add the post ID to the user's likedPosts array
    await User.findByIdAndUpdate(userId, { $addToSet: { likedPosts: postId } });

    const updatedLikesCount = updatedPost.likes;
    res.json({ likes: updatedLikesCount });
  } catch (error) {
    console.error("Error liking post:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
server.post("/newpass",async (req, res) => {
  const { username, password, userotp, token } = req.body;
  const user = await User.findOne({ username });

  // Verify the token to get the OTP
  jwt.verify(token, SECRET_KEY, async (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Invalid token' });
    }
    const storedotp=decoded.otp;
    const storedotp_=String(storedotp).trim();
    const Userotp=String(userotp);
    if(user){
      if(Userotp===storedotp_){
        await user.updateOne({password:password});
      }
      else{
        console.log("invalid otp");
      }
    }
    else{
      console.log("user not exists");
    }
    res.json(200);
  })
})

  server.post("/delpost", async (req, res) => {
    const e = req.body.e;
    // const filePath = e.id;
    const postfind= await postnew.findOne({_id:e})
  const filepath =String(postfind.imageUrl)
    console.log(typeof(postfind));
    const post = String(e);
    console.log(typeof (filepath));
    console.log(filepath);
    fs.unlink(`.${filepath}`, (err) => {
      if (err) {
        console.error('Error occurred while deleting the file:', err);
        return;
      }
      console.log('File was successfully deleted');
    });
    await postnew.deleteOne({ _id: post });
  })
  server.use('/uploads', express.static(path.join(__dirname, 'uploads')));

  server.listen(3005||process.env.BASE_URL, () => {
    console.log("server started");
  });
//  this is my server file handle the otp here and setup middleware and  update in the above code without changing existing content