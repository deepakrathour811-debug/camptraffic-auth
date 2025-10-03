// Import necessary packages
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');

// Initialize the Express app
const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// Nodemailer transporter (using Gmail SMTP)
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: 'deepakrathour811@gmail.com',
        pass: 'sxegsmnydjrb cusq'
    }
});



// In-memory registration store (use Redis in production)
const registrationStore = new Map();

// Middleware setup
app.use(cors());
app.use(express.json());

// --- Authentication Middleware ---
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(400).json({ message: 'Invalid token.' });
    }
};

// --- Admin Authentication Middleware ---
const adminAuthMiddleware = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied. Admin privileges required.' });
        }
        req.user = decoded;
        next();
    } catch (error) {
        res.status(400).json({ message: 'Invalid token.' });
    }
};

// Protected Admin Page Route
app.get('/admin.html', adminAuthMiddleware, (req, res) => {
    res.sendFile(path.join(__dirname, '../public/admin.html'));
});

// Serve static files (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, '../public')));

// --- THIS IS THE FIX ---
// Explicitly handle preflight requests for all routes
app.options('*', cors());

// --- MongoDB Connection for Vercel/Serverless ---
let cached = global.mongoose;

if (!cached) {
    cached = global.mongoose = { conn: null, promise: null };
}

async function connectToDatabase() {
    if (cached.conn) {
        return cached.conn;
    }

    if (!cached.promise) {
        const opts = {
            bufferCommands: false,
            maxPoolSize: 10,
            minPoolSize: 5,
            maxIdleTimeMS: 30000,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
            family: 4
        };

        cached.promise = mongoose.connect(MONGO_URI, opts).then((mongoose) => {
            console.log('Successfully connected to MongoDB');
            return mongoose;
        });
    }

    try {
        cached.conn = await cached.promise;
    } catch (e) {
        cached.promise = null;
        console.error('Could not connect to MongoDB:', e);
        throw e;
    }

    return cached.conn;
}

// --- User Schema and Model ---
const userSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    referralCode: { type: String, default: '' },
    email: { type: String, required: true, unique: true, lowercase: true },
    phone: { type: String, required: false, default: '' },
    countryCode: { type: String, required: true, default: '+91' },
    messagingPlatform: { type: String, required: true },
    username: { type: String, required: true },
    howDidYouKnow: { type: String, required: true },
    password: { type: String, required: true },
    agreeToTerms: { type: Boolean, required: true, default: false },
    agreeToPromotional: { type: Boolean, default: false },
    walletBalance: { type: Number, default: 0 },
    role: { type: String, default: 'user' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Campaign Schema and Model
const campaignSchema = new mongoose.Schema({
    name: { type: String, required: true },
    adTitle: { type: String, required: true },
    adDescription: { type: String, required: true },
    targeting: { type: String, required: true },
    budgetType: { type: String, required: true, enum: ['CPC', 'CPM'] },
    budgetAmount: { type: Number, required: true },
    cpcRate: { type: Number, default: null },
    type: { type: String, required: true, enum: ['text', 'banner', 'in-page-push', 'native', 'popunder'] },
    imageUrl: { type: String, default: null },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    status: { type: String, default: 'active' },
    createdAt: { type: Date, default: Date.now }
});

const Campaign = mongoose.model('Campaign', campaignSchema);

// Click Schema and Model
const clickSchema = new mongoose.Schema({
    campaignId: { type: mongoose.Schema.Types.ObjectId, ref: 'Campaign', required: true },
    ip: { type: String, required: true },
    userAgent: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    referrer: { type: String }
});

const Click = mongoose.model('Click', clickSchema);

// Statistics Schema and Model
const statisticsSchema = new mongoose.Schema({
    campaignId: { type: mongoose.Schema.Types.ObjectId, ref: 'Campaign', required: true },
    date: { type: Date, required: true },
    impressions: { type: Number, default: 0 },
    clicks: { type: Number, default: 0 },
    conversions: { type: Number, default: 0 },
    spend: { type: Number, default: 0 },
    ctr: { type: Number, default: 0 }, // Click-through rate
    cpc: { type: Number, default: 0 }, // Cost per click
    cpm: { type: Number, default: 0 }, // Cost per thousand impressions
    createdAt: { type: Date, default: Date.now }
});

const Statistics = mongoose.model('Statistics', statisticsSchema);

// Multer configuration for file uploads

const storage = multer.diskStorage({

  destination: function (req, file, cb) {

    const uploadDir = path.join(__dirname, '../public/uploads');

    if (!fs.existsSync(uploadDir)) {

      fs.mkdirSync(uploadDir, { recursive: true });

    }

    cb(null, uploadDir);

  },

  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// --- API Routes ---

// Removed legacy /signup route - use /register for new registrations

// Comprehensive Registration Route (OTP-based)
app.post('/register', async (req, res) => {
    try {
        await connectToDatabase();

        const {
            firstName,
            lastName,
            referralCode,
            email,
            phone,
            countryCode,
            messagingPlatform,
            username,
            howDidYouKnow,
            password,
            agreeToTerms,
            agreeToPromotional
        } = req.body;

        console.log('Registration request received:', { firstName, lastName, email, phone, username, messagingPlatform, howDidYouKnow, agreeToTerms });

        // Validation
        if (!firstName || !lastName || !email || !phone || !messagingPlatform || !username || !howDidYouKnow || !password) {
            return res.status(400).json({ message: 'All required fields must be filled.' });
        }

        if (!agreeToTerms) {
            return res.status(400).json({ message: 'You must agree to the Terms and Privacy Policy.' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ message: 'User with this email already exists.' });
        }

        // Store registration data temporarily
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const registrationData = {
            firstName,
            lastName,
            referralCode: referralCode || '',
            email,
            phone,
            countryCode: countryCode || '+91',
            messagingPlatform,
            username,
            howDidYouKnow,
            password: hashedPassword,
            agreeToTerms,
            agreeToPromotional: agreeToPromotional || false
        };

        // Generate 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        registrationStore.set(email.toLowerCase(), { ...registrationData, otp, expires: Date.now() + 5 * 60 * 1000 }); // 5 min expiry

        // Send OTP email
        console.log(`OTP for ${email}: ${otp}`);
        const mailOptions = {
            from: 'deepakrathour811@gmail.com',
            to: email,
            subject: 'Verify Your Email for CampTraffic Auth',
            text: `Your OTP for email verification is: ${otp}. It expires in 5 minutes.`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Email send error:', error);
                return res.status(500).json({ message: 'Failed to send verification email.' });
            }
            console.log('Verification OTP sent:', info.response);
            res.status(200).json({ message: 'Verification OTP sent to your email. Please verify to complete registration.' });
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error during registration.', error: error.message });
    }
});

// Verify Registration OTP Route
app.post('/verify-registration-otp', async (req, res) => {
    try {
        await connectToDatabase();

        const { email, otp } = req.body;
        const stored = registrationStore.get(email.toLowerCase());
        if (!stored || stored.otp !== otp || Date.now() > stored.expires) {
            return res.status(400).json({ message: 'Invalid or expired OTP.' });
        }

        // Clear registration data and OTP
        const { otp: _, expires: __, ...userData } = stored;
        registrationStore.delete(email);

        // Save user to DB
        const newUser = new User(userData);
        const savedUser = await newUser.save();
        console.log('User saved successfully:', savedUser._id);

        res.status(201).json({ message: 'Account created successfully! You can now login.' });
    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).json({ message: 'Server error during verification.', error: error.message });
    }
});

// Login Route (Direct password verification)
app.post('/login', async (req, res) => {
    try {
        await connectToDatabase();

        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid password.' });
        }

        // Generate JWT token
        const payload = { id: user._id, name: user.firstName + ' ' + user.lastName };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ message: 'Login successful!', token });
    } catch (error) {
        res.status(500).json({ message: 'Server error during login.', error: error.message });
    }
});

// Admin Login Route
app.post('/admin-login', async (req, res) => {
    try {
        await connectToDatabase();

        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        if (user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied. Admin privileges required.' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid password.' });
        }

        // Generate JWT token for admin
        const payload = { id: user._id, name: user.firstName + ' ' + user.lastName, role: user.role };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ message: 'Admin login successful!', token });
    } catch (error) {
        res.status(500).json({ message: 'Server error during admin login.', error: error.message });
    }
});



// Protected Dashboard Route
app.get('/dashboard', authMiddleware, async (req, res) => {
    try {
        await connectToDatabase();

        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }
        res.status(200).json({ message: `Welcome to your dashboard!`, user });
    } catch (error) {
        res.status(500).json({ message: 'Server error.', error: error.message });
    }
});

// Protected Get Wallet Balance Route
app.get('/api/wallet/balance', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('walletBalance');
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }
        res.status(200).json({ balance: user.walletBalance || 0 });
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching balance.', error: error.message });
    }
});

// Protected Top Up Wallet Route
app.post('/api/wallet/topup', authMiddleware, async (req, res) => {
    try {
        const { amount } = req.body;
        const topupAmount = parseFloat(amount);
        if (isNaN(topupAmount) || topupAmount <= 0) {
            return res.status(400).json({ message: 'Invalid top-up amount.' });
        }
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }
        user.walletBalance = (user.walletBalance || 0) + topupAmount;
        await user.save();
        res.status(200).json({ message: 'Wallet topped up successfully!', balance: user.walletBalance });
    } catch (error) {
        res.status(500).json({ message: 'Server error during top-up.', error: error.message });
    }
});

// Protected Create Campaign Route (for text ads - JSON)
app.post('/api/campaigns', authMiddleware, async (req, res) => {
    try {
        const { name, adTitle, adDescription, targeting, budgetType, budgetAmount } = req.body;
        const type = 'text'; // Default for this endpoint

        // Validation
        if (!name || !adTitle || !adDescription || !targeting || !budgetType || !budgetAmount) {
            return res.status(400).json({ message: 'All campaign fields are required.' });
        }

        if (!['CPC', 'CPM'].includes(budgetType)) {
            return res.status(400).json({ message: 'Budget type must be CPC or CPM.' });
        }

        const budget = parseFloat(budgetAmount);
        if (isNaN(budget) || budget <= 0) {
            return res.status(400).json({ message: 'Budget amount must be greater than 0.' });
        }

        const newCampaign = new Campaign({
            name,
            adTitle,
            adDescription,
            targeting,
            budgetType,
            budgetAmount: budget,
            type,
            imageUrl: null,
            userId: req.user.id
        });

        const savedCampaign = await newCampaign.save();
        res.status(201).json({ message: 'Campaign created successfully!', campaign: savedCampaign });
    } catch (error) {
        console.error('Campaign creation error:', error);
        res.status(500).json({ message: 'Server error during campaign creation.', error: error.message });
    }
});

// Protected Create Banner Campaign Route (multipart for image)
app.post('/api/campaigns/banner', authMiddleware, upload.single('bannerImage'), async (req, res) => {
    try {
        const { name, adTitle, adDescription, targeting, budgetType, budgetAmount, cpcRate } = req.body;
        const type = 'banner';

        // Validation
        if (!name || !adTitle || !adDescription || !targeting || !budgetType || !budgetAmount) {
            return res.status(400).json({ message: 'All campaign fields are required.' });
        }

        if (!['CPC', 'CPM'].includes(budgetType)) {
            return res.status(400).json({ message: 'Budget type must be CPC or CPM.' });
        }

        const budget = parseFloat(budgetAmount);
        if (isNaN(budget) || budget <= 0) {
            return res.status(400).json({ message: 'Budget amount must be greater than 0.' });
        }

        if (!req.file) {
            return res.status(400).json({ message: 'Banner image is required for banner campaigns.' });
        }

        const imageUrl = req.file.path;
        const parsedCpcRate = cpcRate ? parseFloat(cpcRate) : null;

        const newCampaign = new Campaign({
            name,
            adTitle,
            adDescription,
            targeting,
            budgetType,
            budgetAmount: budget,
            cpcRate: parsedCpcRate,
            type,
            imageUrl,
            userId: req.user.id
        });

        const savedCampaign = await newCampaign.save();
        res.status(201).json({ message: 'Campaign created successfully!', campaign: savedCampaign });
    } catch (error) {
        console.error('Banner campaign creation error:', error);
        if (req.file) {
            fs.unlinkSync(req.file.path); // Cleanup on error
        }
        res.status(500).json({ message: 'Server error during banner campaign creation.', error: error.message });
    }
});

// Protected Create In-Page Push Campaign Route (multipart for optional icon)
app.post('/api/campaigns/in-page-push', authMiddleware, upload.single('icon'), async (req, res) => {
    try {
        const { name, adTitle, adDescription, targeting, budgetType, budgetAmount } = req.body;
        const type = 'in-page-push';

        // Validation
        if (!name || !adTitle || !adDescription || !targeting || !budgetType || !budgetAmount) {
            return res.status(400).json({ message: 'All campaign fields are required.' });
        }

        if (!['CPC', 'CPM'].includes(budgetType)) {
            return res.status(400).json({ message: 'Budget type must be CPC or CPM.' });
        }

        const budget = parseFloat(budgetAmount);
        if (isNaN(budget) || budget <= 0) {
            return res.status(400).json({ message: 'Budget amount must be greater than 0.' });
        }

        const imageUrl = req.file ? req.file.path : null;

        const newCampaign = new Campaign({
            name,
            adTitle,
            adDescription,
            targeting,
            budgetType,
            budgetAmount: budget,
            type,
            imageUrl,
            userId: req.user.id
        });

        const savedCampaign = await newCampaign.save();
        res.status(201).json({ message: 'Campaign created successfully!', campaign: savedCampaign });
    } catch (error) {
        console.error('In-Page Push campaign creation error:', error);
        if (req.file) {
            fs.unlinkSync(req.file.path); // Cleanup on error
        }
        res.status(500).json({ message: 'Server error during campaign creation.', error: error.message });
    }
});

// Protected Create Native Campaign Route (multipart for required image)
app.post('/api/campaigns/native', authMiddleware, upload.single('nativeImage'), async (req, res) => {
    try {
        const { name, adTitle, adDescription, targeting, budgetType, budgetAmount } = req.body;
        const type = 'native';

        // Validation
        if (!name || !adTitle || !adDescription || !targeting || !budgetType || !budgetAmount) {
            return res.status(400).json({ message: 'All campaign fields are required.' });
        }

        if (!['CPC', 'CPM'].includes(budgetType)) {
            return res.status(400).json({ message: 'Budget type must be CPC or CPM.' });
        }

        const budget = parseFloat(budgetAmount);
        if (isNaN(budget) || budget <= 0) {
            return res.status(400).json({ message: 'Budget amount must be greater than 0.' });
        }

        if (!req.file) {
            return res.status(400).json({ message: 'Native image is required for native campaigns.' });
        }

        const imageUrl = req.file.path;

        const newCampaign = new Campaign({
            name,
            adTitle,
            adDescription,
            targeting,
            budgetType,
            budgetAmount: budget,
            type,
            imageUrl,
            userId: req.user.id
        });

        const savedCampaign = await newCampaign.save();
        res.status(201).json({ message: 'Campaign created successfully!', campaign: savedCampaign });
    } catch (error) {
        console.error('Native campaign creation error:', error);
        if (req.file) {
            fs.unlinkSync(req.file.path); // Cleanup on error
        }
        res.status(500).json({ message: 'Server error during native campaign creation.', error: error.message });
    }
});

// Protected Create Popunder Campaign Route (multipart for required image)
app.post('/api/campaigns/popunder', authMiddleware, upload.single('popunderImage'), async (req, res) => {
    try {
        const { name, adTitle, adDescription, targeting, budgetType, budgetAmount } = req.body;
        const type = 'popunder';

        // Validation
        if (!name || !adTitle || !adDescription || !targeting || !budgetType || !budgetAmount) {
            return res.status(400).json({ message: 'All campaign fields are required.' });
        }

        if (!['CPC', 'CPM'].includes(budgetType)) {
            return res.status(400).json({ message: 'Budget type must be CPC or CPM.' });
        }

        const budget = parseFloat(budgetAmount);
        if (isNaN(budget) || budget <= 0) {
            return res.status(400).json({ message: 'Budget amount must be greater than 0.' });
        }

        if (!req.file) {
            return res.status(400).json({ message: 'Popunder image is required for popunder campaigns.' });
        }

        const imageUrl = req.file.path;

        const newCampaign = new Campaign({
            name,
            adTitle,
            adDescription,
            targeting,
            budgetType,
            budgetAmount: budget,
            type,
            imageUrl,
            userId: req.user.id
        });

        const savedCampaign = await newCampaign.save();
        res.status(201).json({ message: 'Campaign created successfully!', campaign: savedCampaign });
    } catch (error) {
        console.error('Popunder campaign creation error:', error);
        if (req.file) {
            fs.unlinkSync(req.file.path); // Cleanup on error
        }
        res.status(500).json({ message: 'Server error during popunder campaign creation.', error: error.message });
    }
});

// Protected Get User's Campaigns Route
app.get('/api/campaigns', authMiddleware, async (req, res) => {
    try {
        const campaigns = await Campaign.find({ userId: req.user.id }).sort({ createdAt: -1 });
        res.status(200).json({ campaigns });
    } catch (error) {
        console.error('Fetch campaigns error:', error);
        res.status(500).json({ message: 'Server error fetching campaigns.', error: error.message });
    }
});

// Public Log Ad Click Route
app.post('/api/ad-click', async (req, res) => {
    try {
        const { campaignId } = req.body;

        if (!campaignId) {
            return res.status(400).json({ message: 'Campaign ID is required.' });
        }

        // Verify campaign exists
        const campaign = await Campaign.findById(campaignId);
        if (!campaign) {
            return res.status(404).json({ message: 'Campaign not found.' });
        }

        const newClick = new Click({
            campaignId,
            ip: req.ip || req.connection.remoteAddress,
            userAgent: req.headers['user-agent'],
            referrer: req.headers.referer
        });

        const savedClick = await newClick.save();

        // Deduct from wallet if CPC rate is set
        if (campaign.cpcRate && campaign.cpcRate > 0) {
            const user = await User.findById(campaign.userId);
            if (user && (user.walletBalance || 0) >= campaign.cpcRate) {
                user.walletBalance = (user.walletBalance || 0) - campaign.cpcRate;
                await user.save();
                console.log(`Deducted ${campaign.cpcRate} from user ${user._id} wallet. New balance: ${user.walletBalance}`);
            } else {
                console.warn(`Insufficient balance for user ${campaign.userId} to deduct ${campaign.cpcRate}`);
            }
        }

        res.status(201).json({ message: 'Click logged successfully!', click: savedClick });
    } catch (error) {
        console.error('Ad click logging error:', error);
        res.status(500).json({ message: 'Server error logging click.', error: error.message });
    }
});

// Admin Routes
// Get all users
app.get('/api/admin/users', adminAuthMiddleware, async (req, res) => {
    try {
        const users = await User.find().select('-password').sort({ createdAt: -1 });
        res.status(200).json({ users });
    } catch (error) {
        console.error('Fetch users error:', error);
        res.status(500).json({ message: 'Server error fetching users.', error: error.message });
    }
});

// Get all campaigns
app.get('/api/admin/campaigns', adminAuthMiddleware, async (req, res) => {
    try {
        const campaigns = await Campaign.find().populate('userId', 'firstName lastName email').sort({ createdAt: -1 });
        res.status(200).json({ campaigns });
    } catch (error) {
        console.error('Fetch campaigns error:', error);
        res.status(500).json({ message: 'Server error fetching campaigns.', error: error.message });
    }
});

// Update campaign status
app.put('/api/admin/campaigns/:id', adminAuthMiddleware, async (req, res) => {
    try {
        const { status } = req.body;
        const campaign = await Campaign.findByIdAndUpdate(req.params.id, { status }, { new: true });
        if (!campaign) {
            return res.status(404).json({ message: 'Campaign not found.' });
        }
        res.status(200).json({ message: 'Campaign updated successfully.', campaign });
    } catch (error) {
        console.error('Update campaign error:', error);
        res.status(500).json({ message: 'Server error updating campaign.', error: error.message });
    }
});

// Update user wallet
app.put('/api/admin/users/:id/wallet', adminAuthMiddleware, async (req, res) => {
    try {
        const { amount } = req.body;
        const newBalance = parseFloat(amount);
        if (isNaN(newBalance) || newBalance < 0) {
            return res.status(400).json({ message: 'Invalid wallet amount.' });
        }
        const user = await User.findByIdAndUpdate(req.params.id, { walletBalance: newBalance }, { new: true });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        res.status(200).json({ message: 'User wallet updated successfully.', user });
    } catch (error) {
        console.error('Update user wallet error:', error);
        res.status(500).json({ message: 'Server error updating user wallet.', error: error.message });
    }
});

// Insert or update statistics for a campaign
app.post('/api/admin/statistics', adminAuthMiddleware, async (req, res) => {
    try {
        const { campaignId, date, impressions, clicks, conversions, spend } = req.body;

        // Validation
        if (!campaignId || !date) {
            return res.status(400).json({ message: 'Campaign ID and date are required.' });
        }

        const parsedImpressions = impressions ? parseInt(impressions) : 0;
        const parsedClicks = clicks ? parseInt(clicks) : 0;
        const parsedConversions = conversions ? parseInt(conversions) : 0;
        const parsedSpend = spend ? parseFloat(spend) : 0;

        // Calculate derived metrics
        const ctr = parsedImpressions > 0 ? (parsedClicks / parsedImpressions) * 100 : 0;
        const cpc = parsedClicks > 0 ? parsedSpend / parsedClicks : 0;
        const cpm = parsedImpressions > 0 ? (parsedSpend / parsedImpressions) * 1000 : 0;

        // Check if statistics already exist for this campaign and date
        const existingStats = await Statistics.findOne({ campaignId, date: new Date(date) });

        if (existingStats) {
            // Update existing
            existingStats.impressions = parsedImpressions;
            existingStats.clicks = parsedClicks;
            existingStats.conversions = parsedConversions;
            existingStats.spend = parsedSpend;
            existingStats.ctr = ctr;
            existingStats.cpc = cpc;
            existingStats.cpm = cpm;
            await existingStats.save();
            res.status(200).json({ message: 'Statistics updated successfully.', statistics: existingStats });
        } else {
            // Create new
            const newStats = new Statistics({
                campaignId,
                date: new Date(date),
                impressions: parsedImpressions,
                clicks: parsedClicks,
                conversions: parsedConversions,
                spend: parsedSpend,
                ctr,
                cpc,
                cpm
            });
            const savedStats = await newStats.save();
            res.status(201).json({ message: 'Statistics created successfully.', statistics: savedStats });
        }
    } catch (error) {
        console.error('Insert/update statistics error:', error);
        res.status(500).json({ message: 'Server error managing statistics.', error: error.message });
    }
});

// Get statistics for user's campaigns
app.get('/api/statistics', authMiddleware, async (req, res) => {
    try {
        // Get user's campaigns first
        const campaigns = await Campaign.find({ userId: req.user.id }).select('_id name');
        const campaignIds = campaigns.map(c => c._id);

        // Get statistics for these campaigns
        const statistics = await Statistics.find({ campaignId: { $in: campaignIds } })
            .populate('campaignId', 'name')
            .sort({ date: -1 });

        res.status(200).json({ statistics, campaigns });
    } catch (error) {
        console.error('Fetch statistics error:', error);
        res.status(500).json({ message: 'Server error fetching statistics.', error: error.message });
    }
});


// Start the server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

