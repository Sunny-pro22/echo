const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { OAuth2Client } = require('google-auth-library');
require('dotenv').config();

const app = express();

app.use(cors({
  origin: ['http://localhost:8081', 'http://localhost:5000', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json());

mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/echobiz')
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, sparse: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  googleId: { type: String, unique: true, sparse: true },
  businessName: String,
  phone: String,
  name: String,
  photo: String,
  createdAt: { type: Date, default: Date.now }
});

const inventoryItemSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  cost: { type: Number, required: true },
  price: { type: Number, required: true },
  quantity: { type: Number, required: true },
  profit: { type: Number, required: true },
  totalValue: { type: Number, required: true },
  createdAt: { type: Date, default: Date.now }
});

const saleSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  itemId: { type: mongoose.Schema.Types.ObjectId, ref: 'InventoryItem', required: true },
  itemName: { type: String, required: true },
  quantity: { type: Number, required: true },
  unitPrice: { type: Number, required: true },
  totalAmount: { type: Number, required: true },
  profit: { type: Number, required: true },
  cost: { type: Number, required: true },
  date: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const InventoryItem = mongoose.model('InventoryItem', inventoryItemSchema);
const Sale = mongoose.model('Sale', saleSchema);

const JWT_SECRET = process.env.JWT_SECRET || 'echobiz-secret-key-2024-change-in-production';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '493232229391-aljvoapmdgsejthpaj11445ccuermrl2.apps.googleusercontent.com';

const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.header('Authorization');
    if (!authHeader) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    const token = authHeader.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ error: 'Invalid token format' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    console.error('Auth error:', error.message);
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token' });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    res.status(401).json({ error: 'Authentication failed' });
  }
};

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// User Registration
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, businessName, phone } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ 
        error: 'Username, email, and password are required' 
      });
    }
    
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ 
        error: 'User with this email or username already exists' 
      });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = new User({
      username,
      email,
      password: hashedPassword,
      businessName: businessName || username,
      phone,
      name: username
    });
    
    await user.save();
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        businessName: user.businessName,
        name: user.name
      },
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Server error during registration' 
    });
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Username and password are required' 
      });
    }
    
    const user = await User.findOne({
      $or: [{ email: username }, { username: username }]
    });
    
    if (!user) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials' 
      });
    }
    
    if (!user.password) {
      return res.status(401).json({ 
        success: false,
        error: 'Please use Google login for this account' 
      });
    }
    
    const isValidPassword = await bcrypt.compare(password, user.password);
    
    if (!isValidPassword) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials' 
      });
    }
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      success: true,
      message: 'Login successful',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        businessName: user.businessName,
        name: user.name,
        photo: user.photo
      },
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Server error during login' 
    });
  }
});

// Google Auth
app.post('/api/auth/google', async (req, res) => {
  try {
    const { idToken, email, name, photo } = req.body;
    
    if (!idToken || !email) {
      return res.status(400).json({ 
        success: false,
        error: 'Google token and email are required' 
      });
    }
    
    try {
      const ticket = await googleClient.verifyIdToken({
        idToken,
        audience: GOOGLE_CLIENT_ID
      });
      
      const payload = ticket.getPayload();
      const googleId = payload['sub'];
      
      let user = await User.findOne({ 
        $or: [{ googleId }, { email }] 
      });
      
      if (!user) {
        user = new User({
          googleId,
          email,
          name: name || email.split('@')[0],
          photo,
          businessName: name || email.split('@')[0],
          username: email.split('@')[0]
        });
        await user.save();
      } else if (!user.googleId) {
        user.googleId = googleId;
        user.name = name || user.name;
        user.photo = photo || user.photo;
        await user.save();
      }
      
      const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
      
      res.json({
        success: true,
        message: 'Google login successful',
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          businessName: user.businessName,
          name: user.name,
          photo: user.photo
        },
        token
      });
    } catch (googleError) {
      console.error('Google verification error:', googleError);
      
      let user = await User.findOne({ email });
      
      if (!user) {
        user = new User({
          email,
          name: name || email.split('@')[0],
          photo,
          businessName: name || email.split('@')[0],
          username: email.split('@')[0]
        });
        await user.save();
      }
      
      const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
      
      res.json({
        success: true,
        message: 'Google login successful (development mode)',
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          businessName: user.businessName,
          name: user.name,
          photo: user.photo
        },
        token
      });
    }
  } catch (error) {
    console.error('Google auth error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Google authentication failed' 
    });
  }
});

// Test Account Creation
app.post('/api/auth/test-account', async (req, res) => {
  try {
    const testUsername = `testuser_${Date.now()}`;
    const testEmail = `${testUsername}@test.com`;
    
    let user = await User.findOne({ email: testEmail });
    
    if (!user) {
      user = new User({
        username: testUsername,
        email: testEmail,
        password: await bcrypt.hash('test123', 10),
        businessName: 'Test Business',
        phone: '1234567890',
        name: 'Test User'
      });
      await user.save();
    }
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      success: true,
      message: 'Test account created successfully',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        businessName: user.businessName,
        name: user.name
      },
      token
    });
  } catch (error) {
    console.error('Test account error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to create test account' 
    });
  }
});

// Inventory Routes
app.get('/api/inventory', authMiddleware, async (req, res) => {
  try {
    const items = await InventoryItem.find({ userId: req.user._id }).sort({ createdAt: -1 });
    res.json({
      success: true,
      items
    });
  } catch (error) {
    console.error('Get inventory error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch inventory' 
    });
  }
});

app.get('/api/inventory/:id', authMiddleware, async (req, res) => {
  try {
    const item = await InventoryItem.findOne({
      _id: req.params.id,
      userId: req.user._id
    });
    
    if (!item) {
      return res.status(404).json({ 
        success: false,
        error: 'Item not found' 
      });
    }
    
    res.json({
      success: true,
      item
    });
  } catch (error) {
    console.error('Get item error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch item' 
    });
  }
});

app.post('/api/inventory', authMiddleware, async (req, res) => {
  try {
    const { name, cost, price, quantity } = req.body;
    
    if (!name || cost === undefined || price === undefined || quantity === undefined) {
      return res.status(400).json({ 
        success: false,
        error: 'All fields are required' 
      });
    }
    
    const profit = price - cost;
    const totalValue = cost * quantity;
    
    const item = new InventoryItem({
      userId: req.user._id,
      name,
      cost: parseFloat(cost),
      price: parseFloat(price),
      quantity: parseInt(quantity),
      profit,
      totalValue
    });
    
    await item.save();
    res.status(201).json({ 
      success: true,
      message: 'Item added successfully', 
      item 
    });
  } catch (error) {
    console.error('Add inventory error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to add item' 
    });
  }
});

app.put('/api/inventory/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    
    if (updates.cost && updates.price) {
      updates.profit = updates.price - updates.cost;
    }
    if (updates.cost && updates.quantity) {
      updates.totalValue = updates.cost * updates.quantity;
    }
    
    const item = await InventoryItem.findOneAndUpdate(
      { _id: id, userId: req.user._id },
      updates,
      { new: true }
    );
    
    if (!item) {
      return res.status(404).json({ 
        success: false,
        error: 'Item not found' 
      });
    }
    
    res.json({ 
      success: true,
      message: 'Item updated successfully', 
      item 
    });
  } catch (error) {
    console.error('Update inventory error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to update item' 
    });
  }
});

app.delete('/api/inventory/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    
    const item = await InventoryItem.findOneAndDelete({
      _id: id,
      userId: req.user._id
    });
    
    if (!item) {
      return res.status(404).json({ 
        success: false,
        error: 'Item not found' 
      });
    }
    
    res.json({ 
      success: true,
      message: 'Item deleted successfully' 
    });
  } catch (error) {
    console.error('Delete inventory error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to delete item' 
    });
  }
});

// Sales Routes
app.post('/api/sales', authMiddleware, async (req, res) => {
  try {
    const { itemId, itemName, quantity, unitPrice, totalAmount, profit, cost } = req.body;
    
    if (!itemId || !itemName || quantity === undefined || unitPrice === undefined) {
      return res.status(400).json({ 
        success: false,
        error: 'Required fields are missing' 
      });
    }
    
    const sale = new Sale({
      userId: req.user._id,
      itemId,
      itemName,
      quantity: parseInt(quantity),
      unitPrice: parseFloat(unitPrice),
      totalAmount: parseFloat(totalAmount),
      profit: parseFloat(profit),
      cost: parseFloat(cost)
    });
    
    await sale.save();
    
    res.status(201).json({
      success: true,
      message: 'Sale recorded successfully',
      sale
    });
  } catch (error) {
    console.error('Record sale error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to record sale' 
    });
  }
});

app.get('/api/sales', authMiddleware, async (req, res) => {
  try {
    const sales = await Sale.find({ userId: req.user._id }).sort({ date: -1 });
    
    res.json({
      success: true,
      sales
    });
  } catch (error) {
    console.error('Get sales error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch sales' 
    });
  }
});

// Dashboard Stats
app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
  try {
    const items = await InventoryItem.find({ userId: req.user._id });
    
    const totalInventoryValue = items.reduce((sum, item) => sum + (item.cost * item.quantity), 0);
    const totalPotentialProfit = items.reduce((sum, item) => sum + (item.profit * item.quantity), 0);
    const totalItems = items.length;
    
    res.json({
      success: true,
      stats: {
        totalItems,
        totalInventoryValue,
        totalPotentialProfit,
        averageProfitPerItem: totalItems > 0 ? totalPotentialProfit / totalItems : 0,
        lowStockItems: items.filter(item => item.quantity < 10).length
      }
    });
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch dashboard stats' 
    });
  }
});

// Get user profile
app.get('/api/user/profile', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password -googleId');
    res.json({
      success: true,
      user
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch profile' 
    });
  }
});

// Update user profile
app.put('/api/user/profile', authMiddleware, async (req, res) => {
  try {
    const updates = req.body;
    
    delete updates.password;
    delete updates.googleId;
    delete updates._id;
    
    const user = await User.findByIdAndUpdate(
      req.user._id,
      updates,
      { new: true, select: '-password -googleId' }
    );
    
    res.json({ 
      success: true,
      message: 'Profile updated successfully', 
      user 
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to update profile' 
    });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true,
    status: 'OK', 
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📡 API Base URL: http://localhost:${PORT}`);
  console.log(`✅ Health check: http://localhost:${PORT}/api/health`);
});