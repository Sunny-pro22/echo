const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { OAuth2Client } = require('google-auth-library');
require('dotenv').config();

const app = express();

// CORS configuration
app.use(cors({
  origin: ['http://localhost:8081', 'http://localhost:5000', 'http://localhost:3000', 'http://192.168.1.100:8081'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/echobiz', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("✅ MongoDB connected successfully"))
.catch((err) => {
  console.error("❌ MongoDB connection error:", err);
  process.exit(1);
});

// User Schema
const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    unique: true, 
    sparse: true,
    trim: true 
  },
  email: { 
    type: String, 
    required: true, 
    unique: true,
    lowercase: true,
    trim: true 
  },
  password: { 
    type: String,
    minlength: 6 
  },
  googleId: { 
    type: String, 
    unique: true, 
    sparse: true 
  },
  businessName: { 
    type: String, 
    required: true,
    trim: true 
  },
  phone: { 
    type: String,
    trim: true 
  },
  name: { 
    type: String,
    trim: true 
  },
  photo: String,
  language: { 
    type: String, 
    default: 'en',
    enum: ['en', 'hi'] 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  updatedAt: { 
    type: Date, 
    default: Date.now 
  }
});

// Inventory Item Schema
const inventoryItemSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  name: { 
    type: String, 
    required: true,
    trim: true 
  },
  category: {
    type: String,
    enum: ['general', 'grocery', 'dairy', 'stationery', 'electronics', 'clothing', 'other'],
    default: 'general'
  },
  unit: {
    type: String,
    enum: ['kg', 'g', 'liter', 'ml', 'piece', 'packet', 'dozen', 'box', 'other'],
    default: 'kg'
  },
  cost: { 
    type: Number, 
    required: true,
    min: 0 
  },
  price: { 
    type: Number, 
    required: true,
    min: 0 
  },
  quantity: { 
    type: Number, 
    required: true,
    min: 0 
  },
  minStock: {
    type: Number,
    default: 10
  },
  profit: { 
    type: Number, 
    required: true 
  },
  profitMargin: {
    type: Number,
    required: true
  },
  totalValue: { 
    type: Number, 
    required: true 
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  updatedAt: { 
    type: Date, 
    default: Date.now 
  }
});

// Sales Schema
const saleSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  saleNumber: {
    type: String,
    unique: true,
    sparse: true
  },
  itemId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'InventoryItem', 
    required: true 
  },
  itemName: { 
    type: String, 
    required: true 
  },
  quantity: { 
    type: Number, 
    required: true,
    min: 1 
  },
  unitPrice: { 
    type: Number, 
    required: true 
  },
  totalAmount: { 
    type: Number, 
    required: true 
  },
  profit: { 
    type: Number, 
    required: true 
  },
  cost: { 
    type: Number, 
    required: true 
  },
  paymentMethod: {
    type: String,
    enum: ['cash', 'card', 'upi', 'credit', 'other'],
    default: 'cash'
  },
  customer: {
    name: String,
    phone: String
  },
  status: {
    type: String,
    enum: ['completed', 'pending', 'cancelled'],
    default: 'completed'
  },
  date: { 
    type: Date, 
    default: Date.now,
    index: true 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
});

// Expense Schema
const expenseSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  description: { 
    type: String, 
    required: true,
    trim: true 
  },
  amount: { 
    type: Number, 
    required: true,
    min: 0 
  },
  category: { 
    type: String, 
    enum: ['inventory', 'rent', 'salary', 'utilities', 'supplies', 'maintenance', 'other'], 
    default: 'other' 
  },
  date: { 
    type: Date, 
    default: Date.now,
    index: true 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
});

// Voice Command Log Schema
const voiceCommandSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  command: {
    type: String,
    required: true
  },
  language: {
    type: String,
    default: 'en'
  },
  productName: String,
  quantity: Number,
  success: {
    type: Boolean,
    default: false
  },
  error: String,
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
});

// Create models
const User = mongoose.model('User', userSchema);
const InventoryItem = mongoose.model('InventoryItem', inventoryItemSchema);
const Sale = mongoose.model('Sale', saleSchema);
const Expense = mongoose.model('Expense', expenseSchema);
const VoiceCommand = mongoose.model('VoiceCommand', voiceCommandSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'echobiz-secret-key-2024-change-in-production';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;

const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

// Authentication Middleware
const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.header('Authorization');
    if (!authHeader) {
      return res.status(401).json({ 
        success: false,
        error: 'No token provided' 
      });
    }
    
    const token = authHeader.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid token format' 
      });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ 
        success: false,
        error: 'User not found' 
      });
    }
    
    req.user = user;
    req.userId = user._id;
    req.token = token;
    next();
  } catch (error) {
    console.error('Auth error:', error.message);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid token' 
      });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false,
        error: 'Token expired' 
      });
    }
    
    res.status(401).json({ 
      success: false,
      error: 'Authentication failed' 
    });
  }
};

// Generate Sale Number
const generateSaleNumber = async (userId) => {
  const count = await Sale.countDocuments({ userId });
  const date = new Date();
  const year = date.getFullYear().toString().slice(-2);
  const month = (date.getMonth() + 1).toString().padStart(2, '0');
  const day = date.getDate().toString().padStart(2, '0');
  return `SALE${year}${month}${day}${(count + 1).toString().padStart(4, '0')}`;
};

// ==================== USER ROUTES ====================

// User Registration
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, businessName, phone, name } = req.body;
    
    if (!email || !password || !businessName) {
      return res.status(400).json({ 
        success: false,
        error: 'Email, password, and business name are required' 
      });
    }
    
    const existingUser = await User.findOne({ 
      $or: [{ email: email.toLowerCase() }, { username }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ 
        success: false,
        error: 'User with this email or username already exists' 
      });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = new User({
      username: username || email.split('@')[0],
      email: email.toLowerCase(),
      password: hashedPassword,
      businessName,
      phone,
      name: name || username || email.split('@')[0]
    });
    
    await user.save();
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
    
    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        businessName: user.businessName,
        name: user.name,
        phone: user.phone,
        language: user.language
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
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Email and password are required' 
      });
    }
    
    const user = await User.findOne({ email: email.toLowerCase() });
    
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
    
    user.updatedAt = new Date();
    await user.save();
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
    
    res.json({
      success: true,
      message: 'Login successful',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        businessName: user.businessName,
        name: user.name,
        photo: user.photo,
        language: user.language
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
      if (googleClient) {
        const ticket = await googleClient.verifyIdToken({
          idToken,
          audience: GOOGLE_CLIENT_ID
        });
        
        const payload = ticket.getPayload();
        const googleId = payload['sub'];
        
        let user = await User.findOne({ 
          $or: [{ googleId }, { email: email.toLowerCase() }] 
        });
        
        if (!user) {
          user = new User({
            googleId,
            email: email.toLowerCase(),
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
        
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
        
        res.json({
          success: true,
          message: 'Google login successful',
          user: {
            id: user._id,
            username: user.username,
            email: user.email,
            businessName: user.businessName,
            name: user.name,
            photo: user.photo,
            language: user.language
          },
          token
        });
      } else {
        throw new Error('Google client not configured');
      }
    } catch (googleError) {
      console.error('Google verification error:', googleError);
      
      let user = await User.findOne({ email: email.toLowerCase() });
      
      if (!user) {
        user = new User({
          email: email.toLowerCase(),
          name: name || email.split('@')[0],
          photo,
          businessName: name || email.split('@')[0],
          username: email.split('@')[0]
        });
        await user.save();
      }
      
      const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
      
      res.json({
        success: true,
        message: 'Google login successful (development mode)',
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          businessName: user.businessName,
          name: user.name,
          photo: user.photo,
          language: user.language
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

// Update user language
app.put('/api/user/language', authMiddleware, async (req, res) => {
  try {
    const { language } = req.body;
    
    if (!['en', 'hi'].includes(language)) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid language. Use "en" or "hi"' 
      });
    }
    
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { language, updatedAt: new Date() },
      { new: true, select: '-password -googleId' }
    );
    
    res.json({
      success: true,
      message: 'Language updated successfully',
      user
    });
  } catch (error) {
    console.error('Update language error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to update language' 
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

// ==================== VOICE SALES ROUTES ====================

// Process voice sale command
app.post('/api/voice/sell', authMiddleware, async (req, res) => {
  try {
    const { command, language } = req.body;
    
    if (!command) {
      return res.status(400).json({ 
        success: false,
        error: 'Voice command is required' 
      });
    }
    
    // Log the voice command
    const voiceLog = new VoiceCommand({
      userId: req.user._id,
      command,
      language: language || req.user.language || 'en'
    });
    
    // Parse the voice command
    const parsedCommand = parseVoiceCommand(command, language || req.user.language || 'en');
    
    voiceLog.productName = parsedCommand.productName;
    voiceLog.quantity = parsedCommand.quantity;
    
    // Find the product in inventory
    const item = await InventoryItem.findOne({
      userId: req.user._id,
      name: { $regex: new RegExp(parsedCommand.productName, 'i') },
      isActive: true
    });
    
    if (!item) {
      voiceLog.success = false;
      voiceLog.error = `Product "${parsedCommand.productName}" not found`;
      await voiceLog.save();
      
      return res.status(404).json({
        success: false,
        error: `Product "${parsedCommand.productName}" not found in inventory`,
        suggestions: await getSimilarProducts(req.user._id, parsedCommand.productName)
      });
    }
    
    // Check if enough stock is available
    if (item.quantity < parsedCommand.quantity) {
      voiceLog.success = false;
      voiceLog.error = `Insufficient stock. Only ${item.quantity} units available`;
      await voiceLog.save();
      
      return res.status(400).json({
        success: false,
        error: `Insufficient stock. Only ${item.quantity} ${item.unit} available`,
        availableQuantity: item.quantity
      });
    }
    
    // Calculate sale details
    const totalAmount = item.price * parsedCommand.quantity;
    const totalCost = item.cost * parsedCommand.quantity;
    const profit = totalAmount - totalCost;
    
    // Generate sale number
    const saleNumber = await generateSaleNumber(req.user._id);
    
    // Create sale record
    const sale = new Sale({
      userId: req.user._id,
      saleNumber,
      itemId: item._id,
      itemName: item.name,
      quantity: parsedCommand.quantity,
      unitPrice: item.price,
      totalAmount,
      profit,
      cost: totalCost,
      paymentMethod: 'cash',
      status: 'completed',
      date: new Date()
    });
    
    await sale.save();
    
    // Update inventory quantity
    item.quantity -= parsedCommand.quantity;
    item.updatedAt = new Date();
    await item.save();
    
    // Log successful voice command
    voiceLog.success = true;
    await voiceLog.save();
    
    // Prepare response
    const response = {
      success: true,
      message: 'Sale processed successfully',
      sale: {
        id: sale._id,
        saleNumber: sale.saleNumber,
        itemName: sale.itemName,
        quantity: sale.quantity,
        unitPrice: sale.unitPrice,
        totalAmount: sale.totalAmount,
        profit: sale.profit,
        date: sale.date
      },
      remainingStock: item.quantity,
      voiceMessage: getVoiceMessage(language || req.user.language || 'en', {
        itemName: item.name,
        quantity: parsedCommand.quantity,
        totalAmount,
        profit,
        remainingStock: item.quantity
      })
    };
    
    res.json(response);
    
  } catch (error) {
    console.error('Voice sale error:', error);
    
    // Log the error
    const voiceLog = new VoiceCommand({
      userId: req.user._id,
      command: req.body.command,
      language: req.body.language || req.user.language || 'en',
      success: false,
      error: error.message
    });
    await voiceLog.save();
    
    res.status(500).json({ 
      success: false,
      error: 'Failed to process voice sale',
      details: error.message
    });
  }
});

// Helper function to parse voice command
function parseVoiceCommand(command, language = 'en') {
  const lowerCommand = command.toLowerCase();
  
  // Common product mappings
  const productMappings = {
    'sugar': ['sugar', 'chini', 'शुगर', 'चीनी', 'shakkar', 'शक्कर'],
    'rice': ['rice', 'chawal', 'चावल', 'चावल', 'rice'],
    'wheat flour': ['atta', 'flour', 'आटा', 'गेहूं का आटा', 'wheat flour', 'मैदा'],
    'lentils': ['dal', 'दाल', 'lentils', 'pulses', 'डाल'],
    'cooking oil': ['oil', 'tel', 'तेल', 'cooking oil', 'रिफाइंड ऑयल'],
    'milk': ['milk', 'doodh', 'दूध', 'milk'],
    'tea': ['tea', 'chai', 'चाय', 'tea'],
    'coffee': ['coffee', 'कॉफी', 'coffee'],
    'salt': ['salt', 'namak', 'नमक', 'salt'],
    'spices': ['spices', 'masala', 'मसाला', 'spices'],
    'soap': ['soap', 'साबुन', 'soap'],
    'shampoo': ['shampoo', 'शैम्पू', 'shampoo'],
    'toothpaste': ['toothpaste', 'टूथपेस्ट', 'toothpaste'],
    'biscuits': ['biscuits', 'बिस्कुट', 'cookies', 'बिस्किट']
  };
  
  // Extract quantity
  let quantity = 1;
  const quantityRegex = /(\d+(\.\d+)?)\s*(kg|kilo|kilogram|kgs|g|gram|gm|units?|pieces?|pcs?)?/i;
  const quantityMatch = lowerCommand.match(quantityRegex);
  if (quantityMatch) {
    quantity = parseFloat(quantityMatch[1]);
  }
  
  // Handle Indian measurements
  if (lowerCommand.includes('aadha') || lowerCommand.includes('आधा') || lowerCommand.includes('half')) {
    quantity = 0.5;
  } else if (lowerCommand.includes('paav') || lowerCommand.includes('पाव') || lowerCommand.includes('quarter')) {
    quantity = 0.25;
  } else if (lowerCommand.includes('ser') || lowerCommand.includes('सेर')) {
    quantity = quantity * 0.933;
  }
  
  // Find product name
  let productName = '';
  for (const [englishName, variants] of Object.entries(productMappings)) {
    for (const variant of variants) {
      if (lowerCommand.includes(variant.toLowerCase())) {
        productName = englishName;
        break;
      }
    }
    if (productName) break;
  }
  
  // If product not found in mappings, try to extract from command
  if (!productName) {
    const words = lowerCommand.split(/\s+/);
    for (const word of words) {
      if (word.length > 3 && !isNumeric(word) && 
          !['kg', 'kilo', 'kilogram', 'g', 'gram', 'unit', 'units', 'piece', 'pieces'].includes(word)) {
        productName = word.charAt(0).toUpperCase() + word.slice(1);
        break;
      }
    }
  }
  
  return {
    productName: productName || 'Unknown Product',
    quantity: quantity || 1
  };
}

// Helper function to get similar products
async function getSimilarProducts(userId, productName) {
  try {
    const items = await InventoryItem.find({
      userId,
      isActive: true,
      $or: [
        { name: { $regex: productName, $options: 'i' } },
        { name: { $regex: productName.split(' ')[0], $options: 'i' } }
      ]
    }).limit(5);
    
    return items.map(item => item.name);
  } catch (error) {
    return [];
  }
}

// Helper function to get voice message
function getVoiceMessage(language, data) {
  if (language === 'hi') {
    return `${data.quantity} ${getUnitText(data.quantity)} ${data.itemName} बेचा गया। कुल राशि: ₹${data.totalAmount}। लाभ: ₹${data.profit}। शेष स्टॉक: ${data.remainingStock} ${getUnitText(data.remainingStock)}।`;
  } else {
    return `Sold ${data.quantity} ${data.quantity === 1 ? 'unit' : 'units'} of ${data.itemName}. Total amount: ₹${data.totalAmount}. Profit: ₹${data.profit}. Remaining stock: ${data.remainingStock} ${data.remainingStock === 1 ? 'unit' : 'units'}.`;
  }
}

// Helper function to get unit text in Hindi
function getUnitText(quantity) {
  if (quantity === 1 || quantity === 0.5 || quantity === 0.25) {
    return 'किलो';
  }
  return 'किलो';
}

function isNumeric(str) {
  return /^\d+$/.test(str);
}

// ==================== INVENTORY ROUTES ====================

// Get all inventory items
app.get('/api/inventory', authMiddleware, async (req, res) => {
  try {
    const { search, category, lowStock } = req.query;
    
    let query = { userId: req.user._id, isActive: true };
    
    if (search) {
      query.name = { $regex: search, $options: 'i' };
    }
    
    if (category && category !== 'all') {
      query.category = category;
    }
    
    if (lowStock === 'true') {
      query.quantity = { $lt: 10 };
    }
    
    const items = await InventoryItem.find(query).sort({ createdAt: -1 });
    
    res.json({
      success: true,
      items,
      count: items.length
    });
  } catch (error) {
    console.error('Get inventory error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch inventory' 
    });
  }
});

// Get single inventory item
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

// Add new inventory item
app.post('/api/inventory', authMiddleware, async (req, res) => {
  try {
    const { name, cost, price, quantity, category, unit, minStock } = req.body;
    
    if (!name || cost === undefined || price === undefined || quantity === undefined) {
      return res.status(400).json({ 
        success: false,
        error: 'Name, cost, price, and quantity are required' 
      });
    }
    
    const profit = price - cost;
    const profitMargin = cost > 0 ? ((profit / cost) * 100).toFixed(2) : 0;
    const totalValue = cost * quantity;
    
    const item = new InventoryItem({
      userId: req.user._id,
      name,
      cost: parseFloat(cost),
      price: parseFloat(price),
      quantity: parseInt(quantity),
      category: category || 'general',
      unit: unit || 'kg',
      minStock: minStock || 10,
      profit,
      profitMargin,
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

// Update inventory item
app.put('/api/inventory/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    
    const existingItem = await InventoryItem.findOne({ 
      _id: id, 
      userId: req.user._id 
    });
    
    if (!existingItem) {
      return res.status(404).json({ 
        success: false,
        error: 'Item not found' 
      });
    }
    
    // Calculate profit if cost or price is updated
    if (updates.cost !== undefined || updates.price !== undefined) {
      const newCost = updates.cost !== undefined ? updates.cost : existingItem.cost;
      const newPrice = updates.price !== undefined ? updates.price : existingItem.price;
      updates.profit = newPrice - newCost;
      updates.profitMargin = newCost > 0 ? ((updates.profit / newCost) * 100).toFixed(2) : 0;
    }
    
    // Calculate total value if cost or quantity is updated
    if (updates.cost !== undefined || updates.quantity !== undefined) {
      const newCost = updates.cost !== undefined ? updates.cost : existingItem.cost;
      const newQuantity = updates.quantity !== undefined ? updates.quantity : existingItem.quantity;
      updates.totalValue = newCost * newQuantity;
    }
    
    updates.updatedAt = new Date();
    
    const item = await InventoryItem.findOneAndUpdate(
      { _id: id, userId: req.user._id },
      updates,
      { new: true }
    );
    
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

// Delete inventory item
app.delete('/api/inventory/:id', authMiddleware, async (req, res) => {
  try {
    const item = await InventoryItem.findOneAndDelete({
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

// Quick sell item (direct API, not via voice)
app.post('/api/inventory/:id/sell', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { quantity, customerName, customerPhone, paymentMethod } = req.body;
    
    if (!quantity || quantity <= 0) {
      return res.status(400).json({ 
        success: false,
        error: 'Valid quantity is required' 
      });
    }
    
    const item = await InventoryItem.findOne({
      _id: id,
      userId: req.user._id,
      isActive: true
    });
    
    if (!item) {
      return res.status(404).json({ 
        success: false,
        error: 'Item not found' 
      });
    }
    
    if (item.quantity < quantity) {
      return res.status(400).json({
        success: false,
        error: `Insufficient stock. Only ${item.quantity} units available`
      });
    }
    
    // Calculate sale details
    const totalAmount = item.price * quantity;
    const totalCost = item.cost * quantity;
    const profit = totalAmount - totalCost;
    
    // Generate sale number
    const saleNumber = await generateSaleNumber(req.user._id);
    
    // Create sale record
    const sale = new Sale({
      userId: req.user._id,
      saleNumber,
      itemId: item._id,
      itemName: item.name,
      quantity,
      unitPrice: item.price,
      totalAmount,
      profit,
      cost: totalCost,
      paymentMethod: paymentMethod || 'cash',
      customer: {
        name: customerName,
        phone: customerPhone
      },
      status: 'completed',
      date: new Date()
    });
    
    await sale.save();
    
    // Update inventory quantity
    item.quantity -= quantity;
    item.updatedAt = new Date();
    await item.save();
    
    res.json({
      success: true,
      message: 'Sale completed successfully',
      sale,
      remainingStock: item.quantity
    });
  } catch (error) {
    console.error('Quick sell error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to process sale' 
    });
  }
});

// ==================== SALES ROUTES ====================

// Get all sales
app.get('/api/sales', authMiddleware, async (req, res) => {
  try {
    const { startDate, endDate, itemId } = req.query;
    
    let query = { userId: req.user._id };
    
    if (startDate && endDate) {
      query.date = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }
    
    if (itemId) {
      query.itemId = itemId;
    }
    
    const sales = await Sale.find(query)
      .sort({ date: -1 })
      .populate('itemId', 'name category');
    
    const totalSales = sales.reduce((sum, sale) => sum + sale.totalAmount, 0);
    const totalProfit = sales.reduce((sum, sale) => sum + sale.profit, 0);
    
    res.json({
      success: true,
      sales,
      stats: {
        totalSales,
        totalProfit,
        count: sales.length
      }
    });
  } catch (error) {
    console.error('Get sales error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch sales' 
    });
  }
});

// Get sales summary
app.get('/api/sales/summary', authMiddleware, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);
    
    const thisMonth = new Date(today.getFullYear(), today.getMonth(), 1);
    const lastMonth = new Date(today.getFullYear(), today.getMonth() - 1, 1);
    
    const [todaySales, yesterdaySales, thisMonthSales, lastMonthSales] = await Promise.all([
      Sale.aggregate([
        { $match: { userId: req.user._id, date: { $gte: today } } },
        { $group: { _id: null, total: { $sum: "$totalAmount" }, profit: { $sum: "$profit" } } }
      ]),
      Sale.aggregate([
        { $match: { userId: req.user._id, date: { $gte: yesterday, $lt: today } } },
        { $group: { _id: null, total: { $sum: "$totalAmount" }, profit: { $sum: "$profit" } } }
      ]),
      Sale.aggregate([
        { $match: { userId: req.user._id, date: { $gte: thisMonth } } },
        { $group: { _id: null, total: { $sum: "$totalAmount" }, profit: { $sum: "$profit" } } }
      ]),
      Sale.aggregate([
        { $match: { userId: req.user._id, date: { $gte: lastMonth, $lt: thisMonth } } },
        { $group: { _id: null, total: { $sum: "$totalAmount" }, profit: { $sum: "$profit" } } }
      ])
    ]);
    
    res.json({
      success: true,
      summary: {
        today: {
          total: todaySales[0]?.total || 0,
          profit: todaySales[0]?.profit || 0
        },
        yesterday: {
          total: yesterdaySales[0]?.total || 0,
          profit: yesterdaySales[0]?.profit || 0
        },
        thisMonth: {
          total: thisMonthSales[0]?.total || 0,
          profit: thisMonthSales[0]?.profit || 0
        },
        lastMonth: {
          total: lastMonthSales[0]?.total || 0,
          profit: lastMonthSales[0]?.profit || 0
        }
      }
    });
  } catch (error) {
    console.error('Sales summary error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch sales summary' 
    });
  }
});

// ==================== EXPENSES ROUTES ====================

// Add expense
app.post('/api/expenses', authMiddleware, async (req, res) => {
  try {
    const { description, amount, category } = req.body;
    
    if (!description || amount === undefined) {
      return res.status(400).json({ 
        success: false,
        error: 'Description and amount are required' 
      });
    }
    
    const expense = new Expense({
      userId: req.user._id,
      description,
      amount: parseFloat(amount),
      category: category || 'other',
      date: new Date()
    });
    
    await expense.save();
    
    res.status(201).json({
      success: true,
      message: 'Expense recorded successfully',
      expense
    });
  } catch (error) {
    console.error('Record expense error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to record expense' 
    });
  }
});

// Get expenses
app.get('/api/expenses', authMiddleware, async (req, res) => {
  try {
    const { startDate, endDate, category } = req.query;
    
    let query = { userId: req.user._id };
    
    if (startDate && endDate) {
      query.date = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }
    
    if (category && category !== 'all') {
      query.category = category;
    }
    
    const expenses = await Expense.find(query).sort({ date: -1 });
    
    const totalExpenses = expenses.reduce((sum, expense) => sum + expense.amount, 0);
    
    res.json({
      success: true,
      expenses,
      totalExpenses,
      count: expenses.length
    });
  } catch (error) {
    console.error('Get expenses error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch expenses' 
    });
  }
});

// ==================== DASHBOARD STATS ====================

app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
  try {
    const [items, sales, expenses] = await Promise.all([
      InventoryItem.find({ userId: req.user._id, isActive: true }),
      Sale.find({ userId: req.user._id }),
      Expense.find({ userId: req.user._id })
    ]);
    
    // Inventory stats
    const totalInventoryValue = items.reduce((sum, item) => sum + (item.cost * item.quantity), 0);
    const totalPotentialProfit = items.reduce((sum, item) => sum + (item.profit * item.quantity), 0);
    const totalItems = items.length;
    const lowStockItems = items.filter(item => item.quantity < item.minStock).length;
    
    // Sales stats
    const totalSales = sales.reduce((sum, sale) => sum + sale.totalAmount, 0);
    const totalProfitFromSales = sales.reduce((sum, sale) => sum + sale.profit, 0);
    
    // Expense stats
    const totalExpenses = expenses.reduce((sum, expense) => sum + expense.amount, 0);
    const inventoryExpenses = expenses
      .filter(e => e.category === 'inventory')
      .reduce((sum, expense) => sum + expense.amount, 0);
    
    // Calculate net profit
    const nonInventoryExpenses = totalExpenses - inventoryExpenses;
    const netProfit = totalProfitFromSales - nonInventoryExpenses;
    
    // Monthly stats
    const now = new Date();
    const currentMonth = now.getMonth();
    const currentYear = now.getFullYear();
    
    const monthlySales = sales
      .filter(sale => {
        const saleDate = new Date(sale.date);
        return saleDate.getMonth() === currentMonth && saleDate.getFullYear() === currentYear;
      })
      .reduce((sum, sale) => sum + sale.totalAmount, 0);
    
    const monthlyExpenses = expenses
      .filter(expense => {
        const expenseDate = new Date(expense.date);
        return expenseDate.getMonth() === currentMonth && expenseDate.getFullYear() === currentYear;
      })
      .reduce((sum, expense) => sum + expense.amount, 0);
    
    const monthlyProfit = monthlySales - monthlyExpenses;
    
    // Today's stats
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const todaySales = sales
      .filter(sale => new Date(sale.date) >= today)
      .reduce((sum, sale) => sum + sale.totalAmount, 0);
    
    const todayProfit = sales
      .filter(sale => new Date(sale.date) >= today)
      .reduce((sum, sale) => sum + sale.profit, 0);
    
    res.json({
      success: true,
      stats: {
        // Inventory
        totalItems,
        totalInventoryValue,
        totalPotentialProfit,
        lowStockItems,
        
        // Financial
        totalSales,
        totalProfitFromSales,
        totalExpenses,
        netProfit,
        
        // Monthly
        monthlySales,
        monthlyExpenses,
        monthlyProfit,
        
        // Today
        todaySales,
        todayProfit,
        
        // Business health
        profitMargin: totalSales > 0 ? (totalProfitFromSales / totalSales) * 100 : 0,
        expenseRatio: totalSales > 0 ? (totalExpenses / totalSales) * 100 : 0
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

// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
  res.json({ 
    success: true,
    status: 'OK', 
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// ==================== START SERVER ====================

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📡 API Base URL: http://localhost:${PORT}`);
  console.log(`✅ Health check: http://localhost:${PORT}/api/health`);
  console.log(`🎤 Voice Sales API: POST http://localhost:${PORT}/api/voice/sell`);
});