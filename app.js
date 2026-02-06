const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { OAuth2Client } = require('google-auth-library');
const { GoogleGenerativeAI } = require('@google/generative-ai');
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
  language: { type: String, default: 'en' }, // 'en' for English, 'hi' for Hindi
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

const expenseSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  description: { type: String, required: true },
  amount: { type: Number, required: true },
  category: { type: String, enum: ['inventory', 'rent', 'salary', 'utilities', 'other'], default: 'other' },
  date: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const InventoryItem = mongoose.model('InventoryItem', inventoryItemSchema);
const Sale = mongoose.model('Sale', saleSchema);
const Expense = mongoose.model('Expense', expenseSchema);

const JWT_SECRET = process.env.JWT_SECRET || 'echobiz-secret-key-2024-change-in-production';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || 'YOUR_GEMINI_API_KEY';

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
const genAI = GEMINI_API_KEY !== 'YOUR_GEMINI_API_KEY' ? new GoogleGenerativeAI(GEMINI_API_KEY) : null;

// Process voice command with Gemini AI
const processVoiceCommandWithGemini = async (command, language = 'en') => {
  if (!genAI) {
    throw new Error('Gemini API not configured');
  }

  const model = genAI.getGenerativeModel({ model: "gemini-pro" });
  
  const prompt = `Extract product name and quantity from this ${language === 'hi' ? 'Hindi/Hinglish' : 'English'} command: "${command}"
  
  Return ONLY a JSON object with this exact structure:
  {
    "productName": "extracted product name in English",
    "quantity": extracted number,
    "action": "sell" or "add" or "update"
  }
  
  Rules:
  1. Product name should be in English even if command is in Hindi
  2. If quantity is not specified, use 1
  3. Recognize common Indian product names: sugar, atta, rice, dal, oil, milk, etc.
  4. Convert words like "kilo", "kg", "kilogram" to number 1
  5. Convert "aadha kilo" to 0.5
  6. Convert "paav" to 0.25
  7. Recognize actions: "sold", "sell", "bik gaya" = "sell"; "added", "bought", "kharida" = "add"
  
  Example responses:
  Input: "sold 4 kg sugar" -> {"productName": "sugar", "quantity": 4, "action": "sell"}
  Input: "चीनी 4 किलो बेच दी" -> {"productName": "sugar", "quantity": 4, "action": "sell"}
  Input: "adda kilo chini" -> {"productName": "sugar", "quantity": 0.5, "action": "sell"}`;

  try {
    const result = await model.generateContent(prompt);
    const response = await result.response;
    const text = response.text();
    
    // Extract JSON from response
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }
    
    throw new Error('Failed to parse Gemini response');
  } catch (error) {
    console.error('Gemini API error:', error);
    throw error;
  }
};

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
          photo: user.photo,
          language: user.language
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
      { language },
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

// Process voice command
app.post('/api/voice/process', authMiddleware, async (req, res) => {
  try {
    const { command, language } = req.body;
    
    if (!command) {
      return res.status(400).json({ 
        success: false,
        error: 'Voice command is required' 
      });
    }
    
    let parsedCommand;
    
    if (genAI) {
      try {
        parsedCommand = await processVoiceCommandWithGemini(command, language || req.user.language || 'en');
      } catch (geminiError) {
        console.error('Gemini processing failed:', geminiError);
        // Fallback to simple parsing
        parsedCommand = parseVoiceCommandFallback(command, language || req.user.language || 'en');
      }
    } else {
      parsedCommand = parseVoiceCommandFallback(command, language || req.user.language || 'en');
    }
    
    // Find the product in inventory
    const items = await InventoryItem.find({ userId: req.user._id });
    const foundItem = items.find(item => 
      item.name.toLowerCase().includes(parsedCommand.productName.toLowerCase()) ||
      parsedCommand.productName.toLowerCase().includes(item.name.toLowerCase())
    );
    
    if (!foundItem) {
      return res.status(404).json({
        success: false,
        error: `Product "${parsedCommand.productName}" not found in inventory`,
        parsedCommand
      });
    }
    
    res.json({
      success: true,
      parsedCommand,
      item: foundItem
    });
  } catch (error) {
    console.error('Voice processing error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to process voice command' 
    });
  }
});

// Helper function for fallback voice parsing
function parseVoiceCommandFallback(command, language) {
  const lowerCommand = command.toLowerCase();
  
  // Common product mappings
  const productMappings = {
    'en': {
      'sugar': 'sugar',
      'chini': 'sugar',
      'atta': 'atta',
      'flour': 'atta',
      'rice': 'rice',
      'chawal': 'rice',
      'dal': 'dal',
      'oil': 'oil',
      'milk': 'milk',
      'doodh': 'milk',
      'tea': 'tea',
      'chai': 'tea',
      'coffee': 'coffee',
      'salt': 'salt',
      'namak': 'salt'
    },
    'hi': {
      'चीनी': 'sugar',
      'chini': 'sugar',
      'आटा': 'atta',
      'atta': 'atta',
      'चावल': 'rice',
      'chawal': 'rice',
      'दाल': 'dal',
      'dal': 'dal',
      'तेल': 'oil',
      'tel': 'oil',
      'दूध': 'milk',
      'doodh': 'milk',
      'चाय': 'tea',
      'chai': 'tea',
      'कॉफी': 'coffee',
      'coffee': 'coffee',
      'नमक': 'salt',
      'namak': 'salt'
    }
  };
  
  // Extract quantity
  const quantityMatches = lowerCommand.match(/(\d+(\.\d+)?)\s*(kg|kilo|kilogram|kgs|g|gram|grams|unit|units)?/);
  let quantity = quantityMatches ? parseFloat(quantityMatches[1]) : 1;
  
  // Handle Indian measurements
  if (lowerCommand.includes('aadha') || lowerCommand.includes('आधा') || lowerCommand.includes('half')) {
    quantity = 0.5;
  } else if (lowerCommand.includes('paav') || lowerCommand.includes('पाव') || lowerCommand.includes('quarter')) {
    quantity = 0.25;
  }
  
  // Determine action
  let action = 'sell';
  if (lowerCommand.includes('add') || lowerCommand.includes('bought') || lowerCommand.includes('buy') || 
      lowerCommand.includes('खरीदा') || lowerCommand.includes('जोड़ा')) {
    action = 'add';
  } else if (lowerCommand.includes('update') || lowerCommand.includes('change') || lowerCommand.includes('बदला')) {
    action = 'update';
  }
  
  // Find product name
  let productName = '';
  const mappings = productMappings[language] || productMappings['en'];
  
  for (const [key, value] of Object.entries(mappings)) {
    if (lowerCommand.includes(key)) {
      productName = value;
      break;
    }
  }
  
  if (!productName) {
    // Try to extract any word that might be a product
    const words = lowerCommand.split(' ');
    for (const word of words) {
      if (word.length > 2 && !isNumeric(word)) {
        productName = word;
        break;
      }
    }
  }
  
  return {
    productName: productName || 'unknown',
    quantity,
    action
  };
}

function isNumeric(str) {
  return /^\d+$/.test(str);
}

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
    
    // Create expense for inventory purchase
    const expense = new Expense({
      userId: req.user._id,
      description: `Inventory purchase: ${name}`,
      amount: totalValue,
      category: 'inventory',
      date: new Date()
    });
    
    await expense.save();
    
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
    
    const existingItem = await InventoryItem.findOne({ _id: id, userId: req.user._id });
    if (!existingItem) {
      return res.status(404).json({ 
        success: false,
        error: 'Item not found' 
      });
    }
    
    // If quantity is being increased, create an expense
    if (updates.quantity !== undefined && updates.quantity > existingItem.quantity) {
      const addedQuantity = updates.quantity - existingItem.quantity;
      const expenseAmount = existingItem.cost * addedQuantity;
      
      const expense = new Expense({
        userId: req.user._id,
        description: `Restock: ${existingItem.name}`,
        amount: expenseAmount,
        category: 'inventory',
        date: new Date()
      });
      
      await expense.save();
    }
    
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

// Expenses Routes
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

app.get('/api/expenses', authMiddleware, async (req, res) => {
  try {
    const expenses = await Expense.find({ userId: req.user._id }).sort({ date: -1 });
    
    res.json({
      success: true,
      expenses
    });
  } catch (error) {
    console.error('Get expenses error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch expenses' 
    });
  }
});

// Dashboard Stats
app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
  try {
    const [items, sales, expenses] = await Promise.all([
      InventoryItem.find({ userId: req.user._id }),
      Sale.find({ userId: req.user._id }),
      Expense.find({ userId: req.user._id })
    ]);
    
    // Inventory stats
    const totalInventoryValue = items.reduce((sum, item) => sum + (item.cost * item.quantity), 0);
    const totalPotentialProfit = items.reduce((sum, item) => sum + (item.profit * item.quantity), 0);
    const totalItems = items.length;
    
    // Sales stats
    const totalSales = sales.reduce((sum, sale) => sum + sale.totalAmount, 0);
    const totalProfitFromSales = sales.reduce((sum, sale) => sum + sale.profit, 0);
    const totalCostOfSales = sales.reduce((sum, sale) => sum + sale.cost, 0);
    
    // Expense stats
    const totalExpenses = expenses.reduce((sum, expense) => sum + expense.amount, 0);
    const inventoryExpenses = expenses
      .filter(e => e.category === 'inventory')
      .reduce((sum, expense) => sum + expense.amount, 0);
    
    // Calculate net profit (Sales Profit - Non-inventory Expenses)
    const nonInventoryExpenses = totalExpenses - inventoryExpenses;
    const netProfit = totalProfitFromSales - nonInventoryExpenses;
    
    // Monthly breakdown
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
    
    res.json({
      success: true,
      stats: {
        // Inventory
        totalItems,
        totalInventoryValue,
        totalPotentialProfit,
        averageProfitPerItem: totalItems > 0 ? totalPotentialProfit / totalItems : 0,
        lowStockItems: items.filter(item => item.quantity < 10).length,
        
        // Financial
        totalSales,
        totalProfitFromSales,
        totalCostOfSales,
        totalExpenses,
        inventoryExpenses,
        nonInventoryExpenses,
        netProfit,
        
        // Monthly
        monthlySales,
        monthlyExpenses,
        monthlyProfit,
        
        // Business health
        profitMargin: totalSales > 0 ? (totalProfitFromSales / totalSales) * 100 : 0,
        expenseRatio: totalSales > 0 ? (totalExpenses / totalSales) * 100 : 0,
        roi: inventoryExpenses > 0 ? (totalProfitFromSales / inventoryExpenses) * 100 : 0
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