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
  language: { type: String, default: 'en' }, // 'en' or 'hi' for Hinglish
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
  category: { type: String, default: 'General' },
  createdAt: { type: Date, default: Date.now }
});

const expenseSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  description: { type: String, required: true },
  amount: { type: Number, required: true },
  category: { 
    type: String, 
    enum: ['rent', 'utilities', 'salary', 'supplies', 'transport', 'marketing', 'maintenance', 'other'],
    default: 'other'
  },
  date: { type: Date, default: Date.now }
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
const Expense = mongoose.model('Expense', expenseSchema);
const Sale = mongoose.model('Sale', saleSchema);

const JWT_SECRET = process.env.JWT_SECRET || 'echobiz-secret-key-2024-change-in-production';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);

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

// Process voice command with Gemini AI
app.post('/api/voice/process', authMiddleware, async (req, res) => {
  try {
    const { command, language } = req.body;
    
    if (!command) {
      return res.status(400).json({ 
        success: false,
        error: 'Voice command is required' 
      });
    }

    // Get user's inventory items
    const inventoryItems = await InventoryItem.find({ userId: req.user._id });
    const itemNames = inventoryItems.map(item => item.name).join(', ');

    // Create prompt based on language
    let prompt;
    if (language === 'hi') {
      prompt = `You are an inventory management assistant. The user speaks Hinglish (Hindi-English mix). Extract the product name and quantity from their command. 

Available products in inventory: ${itemNames}

User command: "${command}"

Return a JSON object with these fields:
1. productName: The exact product name from inventory (match from: ${itemNames})
2. quantity: Number of units/quantity
3. action: 'sale' or 'update' or 'add'
4. confidence: 0-1 how confident you are

Examples:
Input: "4 kg sugar bech diya"
Output: {"productName": "sugar", "quantity": 4, "action": "sale", "confidence": 0.9}

Input: "do kilo atta add karo"
Output: {"productName": "atta", "quantity": 2, "action": "add", "confidence": 0.8}

Input: "milk 2 liters"
Output: {"productName": "milk", "quantity": 2, "action": "sale", "confidence": 0.7}

If product not found in inventory, set productName to "not_found"`;
    } else {
      prompt = `You are an inventory management assistant. Extract the product name and quantity from the user's voice command.

Available products in inventory: ${itemNames}

User command: "${command}"

Return a JSON object with these fields:
1. productName: The exact product name from inventory (match from: ${itemNames})
2. quantity: Number of units/quantity
3. action: 'sale' or 'update' or 'add'
4. confidence: 0-1 how confident you are

Examples:
Input: "sold 4 kg of sugar"
Output: {"productName": "sugar", "quantity": 4, "action": "sale", "confidence": 0.9}

Input: "add 2 kg atta"
Output: {"productName": "atta", "quantity": 2, "action": "add", "confidence": 0.8}

Input: "update milk quantity to 5"
Output: {"productName": "milk", "quantity": 5, "action": "update", "confidence": 0.7}

If product not found in inventory, set productName to "not_found"`;
    }

    try {
      const model = genAI.getGenerativeModel({ model: "gemini-pro" });
      const result = await model.generateContent(prompt);
      const response = await result.response;
      const text = response.text();
      
      // Extract JSON from response
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsedData = JSON.parse(jsonMatch[0]);
        
        // Find the actual product name from inventory
        if (parsedData.productName && parsedData.productName !== 'not_found') {
          const foundItem = inventoryItems.find(item => 
            item.name.toLowerCase().includes(parsedData.productName.toLowerCase()) ||
            parsedData.productName.toLowerCase().includes(item.name.toLowerCase())
          );
          
          if (foundItem) {
            parsedData.productName = foundItem.name;
            parsedData.confidence = Math.min(1, parsedData.confidence + 0.1);
          } else {
            parsedData.productName = 'not_found';
            parsedData.confidence = 0.3;
          }
        }

        res.json({
          success: true,
          data: parsedData,
          rawResponse: text
        });
      } else {
        throw new Error('No JSON found in response');
      }
    } catch (geminiError) {
      console.error('Gemini API error:', geminiError);
      
      // Fallback: Simple pattern matching
      const quantityMatch = command.match(/\d+/);
      const quantity = quantityMatch ? parseInt(quantityMatch[0]) : 1;
      
      // Try to find product name
      let productName = 'not_found';
      for (const item of inventoryItems) {
        if (command.toLowerCase().includes(item.name.toLowerCase())) {
          productName = item.name;
          break;
        }
      }
      
      res.json({
        success: true,
        data: {
          productName,
          quantity,
          action: command.toLowerCase().includes('sold') || command.toLowerCase().includes('bech') ? 'sale' : 
                  command.toLowerCase().includes('add') || command.toLowerCase().includes('add karo') ? 'add' : 'update',
          confidence: 0.5
        },
        fallback: true
      });
    }
  } catch (error) {
    console.error('Voice process error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to process voice command' 
    });
  }
});

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
        name: user.name,
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
        name: user.name,
        language: user.language
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
    const { name, cost, price, quantity, category } = req.body;
    
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
      totalValue,
      category: category || 'General'
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

// Expense Routes
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
      category: category || 'other'
    });
    
    await expense.save();
    res.status(201).json({ 
      success: true,
      message: 'Expense added successfully', 
      expense 
    });
  } catch (error) {
    console.error('Add expense error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to add expense' 
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

app.delete('/api/expenses/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    
    const expense = await Expense.findOneAndDelete({
      _id: id,
      userId: req.user._id
    });
    
    if (!expense) {
      return res.status(404).json({ 
        success: false,
        error: 'Expense not found' 
      });
    }
    
    res.json({ 
      success: true,
      message: 'Expense deleted successfully' 
    });
  } catch (error) {
    console.error('Delete expense error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to delete expense' 
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

app.get('/api/sales/stats', authMiddleware, async (req, res) => {
  try {
    const sales = await Sale.find({ userId: req.user._id });
    
    const totalSalesAmount = sales.reduce((sum, sale) => sum + sale.totalAmount, 0);
    const totalSalesProfit = sales.reduce((sum, sale) => sum + sale.profit, 0);
    const totalSalesCost = sales.reduce((sum, sale) => sum + sale.cost, 0);
    const totalItemsSold = sales.reduce((sum, sale) => sum + sale.quantity, 0);
    
    // Get sales by day for last 7 days
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    
    const recentSales = await Sale.find({
      userId: req.user._id,
      date: { $gte: sevenDaysAgo }
    }).sort({ date: 1 });
    
    const salesByDay = {};
    recentSales.forEach(sale => {
      const date = sale.date.toISOString().split('T')[0];
      if (!salesByDay[date]) {
        salesByDay[date] = {
          amount: 0,
          profit: 0,
          items: 0
        };
      }
      salesByDay[date].amount += sale.totalAmount;
      salesByDay[date].profit += sale.profit;
      salesByDay[date].items += sale.quantity;
    });
    
    res.json({
      success: true,
      stats: {
        totalSalesAmount,
        totalSalesProfit,
        totalSalesCost,
        totalItemsSold,
        averageSaleValue: sales.length > 0 ? totalSalesAmount / sales.length : 0,
        salesByDay
      }
    });
  } catch (error) {
    console.error('Get sales stats error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch sales stats' 
    });
  }
});

// Dashboard Stats
app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
  try {
    const items = await InventoryItem.find({ userId: req.user._id });
    const expenses = await Expense.find({ userId: req.user._id });
    const sales = await Sale.find({ userId: req.user._id });
    
    const totalInventoryValue = items.reduce((sum, item) => sum + (item.cost * item.quantity), 0);
    const totalPotentialProfit = items.reduce((sum, item) => sum + (item.profit * item.quantity), 0);
    const totalItems = items.length;
    
    const totalExpenses = expenses.reduce((sum, expense) => sum + expense.amount, 0);
    const totalSalesAmount = sales.reduce((sum, sale) => sum + sale.totalAmount, 0);
    const totalSalesProfit = sales.reduce((sum, sale) => sum + sale.profit, 0);
    
    const netProfit = totalSalesProfit - totalExpenses;
    
    // Calculate expense by category
    const expenseByCategory = {};
    expenses.forEach(expense => {
      if (!expenseByCategory[expense.category]) {
        expenseByCategory[expense.category] = 0;
      }
      expenseByCategory[expense.category] += expense.amount;
    });
    
    res.json({
      success: true,
      stats: {
        totalItems,
        totalInventoryValue,
        totalPotentialProfit,
        averageProfitPerItem: totalItems > 0 ? totalPotentialProfit / totalItems : 0,
        lowStockItems: items.filter(item => item.quantity < 10).length,
        
        // Financial stats
        totalExpenses,
        totalSalesAmount,
        totalSalesProfit,
        netProfit,
        expenseByCategory,
        
        // Performance metrics
        profitMargin: totalSalesAmount > 0 ? (totalSalesProfit / totalSalesAmount) * 100 : 0,
        roi: totalInventoryValue > 0 ? (netProfit / totalInventoryValue) * 100 : 0
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