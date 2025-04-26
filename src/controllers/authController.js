const express = require('express');
const router = express.Router();
const User = require('../models/userModel');
const authService = require('../services/authService');
const authMiddleware = require('../middleware/authMiddleware');
const logger = require('../utils/logger');

/**
 * Register a new user
 * POST /api/auth/register
 */
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Basic validation
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });
    
    if (existingUser) {
      return res.status(409).json({ message: 'User already exists with this email or username' });
    }
    
    // Create new user
    const user = new User({
      username,
      email,
      password // Will be hashed by the pre-save hook in userModel
    });
    
    await user.save();
    
    // Generate token
    const token = authService.generateToken(user);
    
    // Add token to user
    await user.addToken(token);
    
    // Return user and token
    return res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      },
      token
    });
  } catch (error) {
    logger.error('Registration error:', error);
    return res.status(500).json({ message: 'Error registering user' });
  }
});

/**
 * Login user
 * POST /api/auth/login
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Basic validation
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    
    // Find user by email
    const user = await User.findOne({ email });
    
    // Check if user exists
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // Verify password
    const isPasswordValid = await authService.comparePassword(password, user.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // Generate token
    const token = authService.generateToken(user);
    
    // Add token to user
    await user.addToken(token);
    
    // Return user and token
    return res.status(200).json({
      message: 'Login successful',
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      },
      token
    });
  } catch (error) {
    logger.error('Login error:', error);
    return res.status(500).json({ message: 'Error logging in' });
  }
});

/**
 * Refresh token
 * POST /api/auth/refresh
 */
router.post('/refresh', async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({ message: 'Token is required' });
    }
    
    // Refresh token
    const newToken = await authService.refreshToken(token);
    
    // Update user's tokens
    // Find user from token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default_jwt_secret');
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Remove old token and add new one
    await user.removeToken(token);
    await user.addToken(newToken);
    
    return res.status(200).json({
      message: 'Token refreshed successfully',
      token: newToken
    });
  } catch (error) {
    logger.error('Token refresh error:', error);
    return res.status(401).json({ message: 'Error refreshing token' });
  }
});

/**
 * Logout user
 * POST /api/auth/logout
 */
router.post('/logout', authMiddleware, async (req, res) => {
  try {
    // Remove token from user's tokens array
    await req.user.removeToken(req.token);
    
    return res.status(200).json({ message: 'Logged out successfully' });
  } catch (error) {
    logger.error('Logout error:', error);
    return res.status(500).json({ message: 'Error logging out' });
  }
});

/**
 * Validate token
 * GET /api/auth/validate
 */
router.get('/validate', authMiddleware, async (req, res) => {
  try {
    // If we get here, the token is valid (middleware has validated it)
    return res.status(200).json({ 
      message: 'Token is valid',
      user: {
        id: req.user._id,
        username: req.user.username,
        email: req.user.email
      }
    });
  } catch (error) {
    logger.error('Token validation error:', error);
    return res.status(500).json({ message: 'Error validating token' });
  }
});

module.exports = router;
