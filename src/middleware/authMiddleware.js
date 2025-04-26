const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const authService = require('../services/authService');
const logger = require('../utils/logger');

/**
 * Authentication middleware to validate JWT tokens and attach user to request
 */
const authMiddleware = async (req, res, next) => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Authentication required. No token provided.' });
    }

    const token = authHeader.split(' ')[1];
    
    // Use the buggy isTokenValid function to validate token
    if (!authService.isTokenValid(token)) {
      return res.status(401).json({ message: 'Invalid or expired token.' });
    }
    
    // If token is valid, decode it to get user information
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default_jwt_secret');
    
    // Find user by id
    const user = await User.findById(decoded.id);
    
    // Check if user exists
    if (!user) {
      return res.status(401).json({ message: 'User not found.' });
    }
    
    // Check if token exists in user's tokens array
    const tokenExists = user.tokens.some(t => t.token === token);
    if (!tokenExists) {
      return res.status(401).json({ message: 'Token not found in user records.' });
    }
    
    // Attach user to request for later use
    req.user = user;
    req.token = token;
    
    // Move to next middleware or route handler
    next();
  } catch (error) {
    logger.error('Auth middleware error:', error);
    return res.status(401).json({ message: 'Authentication failed.' });
  }
};

module.exports = authMiddleware;
