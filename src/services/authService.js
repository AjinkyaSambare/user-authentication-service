const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('../models/userModel');
const logger = require('../utils/logger');

/**
 * Authentication service with methods for token generation and validation,
 * password hashing, and user authentication
 */
const authService = {
  /**
   * Generate JWT token for user authentication
   * @param {Object} user User object
   * @returns {String} JWT token
   */
  generateToken: (user) => {
    try {
      const payload = {
        id: user._id,
        username: user.username,
        email: user.email
      };
      
      // Generate token with expiration time from environment variable or default to 24h
      const token = jwt.sign(
        payload, 
        process.env.JWT_SECRET || 'default_jwt_secret',
        { expiresIn: process.env.JWT_EXPIRY || '24h' }
      );
      
      return token;
    } catch (error) {
      logger.error('Error generating token:', error);
      throw new Error('Failed to generate authentication token');
    }
  },
  
  /**
   * Validate JWT token
   * @param {String} token JWT token to validate
   * @returns {Boolean} True if valid, false otherwise
   * 
   * BUG: This function compares expiration time in seconds with Date.now() in milliseconds
   * causing tokens to not expire properly.
   */
  isTokenValid: (token) => {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default_jwt_secret');
      
      // BUG: This comparison is incorrect
      // decoded.exp is in seconds (JWT standard) but Date.now() returns milliseconds
      // This comparison will almost always return true even for expired tokens
      return decoded.exp > Date.now();
    } catch (error) {
      logger.error('Token validation error:', error);
      return false;
    }
  },
  
  /**
   * Hash a password
   * @param {String} password Plain text password
   * @returns {String} Hashed password
   */
  hashPassword: async (password) => {
    try {
      const salt = await bcrypt.genSalt(10);
      return await bcrypt.hash(password, salt);
    } catch (error) {
      logger.error('Error hashing password:', error);
      throw new Error('Failed to hash password');
    }
  },
  
  /**
   * Compare plain text password with hashed password
   * @param {String} password Plain text password
   * @param {String} hashedPassword Hashed password
   * @returns {Boolean} True if matching, false otherwise
   */
  comparePassword: async (password, hashedPassword) => {
    try {
      return await bcrypt.compare(password, hashedPassword);
    } catch (error) {
      logger.error('Error comparing passwords:', error);
      throw new Error('Failed to verify password');
    }
  },
  
  /**
   * Refresh an existing token
   * @param {String} token Existing token to refresh
   * @returns {String} New JWT token
   */
  refreshToken: async (token) => {
    try {
      // Despite bug in validation, we use jwt.verify directly here to get the decoded payload
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default_jwt_secret');
      
      // Find user to ensure they still exist
      const user = await User.findById(decoded.id);
      if (!user) {
        throw new Error('User not found');
      }
      
      // Generate a new token
      return authService.generateToken(user);
    } catch (error) {
      logger.error('Error refreshing token:', error);
      throw new Error('Failed to refresh token');
    }
  }
};

module.exports = authService;
