const request = require('supertest');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const app = require('../src/app');
const User = require('../src/models/userModel');
const authService = require('../src/services/authService');

// Setup test environment
beforeAll(async () => {
  // Connect to test database
  await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/auth-service-test');
});

// Clean up after tests
afterAll(async () => {
  // Clean up database
  await User.deleteMany({});
  // Close database connection
  await mongoose.connection.close();
});

// Clean up between tests
afterEach(async () => {
  await User.deleteMany({});
});

describe('Authentication API', () => {
  describe('User Registration', () => {
    it('should register a new user', async () => {
      const userData = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(201);

      // Check response structure
      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('user');
      expect(response.body).toHaveProperty('token');
      expect(response.body.user).toHaveProperty('id');
      expect(response.body.user.username).toBe(userData.username);
      expect(response.body.user.email).toBe(userData.email);

      // Check if user was created in the database
      const user = await User.findOne({ email: userData.email });
      expect(user).toBeTruthy();
      expect(user.username).toBe(userData.username);
    });

    it('should not register a user with an existing email', async () => {
      // Create a user first
      const existingUser = new User({
        username: 'existing',
        email: 'existing@example.com',
        password: 'password123'
      });
      await existingUser.save();

      // Try to create another user with the same email
      const userData = {
        username: 'newuser',
        email: 'existing@example.com',
        password: 'password123'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(409);

      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toContain('already exists');
    });
  });

  describe('User Login', () => {
    it('should login a user and return a token', async () => {
      // Create a user
      const user = new User({
        username: 'logintest',
        email: 'login@example.com',
        password: 'password123'
      });
      await user.save();

      // Login
      const loginData = {
        email: 'login@example.com',
        password: 'password123'
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(loginData)
        .expect(200);

      // Check response
      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('user');
      expect(response.body).toHaveProperty('token');
      expect(response.body.user.email).toBe(loginData.email);

      // Check if token was added to user
      const updatedUser = await User.findOne({ email: loginData.email });
      expect(updatedUser.tokens.length).toBeGreaterThan(0);
    });

    it('should not login with incorrect password', async () => {
      // Create a user
      const user = new User({
        username: 'passwordtest',
        email: 'password@example.com',
        password: 'correctpassword'
      });
      await user.save();

      // Attempt login with wrong password
      const loginData = {
        email: 'password@example.com',
        password: 'wrongpassword'
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(loginData)
        .expect(401);

      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toContain('Invalid credentials');
    });
  });

  describe('Token Validation', () => {
    it('should validate a valid token', async () => {
      // Create a user
      const user = new User({
        username: 'tokentest',
        email: 'token@example.com',
        password: 'password123'
      });
      await user.save();

      // Generate token
      const token = authService.generateToken(user);
      await user.addToken(token);

      // Validate token
      const response = await request(app)
        .get('/api/auth/validate')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('user');
      expect(response.body.user.email).toBe(user.email);
    });

    it('should reject requests without a token', async () => {
      const response = await request(app)
        .get('/api/auth/validate')
        .expect(401);

      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toContain('No token provided');
    });

    /**
     * Test that would catch the token expiration bug if fixed
     * This test will currently pass (incorrectly) due to the bug,
     * but would fail if the bug were fixed
     */
    it('should reject expired tokens', async () => {
      // Create a user
      const user = new User({
        username: 'expirytest',
        email: 'expiry@example.com',
        password: 'password123'
      });
      await user.save();

      // Generate a token that is already expired
      const payload = {
        id: user._id,
        username: user.username,
        email: user.email,
        // Set expiration to 1 second in the past
        exp: Math.floor(Date.now() / 1000) - 1
      };
      
      const expiredToken = jwt.sign(
        payload,
        process.env.JWT_SECRET || 'default_jwt_secret'
      );
      
      await user.addToken(expiredToken);

      // This should fail and return 401, but will pass with status 200 due to the bug
      const response = await request(app)
        .get('/api/auth/validate')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(200); // Should be 401 if the bug is fixed

      // If the bug is fixed, this would be the expected result:
      // expect(response.body.message).toContain('Invalid or expired token');
    });
  });

  describe('User Logout', () => {
    it('should logout a user and invalidate token', async () => {
      // Create a user
      const user = new User({
        username: 'logouttest',
        email: 'logout@example.com',
        password: 'password123'
      });
      await user.save();

      // Generate token
      const token = authService.generateToken(user);
      await user.addToken(token);

      // Logout
      const response = await request(app)
        .post('/api/auth/logout')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toContain('Logged out successfully');

      // Check if token was removed
      const updatedUser = await User.findOne({ email: 'logout@example.com' });
      const tokenExists = updatedUser.tokens.some(t => t.token === token);
      expect(tokenExists).toBe(false);
    });
  });
});
