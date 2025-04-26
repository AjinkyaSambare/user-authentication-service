const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const tokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 86400 // 24 hours in seconds
  }
});

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email address']
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  tokens: [tokenSchema],
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Pre-save hook to hash password before saving
userSchema.pre('save', async function(next) {
  const user = this;
  if (!user.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(user.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Update the updatedAt timestamp on updates
userSchema.pre('findOneAndUpdate', function() {
  this.set({ updatedAt: new Date() });
});

// Method to add token to user's tokens array
userSchema.methods.addToken = function(token) {
  this.tokens.push({ token });
  return this.save();
};

// Method to remove token from user's tokens array
userSchema.methods.removeToken = function(token) {
  this.tokens = this.tokens.filter(t => t.token !== token);
  return this.save();
};

const User = mongoose.model('User', userSchema);

module.exports = User;
