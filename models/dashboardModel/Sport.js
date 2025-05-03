const mongoose = require('mongoose');

const SportSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please add a sport name'],
    trim: true,
    unique: true
  },
  icon: {
    type: String,
    default: '🏆'
  },
  roles: [{
    type: String,
    trim: true
  }],
  skillLevels: [{
    type: String,
    trim: true
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Sport', SportSchema);