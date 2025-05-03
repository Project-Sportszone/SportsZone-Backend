const mongoose = require('mongoose');

const VenueSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please add a venue name'],
    trim: true
  },
  address: {
    type: String,
    required: [true, 'Please add a venue address'],
    trim: true
  },
  city: {
    type: String,
    required: [true, 'Please add a city'],
    trim: true
  },
  coordinates: {
    latitude: {
      type: Number,
      default: null
    },
    longitude: {
      type: Number,
      default: null
    }
  },
  facilities: [{
    type: String,
    trim: true
  }],
  sports: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Sport'
  }],
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Venue', VenueSchema);