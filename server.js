// Dependecies
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const firebase = require('firebase/app');
const authRoutes = require('./routes/authRoutes');
require('dotenv').config();
const app = express();



// MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch(err => console.log("Cannot connect to MongoDB"));

// Middleware
app.use(express.json());
app.use(cors());
app.use('/auth', authRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});



  const PORT = process.env.PORT;
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
