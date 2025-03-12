// Change this line
// const admin = require('../config/firebase-config');
// To this:
const { admin } = require('../config/firebase-config');

const { verifyToken } = require('../config/jwt_config');

const authMiddleware = async (req, res, next) => {
  try {
    console.log('Auth middleware started');
    
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      console.log('Authentication failed: No token provided');
      return res.status(401).json({ message: 'No token provided' });
    }
    
    // Verify JWT token
    console.log('Attempting to verify JWT token...');
    try {
      const decoded = verifyToken(token);
      console.log('JWT verification successful');
      
      // Verify Firebase token
      console.log('Attempting to verify Firebase token...');
      try {
        const firebaseToken = await admin.auth().verifyIdToken(decoded.firebaseToken);
        console.log('Firebase verification successful');
        
        req.user = {
          ...decoded,
          firebaseUid: firebaseToken.uid
        };
        
        console.log('User authenticated');
        next();
      } catch (firebaseError) {
        console.error('Firebase verification failed:', firebaseError.message);
        res.status(401).json({ message: 'Invalid Firebase token', error: firebaseError.message });
      }
    } catch (jwtError) {
      console.error('JWT verification failed:', jwtError.message);
      res.status(401).json({ message: 'Invalid JWT token', error: jwtError.message });
    }
  } catch (error) {
    console.error('Authentication middleware failed:', error.message);
    res.status(401).json({ message: 'Invalid token', error: error.message });
  }
};

module.exports = authMiddleware;