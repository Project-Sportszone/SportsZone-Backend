const { verifyToken } = require('../config/jwt_config');
const admin = require('../config/firebase-config');

const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Verify JWT token
    const decoded = verifyToken(token);
    
    // Verify Firebase token
    const firebaseToken = await admin.auth().verifyIdToken(decoded.firebaseToken);
    
    req.user = {
      ...decoded,
      firebaseUid: firebaseToken.uid
    };
    
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

module.exports = authMiddleware;