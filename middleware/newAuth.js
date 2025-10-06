//new auth
//we use this new auth because for usercontroller

import jwt from 'jsonwebtoken';

const newAuth = async (req, res, next) => {
  // console.log('userAuth middleware started');

  const { token } = req.cookies;

  if (!token) {
    // console.log('No token found in cookies');
    return res.json({ success: false, message: 'Not authorized login again' });
  }

  try {
    // decode the token
    const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);

    // console.log('Token decoded:', tokenDecode);

    if (tokenDecode.id) {
      req.userId = tokenDecode.id;
      // console.log('User ID from token:', tokenDecode.id);
      // console.log('req.body is:', req.body);
    } else {
      // console.log('Token missing id field');
      return res.json({ success: false, message: 'Not Authorized. Login again' });
    }

    next(); // proceed to controller
  } catch (error) {
    // console.log('Error verifying token:', error.message);
    res.json({ success: false, message: error.message });
  }
};

export default newAuth;
