import jwt from 'jsonwebtoken';

const userAuth = async (req, res, next) => {
  const { token } = req.cookies;

  if (!token) {
    return res.json({ success: false, message: 'Not authorized, login again' });
  }

  try {
    // decode the token
    const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);

    if (tokenDecode.id) {
      // ensure req.body exists
      if (!req.body) req.body = {};
      req.body.userId = tokenDecode.id;

      // alternative (cleaner): attach directly
      req.userId = tokenDecode.id;
    } else {
      return res.json({ success: false, message: 'Not Authorized. Login again' });
    }

    next(); // call the controller
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

export default userAuth;
