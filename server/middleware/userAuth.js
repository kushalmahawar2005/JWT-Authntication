import jwt from "jsonwebtoken";

const userAuth = (req, res, next) => {
  try {
    // Prefer cookie, but also accept Bearer token header for SPA/API clients
    let token = req.cookies?.token;

    if (!token) {
      const authHeader = req.headers?.authorization || req.headers?.Authorization;
      if (authHeader && typeof authHeader === "string" && authHeader.startsWith("Bearer ")) {
        token = authHeader.substring(7);
      }
    }

    if (!token) {
      return res.status(401).json({ success: false, message: "Not Authorized. Please login again" });
    }

    // verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;

    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: "Not Authorized. Please login again" });
  }
};

export default userAuth;
