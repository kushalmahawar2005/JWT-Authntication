import express from "express";
import cors from "cors";
import "dotenv/config";
import cookieParser from "cookie-parser";
import connectDB from "./config/mongodb.js";
import authRouter from "./routes/authRoutes.js";
import userRouter from "./routes/userRoutes.js";



const app = express();
const port = process.env.PORT || 4000;
connectDB();

app.use(express.json());
app.use(cookieParser());
// Allow credentials and dynamic origin for local dev; adjust allowed origins as needed
app.use(
	cors({
		origin: (origin, callback) => callback(null, origin || true),
		credentials: true,
	})
);

app.get('/', (req, res) => res.send("hello server"));
app.use('/api/auth', authRouter);
app.use('/api/user', userRouter); // from userRoutes.js
app.listen(port, () => console.log(`Server listening on http://localhost:${port}`));