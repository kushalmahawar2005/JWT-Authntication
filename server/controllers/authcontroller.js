import bcrypt from 'bcrypt'
import jwt from "jsonwebtoken";
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';

// Register
export const register = async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.json({ success: false, message: "missing data" });
  }
  try {
    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      return res.json({ success: false, message: "User already exist" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new userModel({ name, email, password: hashedPassword });
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // Send welcome email (non-blocking failure)
    const mailoptions = {
      from: process.env.SENDER_EMAIL || process.env.SMTP_USER,
      to: email,
      subject: 'Welcome to Zeetron Network',
      text: `Welcome to Zeetron Network. Your account has been created with email id ${email}`,
    };
    try {
      await transporter.sendMail(mailoptions);
    } catch (e) {
      console.warn('Welcome email failed:', e?.message || e);
    }

    return res.json({ success: true, token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

// Login
export const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.json({ success: false, message: 'Email and password are required' });
  }

  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: 'Invalid email' });
    }
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.json({ success: false, message: 'Invalid password' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json({ success: true, token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

// Logout
export const logout=async(req,res)=>{
  try {
    res.clearCookie('token',{ 
      httpOnly:true,
      secure:process.env.NODE_ENV==='production',
      sameSite:process.env.NODE_ENV==='production'?'none':'strict'
    })
    return res.json({success:true,message:"Logged Out"})
  } catch (error) {
    return res.json({success:false,message:error.message})
  }
}

// Send Verify OTP
export const sendVerifyOtp = async (req, res) => {
  try {
    const userId = req.userId;
    const user = await userModel.findById(userId);
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }
    if (user.isAccountVerified) {
      return res.json({ sucess: false, message: "Account already verified" });
    }
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    user.verifyOtp = otp;
    user.verifyOtpExpireAt = Date.now() + 5 * 60 * 1000; // 5 minutes
    await user.save();

    const mailOption = {
      from: process.env.SENDER_EMAIL || process.env.SMTP_USER,
      to: user.email,
      subject: 'Account verification OTP',
      text: `Your OTP is ${otp}. Verify using this OTP`,
    };
    try {
      await transporter.sendMail(mailOption);
    } catch (e) {
      console.warn('OTP email failed:', e?.message || e);
      return res.json({ success: false, message: "Failed to send OTP email" });
    }
    return res.json({ success: true, message: "OTP sent to email" });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
}

// Verify Email
export const verifyEmail = async (req, res) => {
  const { userId: bodyUserId, otp } = req.body;
  const userId = req.userId || bodyUserId; // use authenticated user when available
  if (!userId || !otp) {
    return res.json({ success: false, message: "Missing Details" });
  }
  try {
    const user = await userModel.findById(userId);
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }
    if (user.verifyOtp === '' || user.verifyOtp !== otp) {
      return res.json({ success: false, message: "Invalid OTP" });
    }

    if (user.verifyOtpExpireAt < Date.now()) {
      return res.json({ success: false, message: "OTP expired" });
    }

    user.isAccountVerified = true;
    user.verifyOtp = '';
    user.verifyOtpExpireAt = 0;

    await user.save();
    return res.json({ success: true, message: "Email Verified successfully" });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
}

// Auth check
export const isAuthenticated = async(req,res)=>{
  try {
    return res.json({success:true})
  } catch (error) {
    res.json({success:false,message:error.message})
  }
}

// Send Reset OTP
export const sendResetOtp = async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.json({ success: false, message: "Email is required" });
  }

  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: 'User not found' });
    }

    const otp = String(Math.floor(100000 + Math.random() * 900000));
    user.resetOtp = otp;
    user.resetOtpExpireAt = Date.now() + 5 * 60 * 1000; // 5 minutes
    await user.save();

    const mailOption = {
      from: process.env.SENDER_EMAIL || process.env.SMTP_USER,
      to: user.email,
      subject: 'Password reset OTP',
      text: `Your OTP for resetting password is ${otp}. Use this OTP to reset your password`,
    };
    try {
      await transporter.sendMail(mailOption);
    } catch (e) {
      console.warn('Reset OTP email failed:', e?.message || e);
      return res.json({ success: false, message: 'Failed to send reset OTP email' });
    }
    return res.json({ success: true, message: 'OTP sent to your email' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
}

// Reset Password
export const resetPassword = async(req,res)=>{
  const{email,otp,newPassword}=req.body;
  if(!email || !otp || !newPassword){
    return res.json({success:false,message:'email otp and new password required'})
  }

  try {
    const user = await userModel.findOne({email});
    if(!user){
      return res.json({success:false,message:'user not found'})
    }
    if(user.resetOtp==="" || user.resetOtp!==otp){
      return res.json({success:false,message:'invalid otp'})
    }
    if(user.resetOtpExpireAt<Date.now()){
      return res.json({success:false,message:'otp expired'})
    }

    const hashedPassword = await bcrypt.hash(newPassword,10)

    user.password=hashedPassword;
    user.resetOtp='';
    user.resetOtpExpireAt=0;
    await user.save()

    res.json({success:true,message:"Password has been reset successfully "})
  } catch (error) {
    res.json({success:false,message:error.message})
  }
}






