import userModel from "../models/user.model.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import config from '../config/config.js';
import sessionModel from "../models/session.model.js";
import sendEmail from "../services/email.service.js";
import { generateOTP, getOtpHtml } from "../utils/utils.js";
import otpModel from "../models/otp.model.js";


export async function registerUser(req, res){
    const {username, email, password} = req.body;

    const userAlreadyExists = await userModel.findOne({
        $or:[
            {username},
            {email}
        ]
    })

    if(userAlreadyExists){
        return res.status(409).json({message: "User already exists"});
    }

    const hashedPassword = crypto.createHash('sha256').update(password)
    .digest('hex');

    const newUser = await userModel.create({
        username, 
        email,
        password: hashedPassword
    })

    const otp = generateOTP();
    const html = getOtpHtml(otp);

    const otpHash = crypto.createHash('sha256').update(otp).digest('hex');

    await otpModel.create({
        email: newUser.email,
        user: newUser._id,
        otpHash
    })

    await sendEmail({
    to: newUser.email,
    subject: "Verify your email",
    text: `Your OTP is: ${otp}`,
    html
});

    res.status(201).json({
        message: 'User registered successfully',
        user: {
            username: newUser.username,
            email: newUser.email,
            verified: newUser.verified
        }
    })

}

export async function loginUser(req, res){
    const {email, password} = req.body;
    

    const user = await userModel.findOne({
        $or:[
            {email}
        ]
    })

    if(!user){
        return res.status(401).json({
            message:'Invalid email or password'
        })
    }

    if(!user.verified) {
        return res.status(403).json({
            message: 'Please verify your email before logging in'
        })
    }

    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

    const isPasswordValid = hashedPassword === user.password

    if(!isPasswordValid){
        return res.status(401).json({
            message: 'Invalid email or password'
        })
    }

    const refreshToken = jwt.sign({
        id: user._id
    }, config.JWT_SECRET, {
        expiresIn: '7d'
    })

    const session = await sessionModel.create({
        user: user._id,
        refreshTokenHash: crypto.createHash('sha256').update(refreshToken).digest('hex'),
        ip: req.ip,
        userAgent: req.headers["user-agent"]
    })

    const accessToken = jwt.sign({
        id: user._id,
        sessionId: session._id
    }, config.JWT_SECRET, {
        expiresIn: "10m"
    })

    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000
    })

    res.status(200).json({
        message: "Logged in successfully",
        user: {
            username: user.username,
            email: user.email
        },
        accessToken,
    })

}

export async function getMe(req, res) {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    try {
        const decoded = jwt.verify(token, config.JWT_SECRET);

        const user = await userModel.findById(decoded.id).select("-password");

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        res.status(200).json({
            message: "User fetched successfully",
            id: user._id,
            username: user.username,
            email: user.email,
        });
    } catch (err) {
        return res.status(401).json({ message: "Invalid or expired token" });
    }
}

export async function refreshToken(req, res){
    const refreshToken = res.cookies.refreshToken;

    if(!refreshToken){
        return res.status(401).json({
            message: 'Refresh Token not found'
        })
    }

    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);

    const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

    const session = await sessionModel.findOne({
        refreshTokenHash,
        revoked: false
    })
    if(!session){
        return res.status(401).json({
            message: 'Session not found'
        })
    }

    const accessToken = jwt.sign({
        id:decoded.id
    }, config.JWT_SECRET,{
        expiresIn: "15m"
    })

    const newRefreshToken = jwt.sign({
        id: decoded.id
    }, config.JWT_SECRET, {
        expiresIn: "7d"
    })

    const newRefreshTokenHash = crypto.createHash('sha256').update(newRefreshToken).digest('hex');

    session.refreshTokenHash = newRefreshTokenHash;
    await session.save();

    res.cookie('refreshToken', newRefreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    })

    res.status(200).json({
        message: 'Access Token refreshed successfully',
        accessToken
    })

}


export async function logoutUser(req, res){

    const refreshToken = req.cookies.refreshToken;

    if(!refreshToken){
        return res.status(401).json({
            message: 'Refresh Token not found'
        })
    }

    const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

    const session = await sessionModel.findOne({
        refreshTokenHash,
        revoked: false
    })

    if(!session){
        return res.status(401).json({
            message: 'Session not found'
        })
    }

    session.revoked = true;
    await session.save();

    res.clearCookie('refreshToken');

    res.status(200).json({
        message: 'User logged out successfully'
    })

}

export async function logoutAllSessions(req, res){
    const refreshToken = req.cookies.refreshToken;

    if(!refreshToken){
        return res.status(401).json({
            message: 'Refresh Token not found'
        })
    }

    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);

    await sessionModel.updateMany({
        user: decoded.id,
        revoked: false
    }, {
        $set: { revoked: true }
    })

    res.clearCookie('refreshToken');

    res.status(200).json({
        message: 'User logged out from all sessions successfully'
    })
}

export async function verifyEmail(req, res){
    const { email, otp } = req.body;

    const otpHash = crypto.createHash('sha256').update(otp).digest('hex');

    const otpDoc = await otpModel.findOne({
        email,
        otpHash
    })

    if(!otpDoc){
        return res.status(400).json({
            message: 'Invalid OTP'
        })
    }

    const user = await userModel.findByIdAndUpdate(
        otpDoc.user, 
        {verified: true},
        {new: true}
    )
    await otpModel.deleteMany({ email });

    return res.status(200).json({
        message: 'Email verified successfully',
        user: {
            username: user.username,
            email: user.email,
            verified: user.verified
        }
    })
}