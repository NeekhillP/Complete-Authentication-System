import userModel from "../models/user.model.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import config from '../config/config.js';

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

    const accessToken = jwt.sign({
        id: newUser._id
    }, config.JWT_SECRET, {
        expiresIn: '15m'
    })

    const refreshToken = jwt.sign({
        id: newUser._id
    }, config.JWT_SECRET, {
        expiresIn: '7d'
    })

    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    })



    res.status(201).json({
        message: 'User registered successfully',
        user: {
            id: newUser._id,
            username: newUser.username,
            email: newUser.email
        },
         accessToken
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