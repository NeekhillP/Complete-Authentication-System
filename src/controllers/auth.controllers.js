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

    const token = jwt.sign({
        id: newUser._id
    }, config.JWT_SECRET, {
        expiresIn: '1d'
    })

    res.cookie('token', token)

    res.status(201).json({
        message: 'User registered successfully',
        user: {
            id: newUser._id,
            username: newUser.username,
            email: newUser.email
        },
        token
    })

}



