import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const userSchema = new Schema(
    {
        firstName: {
            type: String,
            required: true,
            trim: true,
            lowercase: true,
            index: true
        },
        lastName: {
            type: String,
            required: true,
            trim: true,
            lowercase: true,
            index: true
        },
        
        email: {
            type: String,
            required: true,
            trim: true,
            unique: true,
            lowercase: true,
        },
        password: {
            type: String,
            required: [true, 'Password is required!!'],
        },
        contactNumber:{
            type: Number,
            required: [true, 'Contact Number Required'],
            unique: true
        },
        emergencyNumber1:{
            type: Number,
        },
        emergencyNumber2:{
            type: Number,
        },
        emergencyNumber3:{
            type: Number,
        },
        emergencyNumber4:{
            type: Number,
        },
        emergencyNumber5:{
            type: Number,
        },
        refreshToken: {
            type: String,
        }
    },
    {
        timestamps: true
    }

);

userSchema.pre("save", async function (next) {
    if(!this.isModified("password")) return next();

    this.password = await bcrypt.hash(this.password, 10)
    next() 
})
userSchema.methods.isPasswordCorrect = async function(password){
    return await bcrypt.compare(password, this.password)
}

userSchema.methods.generateAccessToken = function(){
    return jwt.sign(
        {
            _id: this._id,
            email: this.email,
            
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY
        }
    )
}
userSchema.methods.generateRefreshToken = function(){
    return jwt.sign(
        {
            _id: this._id,            
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY
        }
    )
}

export const User = mongoose.model('User', userSchema );