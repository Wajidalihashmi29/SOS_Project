import asyncHandler from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.model.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import jwt from "jsonwebtoken"


const generateAccessAndRefreshToken = async (userId) => {
    try {
      const users = await User.findById(userId)
      const accessToken = users.generateAccessToken()
      const refreshToken = users.generateRefreshToken()

      users.refreshToken = refreshToken
      await users.save({validateBeforeSave: false})

      return {accessToken, refreshToken}

    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating access and refresh token")
    }
}
const register = asyncHandler(async (req, res) => {
    const {
        firstName, 
        lastName, 
        email, 
        password, 
        contactNumber, 
        emergencyNumber1 = 0, 
        emergencyNumber2 = 0,
        emergencyNumber3 = 0,
        emergencyNumber4 = 0,
        emergencyNumber5 = 0
    } = req.body
    
    // Validate required fields
    if (!firstName || !lastName || !email || !password || !contactNumber) {
        throw new ApiError(400, "All required fields must be filled")
    }

    // Validate contact number and emergency numbers
    if (isNaN(contactNumber) || contactNumber <= 0) {
        throw new ApiError(400, "Invalid contact number")
    }
    if (emergencyNumber1 && (isNaN(emergencyNumber1) || emergencyNumber1 <= 0)) {
        throw new ApiError(400, "Invalid emergency number 1")
    }
    // Validate other emergency numbers similarly

    // Check for existing user
    const existedUser = await User.findOne({
        $or: [
            { email: email.toLowerCase() }, 
            { contactNumber }
        ]
    })

    if (existedUser) {
        if (existedUser.email === email.toLowerCase()) {
            throw new ApiError(409, "User with this email already exists")
        }
        if (existedUser.contactNumber === contactNumber) {
            throw new ApiError(409, "User with this contact number already exists")
        }
    }

    // Create user
    try {
        const user = await User.create({
            firstName: firstName.trim(), 
            lastName: lastName.trim(),
            email: email.toLowerCase().trim(), 
            password, 
            contactNumber, 
            emergencyNumber1,
            emergencyNumber2,
            emergencyNumber3,
            emergencyNumber4,
            emergencyNumber5
        })

        // Fetch created user without sensitive info
        const createdUser = await User.findById(user._id).select(
            "-password -refreshToken"
        )

        if (!createdUser) {
            throw new ApiError(500, "Something went wrong while registering user")
        }

        return res.status(201).json(
            new ApiResponse(201, createdUser, "User registered successfully")
        )
    } catch (error) {
        // Handle potential mongoose validation errors
        if (error.name === 'ValidationError') {
            const errorMessages = Object.values(error.errors)
                .map(err => err.message)
                .join(', ')
            throw new ApiError(400, `Validation Error: ${errorMessages}`)
        }
        // Re-throw other errors
        throw error
    }
})


const login = asyncHandler(async (req, res) => {
    const {email, password} = req.body

    if(!email){
        throw new ApiError(400, "email is required!!!")
    }

    const user = await User.findOne({
        $or: [{email}]
    })

    if(!user){
        throw new ApiError(404, "user doesnot exists!!")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)
    if(!isPasswordValid){
        throw new ApiError(401, "Password Incorrect!!")
    }

    const {accessToken, refreshToken} = await generateAccessAndRefreshToken(user._id)
    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res.status(200).cookie("accessToken", accessToken, options).cookie("refreshToken", refreshToken, options).json(new ApiResponse(
        200,
        {
            user: loggedInUser, accessToken, refreshToken
        },
        "User Logged In Successfully"
    ))
})

const logout = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )
    const options = {
        httpOnly: true,
        secure: true
    }
    return res.status(200).clearCookie("accessToken", options).clearCookie("refreshToken", options).json(new ApiResponse(200, {}, "User Logged Out Successfully"))
})

const refreshAccessToken = asyncHandler(async (req,res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken
    if(!incomingRefreshToken){
        throw new ApiError(401, "Unauthorised request!!!")
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
    
        const user = await User.findById(decodedToken?._id)
    
        if (!user){
            throw new ApiError(401, "Invalid refresh token!!!")
        }
    
        if (incomingRefreshToken !== usre?.refreshToken) {
            throw new ApiError(401, "Refresh token expired!!!")
        }
    
        const options = {
            httpOnly: true,
            secure: true
        }
    
        const {accessToken, newRefreshToken} = await generateAccessAndRefreshToken(user._id)
    
        return res.status(200).cookie("accessToken", accessToken, options).cookie("refreshToken", newRefreshToken, options).json(
            new ApiResponse(
                200,
                {accessToken, refreshToken: newRefreshToken},
                "Access Token refreshed!!!"
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || 'Invalid refresh token!!!')
    }

})

const changePassword = asyncHandler(async (req, res) => {
    const {oldPassword, newPassword} = req.body

    const user = await Chapter.findById(req.user?._id)

    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if(!isPasswordCorrect){
        throw new ApiError(400, "Invalid Current Password!!!")
    }

    user.password = newPassword
    await user.save({validateBeforeSave: false})
    
    return res.status(200).json(new ApiResponse(200, {}, "Password Changed Successfully!!!"))
})

const getSosContacts = asyncHandler(async (req, res) => {
    // Get the user ID from the request (e.g., from the JWT token)
    const userId = req.user._id;

    try {
        // Find the user by the ID and select only the emergency contact number fields
        const user = await User.findById(userId, {
            emergencyNumber1: 1,
            emergencyNumber2: 1,
            emergencyNumber3: 1,
            emergencyNumber4: 1,
            emergencyNumber5: 1
        });

        if (!user) {
            throw new ApiError(404, 'User not found');
        }

        // Extract the emergency contact numbers
        const sosContacts = {
            emergencyNumber1: user.emergencyNumber1,
            emergencyNumber2: user.emergencyNumber2,
            emergencyNumber3: user.emergencyNumber3,
            emergencyNumber4: user.emergencyNumber4,
            emergencyNumber5: user.emergencyNumber5
        };

        return res.status(200).json(
            new ApiResponse(200, sosContacts, 'Emergency contact numbers retrieved')
        );
    } catch (error) {
        if (error.name === 'CastError') {
            throw new ApiError(400, 'Invalid user ID');
        }
        throw error;
    }
});
const updateSosContacts = asyncHandler(async (req, res) => {
    // Get the user ID from the request (e.g., from the JWT token)
    const userId = req.user._id;

    try {
        // Extract the emergency numbers from the request body
        const { emergencyNumber1, emergencyNumber2, emergencyNumber3, emergencyNumber4, emergencyNumber5 } = req.body;

        // Validate the request body (add custom validation logic if needed)
        if (
            [emergencyNumber1, emergencyNumber2, emergencyNumber3, emergencyNumber4, emergencyNumber5].some(
                (num) => num && typeof num !== 'number'
            )
        ) {
            throw new ApiError(400, 'All emergency numbers must be valid numbers');
        }

        // Update the user's emergency numbers
        const user = await User.findByIdAndUpdate(
            userId,
            { emergencyNumber1, emergencyNumber2, emergencyNumber3, emergencyNumber4, emergencyNumber5 },
            { new: true, runValidators: true }
        );

        if (!user) {
            throw new ApiError(404, 'User not found');
        }

        return res.status(200).json(
            new ApiResponse(200, {
                emergencyNumber1: user.emergencyNumber1,
                emergencyNumber2: user.emergencyNumber2,
                emergencyNumber3: user.emergencyNumber3,
                emergencyNumber4: user.emergencyNumber4,
                emergencyNumber5: user.emergencyNumber5
            }, 'Emergency contact numbers updated successfully')
        );
    } catch (error) {
        if (error.name === 'CastError') {
            throw new ApiError(400, 'Invalid user ID');
        }
        throw error;
    }
});


export {
    register,
    login,
    logout,
    refreshAccessToken,
    getSosContacts,
    changePassword,
    updateSosContacts
};