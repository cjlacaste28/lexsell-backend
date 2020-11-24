import 'dotenv/config';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import httpStatus from "../utils/httpStatus"
import userModel from "../models/user.model";

//google client id to OAuth2Client
const client = new OAuth2Client("999962597242-3rbqhpsghmjo9bk3ouihcdr6u3ddqegq.apps.googleusercontent.com");
const authController = {};

authController.register = async (req, res) => {
    //checks if email was already registered
    userModel.find({ email: req.body.email })
        .exec()
        .then((user) => {
            if (user.length >= 1) {

                //return response if email already registered
                return res.status(httpStatus.CONFLICT).json({
                    error: true,
                    type: "warning",
                    message: "Email already registered."
                });
            } else {
                //password encrypt 10 rounds
                bcrypt.hash(req.body.password, 10, async (err, hash) => {
                    if (err) {
                        //catch unexpected error
                        return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                            error: err
                        });
                    } else {
                        //save the user info
                        const newUser = await userModel.create({
                            firstName: req.body.firstName,
                            lastName: req.body.lastName,
                            email: req.body.email,
                            gender: req.body.gender,
                            country: req.body.country,
                            region: req.body.region,
                            password: hash,
                        });
                        let { password, __v, ...user } = newUser.toObject();
                        //return success confirmation
                        return res.status(httpStatus.CREATED).json({
                            error: false,
                            type: "success",
                            info: { user }
                        });
                    }
                });
            }
        });
}

authController.googleLogin = (req, res) => {

    //gets the tokenId from req
    const { tokenId } = req.body;

    //compares the tokenId if valid 
    client.verifyIdToken({ idToken: tokenId, audience: "999962597242-3rbqhpsghmjo9bk3ouihcdr6u3ddqegq.apps.googleusercontent.com" })
        .then((response) => {

            //deconstruct the google response payload details
            const { email_verified, given_name, family_name, email } = response.payload;

            if (email_verified) {

                //checks if google account was already registered
                userModel.findOne({ email }).exec((err, userInfo) => {
                    if (err) {
                        //catch unexpected error
                        return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                            error: true,
                            type: "error",
                            message: err
                        });
                    } else {
                        if (userInfo) {
                            //store existing google account details to token? :) 
                            const token = jwt.sign(
                                {
                                    role: userInfo.role,
                                    email: userInfo.email,
                                    userId: userInfo.id,
                                    firstName: userInfo.firstName,
                                    lastName: userInfo.lastName
                                },
                                process.env.JWT_KEY,
                                {
                                    expiresIn: process.env.JWT_EXPIRATION
                                }
                            );
                            //response login confirmation    
                            return res.status(httpStatus.OK).json({
                                error: false,
                                type: "success",
                                message: "Sucessfully Logged In",
                                token: token
                            });
                        } else {
                            //goes here if google account is not registered.

                            //create generated password using the email and secret key then encrypt 10 rounds
                            bcrypt.hash(email + process.env.MY_SECRET, 10, async (err, hash) => {
                                if (err) {
                                    //catch unexpected error 
                                    return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                                        error: true,
                                        type: "error",
                                        message: err
                                    });
                                } else {
                                    //store the details of current google account login.
                                    const newUser = await userModel.create({
                                        firstName: given_name,
                                        lastName: family_name,
                                        email: email,
                                        password: hash,
                                    });

                                    ///store newUser details to token
                                    const token = jwt.sign(
                                        {
                                            email: newUser.email,
                                            userId: newUser.id,
                                            role: newUser.role
                                        },
                                        process.env.JWT_KEY,
                                        {
                                            expiresIn: process.env.JWT_EXPIRATION
                                        }
                                    );
                                    let { password, __v, ...user } = newUser.toObject();
                                    // -- Dev Note: Check kung pwede access yung info using token
                                    //response login confirmation  
                                    return res.status(httpStatus.CREATED).json({
                                        error: false,
                                        type: "success",
                                        message: "Sucessfully Logged In",
                                        token: token,
                                        info: { user }
                                    });
                                }
                            });
                        }
                    }
                })
            }
        })
}

authController.login = async (req, res,) => {
    userModel
        .find({ email: req.body.email })
        .exec()
        .then((user) => {
            if (user.length < 1) {
                return res.status(httpStatus.UNAUTHORIZED).json({
                    error: true,
                    type: "error",
                    message: "Auth failed. Account does not exist."
                });
            }
            bcrypt.compare(req.body.password, user[0].password, (err, result) => {
                if (err) {
                    return res.status(httpStatus.UNAUTHORIZED).json({
                        error: true,
                        type: "error",
                        message: "Auth failed. Unauthorized."
                    });
                }
                if (result) {
                    //--embed the additional fields ex. Role
                    const token = jwt.sign(
                        {
                            email: user[0].email,
                            userId: user[0].id,
                            role: user[0].role
                        },
                        process.env.JWT_KEY,
                        {
                            expiresIn: process.env.JWT_EXPIRATION
                        }
                    );
                    return res.status(httpStatus.OK).json({
                        error: false,
                        type: "success",
                        message: "Sucessfully Logged In",
                        token: token,
                    });
                }
                res.status(httpStatus.UNAUTHORIZED).json({
                    error: true,
                    type: "error",
                    message: "Login Failed. Incorrect Email or Password"
                });
            });
        })
        .catch(err => {
            res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                error: err
            });
        });
}

export default authController;