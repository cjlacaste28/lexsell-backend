import 'dotenv/config';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import { validationResult } from 'express-validator';
import _ from 'lodash';
import randomstring from 'randomstring';
import httpStatus from "../utils/httpStatus";
import userModel from "../models/user.model";
import { transformAuthInfo } from 'passport';

import sgMail from '@sendgrid/mail';

//Sendgrid API KEY Setup
sgMail.setApiKey(process.env.SENDGRID_API_KEY)

//google client id to OAuth2Client
const client = new OAuth2Client(process.env.GOOGLE_CLIENT);
const authController = {};

// REGISTER EMAIL
authController.register = (req, res) => {
    const { firstName, lastName, email, password, gender, country, region } = req.body;
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        const firstError = errors.array().map(error => error.msg)[0];
        return res.status(httpStatus.UNPROCESSABLE_ENTITY).json({
            success: false,
            type: "danger",
            message: firstError
        });
    } else {
        userModel.findOne({ email }).exec((err, user) => {
            if (user) {
                return res.status(httpStatus.BAD_REQUEST).json({
                    error: true,
                    type: "warning",
                    message: "Email is already registered."
                });
            }
        });

        //FOR TOKEN BINDING
        const token = jwt.sign(
            {
                firstName, lastName, email, password, gender, country, region
            },
            process.env.JWT_ACCOUNT_ACTIVATION,
            {
                expiresIn: process.env.JWT_EXPIRATION
            }
        );

        //EMAIL CONTENT DETAILS
        const emailData = {
            from: process.env.EMAIL_FROM,
            to: email,
            subject: 'Account activation link',
            html: `
                <h1>Please use the following to activate your account</h1>
                <p>${process.env.CLIENT_URL}/users/activate/${token}</p>
                <hr />
                <p>This email may containe sensetive information</p>
                <p>${process.env.CLIENT_URL}</p>
            `
        };

        //SENDING EMAIL
        sgMail
            .send(emailData)
            .then(sent => {
                return res.json({
                    success: true,
                    type: "success",
                    message: `Email has been sent to ${email}. Please activate your account.`
                });
            })
            .catch(err => {
                //RETURN ERROR IF EMAIL FAILED
                return res.status(httpStatus.BAD_REQUEST).json({
                    success: false,
                    type: "danger",
                    message: err
                });
            });
    }
};

// ACTIVATION
authController.activation = (req, res) => {
    const { token } = req.body;

    // Checks if has token
    if (token) {
        // Validate token
        jwt.verify(token, process.env.JWT_ACCOUNT_ACTIVATION, (err, decoded) => {
            if (err) {
                console.log('Activation error');
                // Return if token is expired
                return res.status(httpStatus.UNAUTHORIZED).json({
                    success: false,
                    type: "warning",
                    message: 'Expired link. Please register again'
                });
            } else {

                // Deconstruct token
                const { firstName, lastName, email, password, gender, country, region } = jwt.decode(token);

                // Assign details to user 
                const user = new userModel({
                    firstName, lastName, email, password, gender, country, region
                });

                // Save user to database
                user.save((err, user) => {
                    if (err) {
                        // Catch unexpected error
                        console.log('Save error -> ' + err);
                        return res.status(httpStatus.UNAUTHORIZED).json({
                            success: false,
                            type: "danger",
                            message: "Activation link already used. Please try to login."
                        });
                    } else {
                        // Activation Complete
                        return res.json({
                            success: true,
                            type: "sucess",
                            message: 'Activation Successful',
                            user: user
                        });
                    }
                });
            }
        });
    } else {
        // Catch Token Error
        return res.json({
            success: false,
            type: "warning",
            message: 'Error happening please try again'
        });
    }
};

// LOGIN
authController.login = (req, res,) => {
    const { email, password } = req.body;
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const firstError = errors.array().map(error => error.msg)[0];
        return res.status(httpStatus.UNPROCESSABLE_ENTITY).json({
            success: false,
            type: "danger",
            message: firstError
        });
    } else {
        // Check if user exist
        userModel.findOne({ email }).exec((err, user) => {
            if (err || !user) {
                return res.status(httpStatus.BAD_REQUEST).json({
                    success: false,
                    type: "warning",
                    message: 'Account with that email does not exist. Please register.'
                });
            }
            // Authenticate
            if (!user.authenticate(password)) {
                return res.status(httpStatus.BAD_REQUEST).json({
                    success: false,
                    type: "warning",
                    message: 'Email and password do not match'
                });
            }
            // Generate a token and send to client
            const token = jwt.sign(
                {
                    _id: user._id
                },
                process.env.JWT_SECRET,
                {
                    expiresIn: process.env.JWT_EXPIRATION
                }
            );

            const { _id, firstName, lastName, email, role, gender, country, region } = user;

            return res.json({
                success: true,
                type: "sucess",
                message: 'Login Successful',
                token,
                user: {
                    _id, firstName, lastName, email, role, gender, country, region
                }
            });
        });
    }
};

// FORGOT PASSWORD
authController.forgotPassword = (req, res) => {
    const { email } = req.body;
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        const firstError = errors.array().map(error => error.msg)[0];
        return res.status(httpStatus.UNPROCESSABLE_ENTITY).json({
            success: false,
            type: "danger",
            message: firstError
        });
    } else {
        // Check if user exist
        userModel.findOne({ email }, (err, user) => {
            if (err || !user) {
                return res.status(httpStatus.BAD_REQUEST).json({
                    success: false,
                    type: "warning",
                    message: 'Account with that email does not exist. Please register.'
                });
            }
            // Generate a token and send to client
            const token = jwt.sign(
                {
                    _id: user._id
                },
                process.env.JWT_RESET_PASSWORD,
                {
                    expiresIn: process.env.JWT_EXPIRATION
                }
            );

            // EMAIL CONTENT DETAILS
            const emailData = {
                from: process.env.EMAIL_FROM,
                to: email,
                subject: `Password Reset link`,
                html: `
                      <h1>Please use the following link to reset your password</h1>
                      <p>${process.env.CLIENT_URL}/users/password/reset/${token}</p>
                      <hr />
                      <p>This email may contain sensetive information</p>
                      <p>${process.env.CLIENT_URL}</p>
                  `
            };

            // Store reset password token to account
            return user.updateOne({ resetPasswordLink: token }, (err, success) => {
                if (err) {
                    console.log('RESET PASSWORD LINK ERROR', err);
                    return res.status(httpStatus.BAD_REQUEST).json({
                        success: false,
                        type: "danger",
                        message:
                            'Database connection error on user password forgot request'
                    });
                } else {
                    // SEND MAIL
                    sgMail
                        .send(emailData)
                        .then(sent => {
                            return res.json({
                                success: true,
                                type: "success",
                                message: `Email has been sent to ${email}. Follow the instruction to activate your account`
                            });
                        })
                        .catch(err => {
                            return res.json({
                                success: false,
                                type: "danger",
                                message: err.message
                            });
                        });
                }
            });
        });
    }
};

// RESET PASSWORD
authController.resetPassword = (req, res) => {

    const { resetPasswordLink, newPassword } = req.body;

    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        const firstError = errors.array().map(error => error.msg)[0];
        return res.status(httpStatus.UNPROCESSABLE_ENTITY).json({
            success: false,
            type: "danger",
            message: firstError
        });
    } else {
        // Checks if has resetPassword Link
        if (resetPasswordLink) {
            jwt.verify(resetPasswordLink, process.env.JWT_RESET_PASSWORD, function (
                err,
                decoded
            ) {
                if (err) {
                    return res.status(httpStatus.BAD_REQUEST).json({
                        success: false,
                        type: "danger",
                        message: 'Expired link. Please try again.'
                    });
                }

                // Find account with same reset password link
                userModel.findOne({ resetPasswordLink }, (err, user) => {
                    if (err || !user) {
                        return res.status(httpStatus.BAD_REQUEST).json({
                            success: false,
                            type: "danger",
                            message: 'Something went wrong. Try later'
                        });
                    }

                    // Set update record
                    const updatedFields = {
                        password: newPassword,
                        resetPasswordLink: ''
                    };

                    //with Lodash
                    user = _.extend(user, updatedFields);

                    // Update database
                    user.save((err, result) => {
                        if (err) {
                            return res.status(httpStatus.BAD_REQUEST).json({
                                success: false,
                                type: "danger",
                                message: 'Error resetting user password'
                            });
                        }
                        // RESET SUCCESS
                        res.json({
                            success: true,
                            type: "success",
                            message: `Great! Now you can login with your new password`
                        });
                    });
                }
                );
            });
        }
    }
};


authController.googleLogin = async (req, res) => {
    // store the token from googleLogin
    const { tokenId } = req.body;
    client
        .verifyIdToken({ idToken: tokenId, audience: process.env.GOOGLE_CLIENT })
        .then(response => {
            // deconstruct data from google payload
            const { email_verified, given_name, family_name, email } = response.payload;
            if (email_verified) {
                //find if google email exist
                userModel.findOne({ email }).exec((err, user) => {
                    if (user) {
                        // Execute if user exist
                        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
                            expiresIn: process.env.JWT_EXPIRATION
                        });
                        const { _id, firstName, lastName, email, role, gender, country, region } = user;
                        return res.json({
                            success: true,
                            type: "success",
                            message: `Google Login Successful`,
                            token,
                            user: { _id, firstName, lastName, email, role, gender, country, region }
                        });
                    } else {
                        // Create new record
                        let password = email + process.env.JWT_SECRET; // generate initial password
                        user = new userModel({ firstName: given_name, lastName: family_name, email: email, password, gender: '', country: '', region: '' });
                        user.save((err, data) => {
                            if (err) {
                                // Catch unexpected error
                                console.log('ERROR GOOGLE LOGIN ON USER SAVE', err);
                                return res.status(httpStatus.BAD_REQUEST).json({
                                    success: false,
                                    type: "danger",
                                    message: 'User signup failed with google.'
                                });
                            }

                            // Token binding
                            const token = jwt.sign(
                                { _id: data._id },
                                process.env.JWT_SECRET,
                                { expiresIn: process.env.JWT_EXPIRATION }
                            );

                            // Deconstruct user data
                            const { _id, firstName, lastName, email, role, gender, country, region } = data;

                            // Google Login Success
                            return res.json({
                                success: true,
                                type: "success",
                                message: `Google Login Successful`,
                                token,
                                user: { _id, firstName, lastName, email, role, gender, country, region }
                            });
                        });
                    }
                });
            } else {
                // Email not verified or Something went wrong.
                return res.status(httpStatus.BAD_REQUEST).json({
                    success: false,
                    type: "danger",
                    message: 'Google login failed. Try again'
                });
            }
        });
};


/*
authController.googleLogin = (req, res) => {
  
       //gets the tokenId from req
       const { tokenId } = req.body;
   
       //compares the tokenId if valid 
       client.verifyIdToken({ idToken: tokenId, audience: process.env.GOOGLE_CLIENT })
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
                               type: "danger",
                               message: err
                           });
                       } else {
                           if (userInfo) {
                               //store existing google account details to token? :) 
                               const token = jwt.sign(
                                   {
                                       firstName: userInfo.firstName,
                                       lastName: userInfo.lastName,
                                       role: userInfo.role,
                                       email: userInfo.email,
                                       userId: userInfo.id,
                                       firstName: userInfo.firstName,
                                       lastName: userInfo.lastName
                                   },
                                   process.env.JWT_SECRET,
                                   {
                                       expiresIn: process.env.JWT_EXPIRATION
                                   }
                               );
                               //response login confirmation    
                               return res.status(httpStatus.OK).json({
                                   error: false,
                                   type: "success",
                                   message: "Sucessfully Logged In",
                                   user: { userId, email, firstName, lastName, role },
                                   token: token
                               });
                           } else {
                               //goes here if google account is not registered.
   
                               //create generated password using the email and secret key
                               let pw = email + process.env.JWT_SECRET;
                               user = new userModel({ firstName, lastName, email, password });
   
                               //store the details of current google account login.
                               const newUser = userModel.create({
                                   firstName: given_name,
                                   lastName: family_name,
                                   email: email,
                                   password: pw
                               });
   
                               ///store newUser details to token
                               const token = jwt.sign(
                                   {
                                       email: newUser.email,
                                       userId: newUser.id,
                                       role: newUser.role
                                   },
                                   process.env.JWT_SECRET,
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
                                   token: token
   
                               });
                           }
   
   
                       }
                   })
               }
           })
           
}*/


export default authController;