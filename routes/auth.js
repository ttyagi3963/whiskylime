const express = require('express');
const { check, body } = require('express-validator/check')

const authController = require('../controllers/auth');
const User = require('../models/user')

const router = express.Router();

router.get('/login', authController.getLogin);

router.get('/signup', authController.getSignup);

router.post('/login',[
                body('email')
                .isEmail()
                .withMessage("Please enter a valid email")
                .normalizeEmail(),

                body('password','please enter a valid password')
                .isLength({min:6})
                .isAlphanumeric()
                .trim()
             ], 
    authController.postLogin);

router.post('/signup',
            [
                check('email')
                .isEmail()
                .withMessage('Please enter a valid email')
                .normalizeEmail()
                .custom((value, { req })=>{
                    return User.findOne({ email: value })
                    .then(userDoc => {
                       return Promise.reject('Email already Exists') 
                    })
                }), 

                body('password',
                'Please enter a password with only numbers and text and at least 5 characters')
                .isLength({min:6})
                .isAlphanumeric()
                .trim(),

                body('confirmPassword').trim().custom((value, {req}) =>{
                    if (value !== req.body.password){
                        throw new Error('passwords have to match');
                    }
                    return true;
                }) 
            ],
                authController.postSignup)
            

router.post('/logout', authController.postLogout);

router.get('/reset', authController.getReset);

router.post('/reset', authController.postReset);

router.get('/reset/:token', authController.getNewPassword);

router.post('/postNewPassword', authController.postNewPassword)

module.exports = router;