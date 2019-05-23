const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const sendGridTransport = require('nodemailer-sendgrid-transport');
const crypto = require ('crypto');
const { validationResult } = require('express-validator/check')

const User = require('../models/user');

const transporter = nodemailer.createTransport(sendGridTransport({
  auth:{
      api_key: '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'
  }
}));

exports.getLogin = (req, res, next) => {
  let message = req.flash('error')
  if(message.length > 0){
    message = message[0];
  }else
  {
    message= null
  }
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage:  message,
    oldInput:{email:'',password:''},
    validationErrors:[]
   
  });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash('error')
  if(message.length > 0){
    message = message[0];
  }else
  {
    message= null
  }
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    isAuthenticated: false,
    errorMessage:  message, 
    oldInput:{ email:'',password:'',confirmPassword:''},
    validationErrors:[]
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  const errors = validationResult(req)
  if(!errors.isEmpty()){
    console.log(errors.array())
    return res.status(422).render(
      'auth/login', {
        path: '/login',
        pageTitle: 'login',
        isAuthenticated: false,
        errorMessage: errors.array()[0].msg,
        oldInput:{
          email:email,
          password:password
        },
        validationErrors: errors.array()
      })
  }

  User.findOne({ email: email })
    .then(user => {
      if (!user) {

        return res.status(422).render(
          'auth/login', {
            path: '/login',
            pageTitle: 'login',
            isAuthenticated: false,
            errorMessage: 'Invalid email or password',
            oldInput:{
              email:email,
              password:password
            },
            validationErrors: []
          })
      }
      bcrypt
        .compare(password, user.password)
        .then(doMatch => {
          if (doMatch) {
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save(err => {
              console.log(err);
              res.redirect('/');
            });
          }
          return res.status(422).render(
            'auth/login', {
              path: '/login',
              pageTitle: 'login',
              isAuthenticated: false,
              errorMessage: 'Invalid email or password',
              oldInput:{
                email:email,
                password:password
              },
              validationErrors: []
            })
        })
        .catch(err => {
          console.log(err);
          res.redirect('/login');
        });
    })
    .catch(err => console.log(err));
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  

  const errors = validationResult(req)
  if(!errors.isEmpty()){
    console.log(errors.array())
    return res.status(422).render(
      'auth/signup', {
        path: '/signup',
        pageTitle: 'Signup',
        isAuthenticated: false,
        errorMessage: errors.array()[0].msg,
        oldInput: {email:email, password:password, confirmPassword: req.body.confirmPassword},
        validationErrors: errors.array()
      })
  }


        bcrypt
        .hash(password, 12)
        .then(hashedPassword => {
          const user = new User({
            email: email,
            password: hashedPassword,
            cart: { items: [] }
          });
          return user.save();
        })
        .then(result => {
          res.redirect('/login');
          return transporter.sendMail({
            to: email,
            from:'shop@node-complete.com',
            subject:'verify your email address',
            html:'<h1>your sign was successful</h1>'
          })
         
        }).catch(err =>{
          console.log("error sending email", err)
        })
    
   
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};


exports.getReset = (req, res, next) => {
  let message = req.flash('error')
  if(message.length > 0){
    message = message[0];
  }else
  {
    message= null
  }
  res.render('auth/reset', {
    path: '/reset',
    pageTitle: 'Reset Password',
    isAuthenticated: false,
    errorMessage:  message
  });
};

exports.postReset = (req, res, next) => {
  const email =  req.body.email
  crypto.randomBytes(32,(err, buffer)=>{
    if (err){
      console.log(err);
     return  res.redirect('/')
    }

    const token = buffer.toString('hex');
    User.findOne({email: email})
        .then(user =>{
                if (!user){
                  req.flash('error', 'no account with that email found')
                  return res.redirect('/reset')
                }

                user.resetToken = token;
                user.resetTokenExpiration = Date.now() + 3600000
                return user.save();
        })//end of find one then
        .then(result =>{
         
          transporter.sendMail({
            to: email,
            from:'shop@node-complete.com',
            subject:'password reset',
            html:     `
                        <p> You requested password reset</p>
                        <p> click this <a href="http://localhost:3000/reset/${token}">link</a>  to set a new password .</p>

                     `
          })
          res.redirect('/')
        })
        .catch(err =>{
      console.log(err)
    })

  })// end of random
}

exports.getNewPassword = (req,res,next) =>{
  const  token  = req.params.token;
  User.findOne({resetToken: token, resetTokenExpiration: {$gt: Date.now()}})
      .then(user =>{
          let message = req.flash('error')
          if(message.length > 0){
            message = message[0];
          }else
          {
            message= null
          }
          res.render('auth/new-password', {
            path: '/new-password',
            pageTitle: 'New Password',
            isAuthenticated: false,
            errorMessage:  message,
            userId: user._id.toString(),
            passwordToken: token
          });
      })
      .catch(err =>{
          console.log(err)
      })

  
}

exports.postNewPassword = (req, res, next) =>{
  const password = req.body.password;
  const userId = req.body.userId;
  const passwordToken = req.body.passwordToken;
  let resetUser;

  User.findOne({ resetToken: passwordToken, 
                resetTokenExpiration: {$gt: Date.now()},
                _id: userId
                })
                .then(user =>{
                  resetUser = user;
                   return bcrypt.hash(password, 12);

                })
                .then(hashedPassword => {
                  resetUser.password =  hashedPassword;
                  resetUser.resetToken = undefined;
                  resetUser.resetTokenExpiration = undefined;
                  return resetUser.save()
                })
                .then( result => {
                  res.redirect('/login')
                })
                .catch(err => {
                  console.log(err)
                })

}