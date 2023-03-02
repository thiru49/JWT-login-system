if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config()
}
  
const express = require('express')
const app = express()
const mongoose = require('mongoose')
const User = require('./models/schema')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const dotenv = require('dotenv')
const cookieParser = require('cookie-parser');
const methodOverride = require('method-override')

//jwt authentication
function auth(req,res,next){
    const token = req.cookies['auth-token'];
    if(!token && req.path !== '/login'){
        res.locals.isLoggedIn = false;
        return res.redirect('/login');
    }
    try {
        const verified = jwt.verify(token,process.env.TOKEN_SECRET);
        req.user = verified;
        res.locals.isLoggedIn = true;
        next();
    } catch (error) {
        res.locals.isLoggedIn = false;
        res.status(400).send("cannot permit  without login");
    }
}
app.use(cookieParser());
app.use(express.urlencoded({extended:true}))
app.set('view-engine', 'ejs')

mongoose.connect(process.env.DATA_BASE).then(() => {
    console.log('Connected to MongoDB database');
  }).catch((err) => {
    console.error('Failed to connect to MongoDB database:', err.message);
  });
  

app.get('/',auth,(req,res)=>{
    
    res.render('index.ejs', { name: req.user.name });
})

app.get('/login',(req,res)=>{
    
    res.render('login.ejs')
})
app.get('/register',(req,res)=>{
    
    res.render('register.ejs')
})
app.post('/login', async (req, res) => {
    try {
      //checking if the user is already in the database
      const user = await User.findOne({ email: req.body.email });
      if (!user) {
        return res.status(400).send('Email or password not correct');
      }
  
      const vaildPass = await bcrypt.compare(req.body.password, user.password);
      if (!vaildPass) {
        return res.status(400).send('Invalid password');
      }
  
      const token = jwt.sign({ _id: user._id }, process.env.TOKEN_SECRET);
      res.cookie('auth-token', token).redirect('/');
    } catch (error) {
      res.status(400).send(error);
    }
});
   
app.post('/register',async (req,res)=>{

   //checking if the user is already in the database
   const EmailExist = await User.findOne({email:req.body.email});
   if(EmailExist){
    return res.status(400).send('Email already exists');
   }
    try{
        const hasedPassword = await bcrypt.hash(req.body.password,10)
        User.create({
        name:req.body.name,
        email:req.body.email,
        password:hasedPassword})
        
        res.redirect('/login')
    }catch(e){
        res.status(400).send(e)
    }
});
app.get('/logout', (req, res) => {
    res.clearCookie('auth-token');
    res.redirect('/login');
});

  

app.listen(3005);













