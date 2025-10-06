//authController.js
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken';
import userModel from '../model/usermodel.js';
import transporter from '../config/nodeMailer.js';
import { EMAIL_VERIFY_TEMPLATE,PASSWORD_RESET_TEMPLATE } from '../config/emailTemplate.js';

//user register
export const register=async(req,res)=>{
    const{name,email,password}=req.body;
    if(!name||!email||!password){
        return res.json({success:false,message:"Missing Details"})
    }
    try {
        const existingUser=await userModel.findOne({email})

         if(existingUser){
            return res.json({success:false,message:"User already exists"})
         }

        const hashedPassword=await bcrypt.hash(password,10);

        const user=new userModel({name,email,password:hashedPassword});

        await user.save();
        //Generating the token for authentification
        const token=jwt.sign({id:user._id},process.env.JWT_SECRET,
             {expiresIn:'7d'}
        );
        //send the token through response with the help of cookie
        res.cookie('token',token,{
            httpOnly:true, //only http request can handle the cookie
            secure:process.env.NODE_ENV === 'production',//it runs on https
            sameSite:process.env.NODE_ENV === 'production'?'none'
            :'strict',
            maxAge:7 * 24 * 160 * 1000
        });
        //We are add codes for mail feature
        //sendin welcome email
        
        const mailOptions={
            from:process.env.SENDER_MAIL,
            to:email,
            subject:"Welcome to project",
            text:`welcome to project your account was successfully created with email id:${email}`
        }
        
        await transporter.sendMail(mailOptions);
        
        return res.json({success:true});
    } 
    catch (error) {
        res.json({success:false,message:error.message})
    }
}

//user login
export const login=async(req,res)=>{
    const{email,password}=req.body;

    if(!email||!password){
        return res.json({success:false,message:" Email and password are Required"})
    }

    try {
        const user=await userModel.findOne({email})
        //if the entered is not available
         if(!user){
            return res.json({success:false,message:"Invalid email"})
         } 
         //then we have to check the password in DB and the one they gave is equal
         const isMatch=await bcrypt.compare(password,user.password)
        
         //if it not matched
         if(!isMatch){
            return res.json({success:false,message:"Invalid password"})
         }
         //if both email and password is fine then we have to create to token for user authenticated and logged in

         //Generating the token for authentification
        const token=jwt.sign({id:user._id},process.env.JWT_SECRET,
             {expiresIn:'7d'}
        );
        //send the token through response with the help of cookie
        res.cookie('token',token,{
            httpOnly:true, //only http request can handle the cookie
            secure:process.env.NODE_ENV === 'production',//it runs on https
            sameSite:process.env.NODE_ENV === 'production'?'none'
            :'strict',
            maxAge:7 * 24 * 160 * 1000
        });
        
        return res.json({success:true});
   
    } 
    catch (error) {
        res.json({success:false,message:error.message})
    }
}

//now logout

export const logout=async(req,res)=>{
    try {
        res.clearCookie('token',{
            httpOnly:true, //only http request can handle the cookie
            secure:process.env.NODE_ENV === 'production',//it runs on https
            sameSite:process.env.NODE_ENV === 'production'?'none'
            :'strict',
            maxAge:7 * 24 * 160 * 1000
        })
        
        return res.json({success:true,message:"logged out"});
         
    } catch (error) {
        res.json({success:false,message:error.message})
    }
}

//send verification otp to the users mail.this only sent the otp to the user mail
export const sendVerifyOtp=async(req,res)=>{
    try {
        const{userId}=req.body;
        const user= await userModel.findById(userId);
        if(user.isAccountVerified){
          res.json({success:false,message:"Acount already verified"})
        }
        //generate otp
        const otp=String(Math.floor(100000+Math.random()*900000))

        user.verifyOtp=otp;
        user.verifyOtpExpireAt=Date.now()+ 24*60*60*1000;

        await user.save();

        //send the otp to the user
        const mailOptions={
            from:process.env.SENDER_MAIL,
            to:user.email,
            subject:"Account verification OTP",
            // text:`Yout OTP is ${otp}. Verify your account using this otp.`,
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}",otp).replace("{{email}}",user.email)
        }
        await transporter.sendMail(mailOptions);
        
        return res.json({success:true,message:'Verification OTP sent on Email'}); 

    } catch (error) {
        res.json({success:false,message:error.message})
    }
} 

//now we have to verify the otp and make them to register the website

export const verifyEmail=async(req,res)=>{
    const{userId,otp}=req.body;
    //we get the userId from the token and token is stored in the cookies so here we need middleware create the cookie and from there we get the token

    if(!userId||!otp){
        return res.json({success:false,message:"Missing Details"})
    }
    try {
        const user= await userModel.findById(userId);//found the email from db

        if(!user){
            return res.json({success:false,message:"User not found"})
        }
        if(user.verifyOtp===''||user.verifyOtp!==otp){
            return res.json({success:false,message:"Invalid OTP"})
        }
        if(user.verifyOtpExpireAt<Date.now()){
            return res.json({success:false,message:"OTP Expired"})
        }
        user.isAccountVerified=true;
        user.verifyOtp='';
        user.verifyOtpExpireAt=Date.now()+ 24*60*60*1000;

        await user.save();
        return res.json({success:true,message:'Email verified Successfully'})


    } catch (error) {
        res.json({success:false,message:error.message})
    }
}

//check if user is authenticated
export const isAuthenticated=async(req,res)=>{
    try {
        res.json({success:true});
    } catch (error) {
        res.json({success:false,message:error.message})
    }
}

//send password reset otp
export const sendResetOtp=async(req,res)=>{
    const {email} =req.body;

    if(!email){
        return res.json({success:false,message:"Email is required"})
    }
    try {
        const user=await userModel.findOne({email});
        if(!user){
        return res.json({success:false,message:"User not found"})
    }
     //generate otp
        const otp=String(Math.floor(100000+Math.random()*900000))

        user.resetOtp=otp;
        user.resetOtpExpireAt=Date.now()+ 15*60*1000;

        await user.save();

        //send the otp to the user
        const mailOptions={
            from:process.env.SENDER_MAIL,
            to:user.email,
            subject:"Password Reset OTP",
            // text:`Your reset OTP is ${otp}. use this OTP to proceed with resetting your password`,
            html:PASSWORD_RESET_TEMPLATE.replace("{{otp}}",otp).replace("{{email}}",user.email)
        }
        await transporter.sendMail(mailOptions);
        
        return res.json({success:true,message:`OTP sent to your email`});
        
    } catch (error) {
        res.json({success:false,message:error.message})
    }
}

//Reset user password
export const resetPassword=async(req,res)=>{
    const {email,otp,newPassword}=req.body;

    if(!email||!otp||!newPassword){
        return res.json({success:false,message:"Email,otp,new password are required"});
    }
    try {
        const user=await userModel.findOne({email});
        if(!user){
            res.json({success:false,message:"user not found"})
        }
        if(user.resetOtp === "" || user.resetOtp !== otp){
            return res.json({success:false,message:"Invalid OTP"})
        }
        if(user.resetOtpExpireAt<Date.now()){
            return res.json({success:false,message:"OTP Expired"})
        }

        //first we have to hash the newpassword sent by the user
        const hashedPassword=await bcrypt.hash(newPassword,10);

        user.password = hashedPassword;
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;

        await user.save();

        return res.json({success:true,message:'password has been reset successfully'})
    } catch (error) {
        res.json({success:false,message:error.message})
    }
}
