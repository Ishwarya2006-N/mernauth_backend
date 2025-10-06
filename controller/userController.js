//controller/userController.js

import userModel from "../model/usermodel.js";

export const getUserData=async(req,res)=>{
    try {
        

        const userId=req.userId;
        // console.log('userId from token:', userId);
        const user=await userModel.findById(userId);

        if(!user){
           return res.json({success:false,message:"user not found"})
        }

        res.json({
            success:true,
            userData:{
                name:user.name,
                isAccountVerified : user.isAccountVerified
            }
        })

    } catch (error) {
        res.json({success:false,message:error.message})
    }
}