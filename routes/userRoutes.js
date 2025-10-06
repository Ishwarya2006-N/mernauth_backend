import express from 'express'
// import userAuth from '../middleware/userAuth.js';
import { getUserData } from '../controller/userController.js';
import newAuth from '../middleware/newAuth.js';

const userRouter= express.Router();

userRouter.get('/data',newAuth,getUserData);

export default userRouter;