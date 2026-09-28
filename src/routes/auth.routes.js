import { Router } from 'express';
import * as authController from '../controllers/auth.controllers.js';


const authRouter = Router();


authRouter.post('/register', authController.registerUser);
authRouter.get('/get-me', authController.getMe);

export default authRouter;