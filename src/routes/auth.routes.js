import { Router } from 'express';
import * as authController from '../controllers/auth.controllers.js';


const authRouter = Router();


authRouter.post('/register', authController.registerUser);
authRouter.get('/get-me', authController.getMe);


authRouter.get('/refresh-token', authController.refreshToken);

export default authRouter;