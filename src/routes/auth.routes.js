import { Router } from 'express';
import * as authController from '../controllers/auth.controllers.js';


const authRouter = Router();


authRouter.post('/register', authController.registerUser);
authRouter.post('/login', authController.loginUser);



authRouter.get('/get-me', authController.getMe);


authRouter.get('/refresh-token', authController.refreshToken);

authRouter.get('/logout', authController.logoutUser);
authRouter.get('/logout-all', authController.logoutAllSessions);

export default authRouter;