import { Router } from "express";
import { requestVerify, verifyOtp } from "../controllers/auth.controller";

const authRouter = Router();

// Endpoint to request an OTP / Magic Link
authRouter.post("/request-verify", requestVerify);

// Endpoint to verify the OTP and get a JWT
authRouter.post("/verify", verifyOtp);

export default authRouter;
