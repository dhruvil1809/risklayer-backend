import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import db from "../config/db";
import { logger } from "../utils/logger";
import { sendEmail } from "../utils/mailer";
import { generateOtpEmail } from "../utils/emailTemplates";
import { createApiError } from "../utils/ApiError";
import { sendResponse } from "../utils/ApiResponse";
import { RequestVerifySchema, VerifyOtpSchema, IRequestVerifyInput, IVerifyOtpInput } from "../models";

const JWT_SECRET = process.env.JWT_SECRET || "default_super_secret_jwt_key";

export const requestVerify = async (req: Request, res: Response): Promise<void> => {
    try {
        const validatedData = RequestVerifySchema.safeParse(req.body);

        if (!validatedData.success) {
            throw createApiError(400, (validatedData.error as any).errors[0].message);
        }

        const { email, captchaToken }: IRequestVerifyInput = validatedData.data;

        if (!captchaToken && process.env.NODE_ENV !== "development") {
            throw createApiError(400, "Captcha verification is required");
        }

        // Verify Captcha with Google
        if (captchaToken) {
            const secretKey = process.env.RECAPTCHA_SECRET_KEY;
            const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${captchaToken}`;

            const recaptchaRes = await fetch(verifyUrl, { method: "POST" });
            const recaptchaData = await recaptchaRes.json();

            if (!recaptchaData.success) {
                throw createApiError(400, "Invalid Captcha. Please try again.");
            }
        }

        // Generate a random 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        console.log("OTP:", otp);
        // Set expiry to 5 minutes from now
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

        // Check if user exists
        const user = await db.user.findUnique({
            where: { email },
            select: { id: true },
        });

        if (!user) {
            // New user, create them
            await db.user.create({
                data: {
                    email,
                    verify_token: otp,
                    verify_token_expires_at: expiresAt,
                },
            });
            logger.info(`New user created for email: ${email}`);
        } else {
            // Existing user, update their OTP
            await db.user.update({
                where: { email },
                data: {
                    verify_token: otp,
                    verify_token_expires_at: expiresAt,
                },
            });
        }

        // Send the real email using Nodemailer
        const emailHtml = generateOtpEmail(otp);
        await sendEmail(email, "Your RiskLayer Verification Code", emailHtml);

        sendResponse(res, 200, "Verification code sent to email.");
    } catch (error) {
        throw error; // Express 5 automatically catches thrown async errors and routes to errorHandler
    }
};

export const verifyOtp = async (req: Request, res: Response): Promise<void> => {
    try {
        const validatedData = VerifyOtpSchema.safeParse(req.body);

        if (!validatedData.success) {
            throw createApiError(400, (validatedData.error as any).errors[0].message);
        }

        const { email, otp }: IVerifyOtpInput = validatedData.data;

        const user = await db.user.findUnique({
            where: { email },
            select: { id: true, verify_token: true, verify_token_expires_at: true },
        });

        if (!user) {
            throw createApiError(404, "User not found");
        }

        // Check if token matches
        if (user.verify_token !== otp) {
            throw createApiError(401, "Invalid verification code");
        }

        // Check expiry
        if (!user.verify_token_expires_at || new Date() > new Date(user.verify_token_expires_at)) {
            throw createApiError(401, "Verification code has expired");
        }

        // Token is valid, mark verified and nullify the token
        await db.user.update({
            where: { email },
            data: {
                is_verified: true,
                verify_token: null,
                verify_token_expires_at: null,
            },
        });

        // Generate stateless JWT for now (Since we are skipping Sessions table)
        const token = jwt.sign({ userId: user.id, email }, JWT_SECRET, {
            expiresIn: "7d",
        });

        sendResponse(res, 200, "Authentication successful", {
            token,
            user: { id: user.id, email, is_verified: true },
        });
    } catch (error) {
        throw error;
    }
};
