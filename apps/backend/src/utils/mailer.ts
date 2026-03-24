import { Resend } from "resend";
import { logger } from "./logger";

const resend = new Resend(process.env.RESEND_API_KEY);

export const sendEmail = async (to: string, subject: string, html: string) => {
  try {
    const response = await resend.emails.send({
      from: "RiskLayer <onboarding@resend.dev>", // change later to your domain
      to,
      subject,
      html,
    });

    logger.info(`Email sent to ${to}: ${JSON.stringify(response)}`);
    return response;
  } catch (error) {
    logger.error(`Error sending email to ${to}:`, error);
    throw error;
  }
};