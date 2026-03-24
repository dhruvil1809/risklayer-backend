import { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, Mail, Lock, ShieldCheck, Loader2 } from "lucide-react";
import ReCAPTCHA from "react-google-recaptcha";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import { useFormik } from "formik";
import * as Yup from "yup";
import { Button } from "./ui/Button";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:5000";
const RECAPTCHA_SITE_KEY = import.meta.env.VITE_RECAPTCHA_SITE_KEY || "";

type Step = "captcha" | "email" | "verify";

interface ScanModalProps {
    isOpen: boolean;
    onClose: () => void;
    url: string;
}

export default function ScanModal({ isOpen, onClose, url }: ScanModalProps) {
    const [step, setStep] = useState<Step>("captcha");
    const [captchaToken, setCaptchaToken] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const emailFormik = useFormik({
        initialValues: { email: "" },
        validationSchema: Yup.object({
            email: Yup.string().email("Invalid email address").required("Email is required"),
        }),
        onSubmit: async (values) => {
            setLoading(true);
            setError(null);
            try {
                await axios.post(`${API_URL}/api/auth/request-verify`, {
                    email: values.email,
                    captchaToken,
                });
                setStep("verify");
            } catch (err: any) {
                setError(err.response?.data?.message || "Failed to send verification code. Please try again.");

                if (err.response?.status === 400 && err.response?.data?.message?.toLowerCase().includes("captcha")) {
                    setCaptchaToken(null);
                    setStep("captcha");
                }
            } finally {
                setLoading(false);
            }
        },
    });

    const otpFormik = useFormik({
        initialValues: { otp: "" },
        validationSchema: Yup.object({
            otp: Yup.string().length(6, "Must be exactly 6 digits").required("OTP is required"),
        }),
        onSubmit: async (values) => {
            setLoading(true);
            setError(null);
            try {
                const res = await axios.post(`${API_URL}/api/auth/verify`, {
                    email: emailFormik.values.email,
                    otp: values.otp,
                });
                const token = res.data.data.token;
                localStorage.setItem("token", token);

                // 🔹 NEW: Trigger the actual scan after successful auth
                const scanRes = await axios.post(`${API_URL}/api/scan/start`,
                    { url },
                    { headers: { Authorization: `Bearer ${token}` } }
                );

                const scanId = scanRes.data.data.scanId;

                onClose();
                navigate(`/dashboard/${scanId}`);
            } catch (err: any) {
                setError(err.response?.data?.message || "Invalid verification code or scan failed.");
            } finally {
                setLoading(false);
            }
        },
    });

    const recaptchaRef = useRef<ReCAPTCHA>(null);
    const navigate = useNavigate();

    // Reset state when modal opens
    useEffect(() => {
        if (isOpen) {
            setStep("captcha");
            setCaptchaToken(null);
            emailFormik.resetForm();
            otpFormik.resetForm();
            setError(null);
            setLoading(false);
            if (recaptchaRef.current) {
                recaptchaRef.current.reset();
            }
        }
    }, [isOpen]);

    const handleCaptchaVerify = async (token: string | null) => {
        if (token) {
            setError(null);
            setCaptchaToken(token);
            
            const authToken = localStorage.getItem("token") || localStorage.getItem("accessToken");
            if (authToken) {
                setLoading(true);
                try {
                    const scanRes = await axios.post(`${API_URL}/api/scan/start`,
                        { url },
                        { headers: { Authorization: `Bearer ${authToken}` } }
                    );

                    const scanId = scanRes.data.data.scanId;
                    onClose();
                    navigate(`/dashboard/${scanId}`);
                } catch (err: any) {
                    setError(err.response?.data?.message || "Failed to start scan.");
                    setLoading(false);
                }
            } else {
                setTimeout(() => {
                    setStep("email");
                }, 400); // Small delay to let user see it checked
            }
        }
    };

    if (!isOpen) return null;

    // Framer motion variants for smooth transitions
    const stepVariants = {
        hidden: { opacity: 0, x: 20 },
        visible: { opacity: 1, x: 0 },
        exit: { opacity: 0, x: -20 }
    };

    return (
        <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-1000 p-4"
        >
            <motion.div
                initial={{ scale: 0.95, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                exit={{ scale: 0.95, opacity: 0 }}
                transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
                className="bg-white border border-slate-200 rounded-[24px] w-full max-w-[450px] p-8 shadow-2xl overflow-hidden"
            >
                <div className="flex justify-between items-center mb-6">
                    <h2 className="text-2xl font-black m-0 text-text-dark tracking-tight">Verify Request</h2>
                    <Button type="button" variant="custom" size="none" display="" rounded="" fontWeight="" className="w-8 h-8 rounded-full bg-slate-50 border border-slate-200 text-slate-500 hover:bg-slate-100 hover:text-text-dark flex items-center justify-center transition-colors p-0!" onClick={onClose}>
                        <X className="w-5 h-5" />
                    </Button>
                </div>

                <div className="mb-6">
                    <label className="block text-sm text-slate-600 mb-2 font-bold tracking-wide">Scanning URL</label>
                    <div className="py-3 px-4 bg-slate-50 rounded-xl text-slate-600 overflow-hidden text-ellipsis whitespace-nowrap border border-slate-200 font-mono text-sm shadow-inner group-hover:border-primary/40 transition-colors">
                        {url}
                    </div>
                </div>

                {error && (
                    <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="text-red-600 bg-red-50 p-3 rounded-xl border border-red-100 text-sm mb-6 font-medium">
                        {error}
                    </motion.div>
                )}

                <div className="relative min-h-[160px]">
                    <AnimatePresence mode="wait">
                        {/* --- STEP 1: CAPTCHA --- */}
                        {step === "captcha" && (
                            <motion.div
                                key="captcha"
                                variants={stepVariants}
                                initial="hidden"
                                animate="visible"
                                exit="exit"
                                transition={{ duration: 0.2 }}
                                className="w-full flex flex-col items-center justify-center py-4"
                            >
                                <div className="mb-4 text-center">
                                    <h3 className="text-text-dark font-bold text-lg mb-1 tracking-tight">Security Check</h3>
                                    <p className="text-slate-500 text-sm font-medium">Please verify you are human to continue.</p>
                                </div>
                                <div className="flex justify-center">
                                    <div
                                        className="relative overflow-hidden rounded-xl border border-slate-200 shadow-sm transition-all duration-300 hover:border-primary/30 hover:shadow-md group bg-slate-50"
                                        style={{ width: 300, height: 74 }}
                                    >
                                        <div className="absolute" style={{ top: -2, left: -2 }}>
                                            <ReCAPTCHA
                                                ref={recaptchaRef}
                                                sitekey={RECAPTCHA_SITE_KEY}
                                                onChange={handleCaptchaVerify}
                                                theme="light"
                                            />
                                        </div>
                                        <div className="absolute inset-0 pointer-events-none rounded-xl border border-slate-200 transition-colors group-hover:bg-primary/5" />
                                    </div>
                                </div>
                            </motion.div>
                        )}


                        {/* --- STEP 2: EMAIL --- */}
                        {step === "email" && (
                            <motion.div
                                key="email"
                                variants={stepVariants}
                                initial="hidden"
                                animate="visible"
                                exit="exit"
                                transition={{ duration: 0.2 }}
                                className="w-full"
                            >
                                <form onSubmit={emailFormik.handleSubmit}>
                                    <div className="mb-6">
                                        <label className="block text-sm text-slate-600 mb-2 font-bold tracking-wide">Report Delivery Email*</label>
                                        <div className="relative">
                                            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                                                <Mail className="w-5 h-5" />
                                            </div>
                                            <input
                                                type="email"
                                                name="email"
                                                className={`w-full bg-slate-50 border ${emailFormik.touched.email && emailFormik.errors.email ? 'border-red-400 focus:border-red-500 focus:shadow-[0_0_0_2px_rgba(239,68,68,0.1)]' : 'border-slate-200 focus:border-primary focus:shadow-[0_0_0_2px_rgba(0,229,255,0.1)]'} text-text-dark font-medium py-3 pl-10 pr-4 rounded-xl text-base outline-none transition-all placeholder:text-slate-400 focus:bg-white inset-shadow-sm`}
                                                placeholder="name@company.com"
                                                value={emailFormik.values.email}
                                                onChange={emailFormik.handleChange}
                                                onBlur={emailFormik.handleBlur}
                                                required
                                                autoFocus
                                            />
                                        </div>
                                        {emailFormik.touched.email && emailFormik.errors.email ? (
                                            <div className="text-red-500 font-medium text-sm mt-2">{emailFormik.errors.email}</div>
                                        ) : null}
                                    </div>

                                    <Button
                                        type="submit"
                                        variant="primary"
                                        size="lg"
                                        fullWidth
                                        disabled={loading || !emailFormik.isValid}
                                        text={loading ? "Sending Code..." : "Send Verification Code"}
                                        startIcon={loading ? <Loader2 className="w-5 h-5 animate-spin" /> : undefined}
                                    />
                                </form>
                            </motion.div>
                        )}

                        {/* --- STEP 3: OTP VERIFY --- */}
                        {step === "verify" && (
                            <motion.div
                                key="verify"
                                variants={stepVariants}
                                initial="hidden"
                                animate="visible"
                                exit="exit"
                                transition={{ duration: 0.2 }}
                                className="w-full"
                            >
                                <form onSubmit={otpFormik.handleSubmit}>
                                    <div className="mb-8 text-center">
                                        <div className="w-14 h-14 bg-primary/10 rounded-full flex items-center justify-center mx-auto mb-4 text-primary border border-primary/20">
                                            <ShieldCheck className="w-7 h-7" />
                                        </div>
                                        <h3 className="text-text-dark text-xl font-bold mb-2 tracking-tight">Enter Verification Code</h3>
                                        <p className="text-slate-500 text-sm font-medium">We sent a 6-digit code to <span className="text-text-dark font-bold">{emailFormik.values.email}</span></p>
                                    </div>

                                    <div className="mb-6">
                                        <div className="relative">
                                            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                                                <Lock className="w-5 h-5" />
                                            </div>
                                            <input
                                                type="text"
                                                name="otp"
                                                maxLength={6}
                                                className={`w-full bg-slate-50 border ${otpFormik.touched.otp && otpFormik.errors.otp ? 'border-red-400 focus:border-red-500 focus:shadow-[0_0_0_2px_rgba(239,68,68,0.1)]' : 'border-slate-200 focus:border-primary focus:shadow-[0_0_0_2px_rgba(0,229,255,0.1)]'} text-text-dark font-bold py-3 pl-10 pr-4 rounded-xl text-lg tracking-[0.5em] text-center outline-none transition-all placeholder:text-slate-300 focus:bg-white inset-shadow-sm`}
                                                placeholder="------"
                                                value={otpFormik.values.otp}
                                                onChange={(e) => otpFormik.setFieldValue("otp", e.target.value.replace(/[^0-9]/g, ''))}
                                                onBlur={otpFormik.handleBlur}
                                                required
                                                autoFocus
                                            />
                                        </div>
                                        {otpFormik.touched.otp && otpFormik.errors.otp ? (
                                            <div className="text-red-500 font-medium text-sm mt-2 text-center">{otpFormik.errors.otp}</div>
                                        ) : null}
                                    </div>

                                    <Button
                                        type="submit"
                                        variant="primary"
                                        size="lg"
                                        fullWidth
                                        disabled={loading || otpFormik.values.otp.length !== 6}
                                        text={loading ? "Verifying..." : "Start Free Scan"}
                                        startIcon={loading ? <Loader2 className="w-5 h-5 animate-spin" /> : undefined}
                                    />

                                    <Button
                                        type="button"
                                        variant="custom" size="none" display="" rounded="" fontWeight=""
                                        className="w-full mt-4 text-sm font-bold text-slate-500 hover:text-text-dark transition-colors py-2 group flex items-center justify-center gap-1"
                                        onClick={() => setStep("email")}
                                    >
                                        Use a different email
                                    </Button>
                                </form>
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>
            </motion.div>
        </motion.div>
    );
}