import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../../components/ui/Button';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import { requestVerify } from '../../services/auth/requestVerify';
import { authVerify } from '../../services/auth/authVerify';
import ReCAPTCHA from 'react-google-recaptcha';
import { Loader2, ArrowRight } from 'lucide-react';

const RECAPTCHA_SITE_KEY = import.meta.env.VITE_RECAPTCHA_SITE_KEY || "";

function LoginPage() {
    const [isSubmitted, setIsSubmitted] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [captchaToken, setCaptchaToken] = useState<string | null>(null);

    const recaptchaRef = useRef<ReCAPTCHA>(null);
    const navigate = useNavigate();

    const emailFormik = useFormik({
        initialValues: { email: '' },
        validationSchema: Yup.object({
            email: Yup.string().email('Invalid email address').required('Email is required'),
        }),
        onSubmit: async (values) => {
            if (!captchaToken && RECAPTCHA_SITE_KEY) {
                setError("Please complete the security captcha.");
                return;
            }

            setLoading(true);
            setError(null);
            try {
                await requestVerify({
                    email: values.email,
                    captchaToken: captchaToken as string,
                });
                setIsSubmitted(true);
            } catch (err: any) {
                setError(err.response?.data?.message || "Failed to send verification code. Please try again.");
                if (err.response?.status === 400 && err.response?.data?.message?.toLowerCase().includes("captcha")) {
                    setCaptchaToken(null);
                    if (recaptchaRef.current) recaptchaRef.current.reset();
                }
            } finally {
                setLoading(false);
            }
        },
    });

    const otpFormik = useFormik({
        initialValues: { otp: '' },
        validationSchema: Yup.object({
            otp: Yup.string().length(6, "Must be exactly 6 digits").required("OTP is required"),
        }),
        onSubmit: async (values) => {
            setLoading(true);
            setError(null);
            try {
                const res = await authVerify({
                    email: emailFormik.values.email,
                    otp: values.otp,
                });
                if (res.data?.token) {
                    localStorage.setItem("token", res.data.token);
                }
                navigate('/');
            } catch (err: any) {
                setError(err.response?.data?.message || "Invalid verification code.");
            } finally {
                setLoading(false);
            }
        },
    });

    return (
        <div className="relative w-full py-8 md:py-16 flex flex-col items-center justify-center overflow-hidden">
            {/* Background Side-Grid maintained by layout - adding local subtle depth */}
            <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-primary/2 blur-[100px] rounded-full -translate-y-1/2 translate-x-1/2" />
            <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-primary/2 blur-[100px] rounded-full translate-y-1/2 -translate-x-1/2" />

            <div className="w-full max-w-[480px] px-6 relative z-10">
                <div className="bg-white border border-slate-100 rounded-[24px] md:rounded-[32px] p-6 md:p-10 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)] overflow-hidden relative group">
                    {/* Branded highlight bar */}
                    <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-primary to-transparent opacity-80" />

                    {!isSubmitted ? (
                        <>
                            <div className="text-center mb-8">
                                <h1 className="text-3xl font-black text-text-dark tracking-tighter leading-tight mb-2">
                                    Welcome back
                                </h1>
                                <p className="text-slate-500 font-medium text-sm md:text-base leading-relaxed px-4 mx-auto">
                                    Login to monitor your <span className="text-text-dark font-bold">compliance risk</span>.
                                </p>
                            </div>

                            {error && (
                                <div className="bg-red-50 text-red-600 border border-red-100 p-3 rounded-xl text-xs mb-6 text-center font-bold flex items-center justify-center gap-2">
                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>
                                    {error}
                                </div>
                            )}

                            <form onSubmit={emailFormik.handleSubmit} className="space-y-5">
                                <div className="space-y-2">
                                    <label htmlFor="email" className="block text-[10px] font-black text-slate-400 uppercase tracking-[0.15em] ml-1">Email address</label>
                                    <div className="group relative">
                                        <input
                                            id="email"
                                            type="email"
                                            name="email"
                                            className={`w-full bg-slate-50/50 border-2 ${emailFormik.touched.email && emailFormik.errors.email ? 'border-red-200' : 'border-slate-50 focus:border-primary'} text-text-dark py-3.5 px-5 rounded-xl text-base outline-none transition-all duration-300 placeholder:text-slate-300 focus:bg-white`}
                                            placeholder="johndoe@company.com"
                                            value={emailFormik.values.email}
                                            onChange={emailFormik.handleChange}
                                            onBlur={emailFormik.handleBlur}
                                            required
                                        />
                                        <div className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-300 group-focus-within:text-primary transition-colors">
                                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" /><polyline points="22,6 12,13 2,6" /></svg>
                                        </div>
                                    </div>
                                    {emailFormik.touched.email && emailFormik.errors.email && (
                                        <div className="text-red-500 text-[11px] mt-1 font-bold ml-1">{emailFormik.errors.email}</div>
                                    )}
                                </div>

                                <div className="flex justify-center py-1">
                                    <div className="scale-90 p-1.5 bg-slate-50 rounded-xl border border-slate-100 shadow-sm">
                                        <ReCAPTCHA
                                            ref={recaptchaRef}
                                            sitekey={RECAPTCHA_SITE_KEY}
                                            onChange={(token) => setCaptchaToken(token)}
                                            theme="light"
                                        />
                                    </div>
                                </div>

                                <Button
                                    type="submit"
                                    variant="primary"
                                    fullWidth
                                    className="py-4 text-base font-black rounded-xl shadow-lg shadow-primary/20 active:scale-[0.98] transition-all"
                                    disabled={loading || !emailFormik.values.email}
                                    text={loading ? "Verifying..." : "Continue"}
                                    endIcon={loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <ArrowRight className="w-5 h-5" />}
                                />
                            </form>

                            <div className="relative flex items-center justify-center my-8">
                                <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-slate-100"></div></div>
                                <span className="relative px-4 bg-white text-[9px] font-black text-slate-400 uppercase tracking-[0.2em]">or</span>
                            </div>

                            <button
                                type="button"
                                className="w-full flex items-center justify-center gap-3 bg-white border border-slate-200 py-3.5 rounded-xl text-slate-700 font-bold text-base hover:bg-slate-50 transition-all active:scale-[0.99]"
                                onClick={() => alert("SSO Not yet configured in MVP")}
                            >
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                                    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4" />
                                    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
                                    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05" />
                                    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" />
                                </svg>
                                Continue with Google
                            </button>

                            <div className="text-center mt-8">
                                <p className="text-slate-400 text-[11px] font-medium leading-relaxed px-2">
                                    RiskLayer protects your authentication with <span className="text-text-dark font-bold underline decoration-primary/20">standard encryption</span>.
                                </p>
                            </div>
                        </>
                    ) : (
                        <div className="py-2 text-center">
                            <div className="w-16 h-16 bg-primary/5 border-2 border-primary/20 rounded-2xl flex items-center justify-center mx-auto mb-8 text-primary shadow-xl shadow-primary/5">
                                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                                </svg>
                            </div>

                            <h1 className="text-2xl font-black mb-2 text-text-dark tracking-tighter">Check your inbox</h1>
                            <p className="text-slate-500 font-medium text-sm leading-relaxed mb-8">
                                We've sent a 6-digit code to<br />
                                <strong className="text-text-dark font-black">{emailFormik.values.email}</strong>
                            </p>

                            <form onSubmit={otpFormik.handleSubmit} className="space-y-8">
                                <div className="relative flex justify-between gap-2 max-w-[320px] mx-auto">
                                    {[0, 1, 2, 3, 4, 5].map((index) => {
                                        const isActive = otpFormik.values.otp.length === index || (otpFormik.values.otp.length === 6 && index === 5);
                                        const isFilled = index < otpFormik.values.otp.length;

                                        return (
                                            <div
                                                key={index}
                                                className={`w-10 h-14 md:w-12 md:h-16 rounded-xl flex items-center justify-center text-xl md:text-2xl font-black transition-all duration-300
                                                    ${isActive
                                                        ? 'border-primary bg-primary/5 ring-4 ring-primary/5 z-10'
                                                        : isFilled
                                                            ? 'border-slate-300 bg-slate-50 text-text-dark'
                                                            : 'border-slate-100 bg-slate-50 text-slate-300'
                                                    } border-2
                                                `}
                                            >
                                                {isFilled ? otpFormik.values.otp[index] : ''}
                                            </div>
                                        );
                                    })}

                                    <input
                                        id="otp"
                                        name="otp"
                                        type="text"
                                        inputMode="numeric"
                                        pattern="[0-9]*"
                                        maxLength={6}
                                        value={otpFormik.values.otp}
                                        onChange={(e) => otpFormik.setFieldValue("otp", e.target.value.replace(/\D/g, '').substring(0, 6))}
                                        onBlur={otpFormik.handleBlur}
                                        className="absolute inset-0 w-full h-full opacity-0 cursor-text z-20 outline-none"
                                        required
                                        autoFocus
                                    />
                                </div>

                                <div className="space-y-5">
                                    <Button
                                        type="submit"
                                        variant="primary"
                                        fullWidth
                                        className="py-4 text-base font-black rounded-xl shadow-lg shadow-primary/10"
                                        disabled={loading || otpFormik.values.otp.length !== 6}
                                        text={loading ? "Unlocking..." : "Continue"}
                                    />

                                    <div className="flex flex-col items-center gap-3">
                                        <p className="text-slate-400 font-bold text-xs">
                                            Didn't receive code?
                                            <button
                                                type="button"
                                                className="ml-2 text-primary font-black hover:underline"
                                                onClick={() => emailFormik.handleSubmit()}
                                            >
                                                Resend
                                            </button>
                                        </p>

                                        <button
                                            type="button"
                                            onClick={() => { setIsSubmitted(false); otpFormik.resetForm(); }}
                                            className="text-slate-400 font-bold hover:text-text-dark transition-colors text-[10px] uppercase tracking-widest flex items-center gap-2"
                                        >
                                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><line x1="19" y1="12" x2="5" y2="12" /><polyline points="12,19 5,12 12,5" /></svg>
                                            Back
                                        </button>
                                    </div>
                                </div>
                            </form>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

export default LoginPage;
