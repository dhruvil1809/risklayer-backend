import { useState, useRef, useEffect } from "react";
import { createPortal } from "react-dom";
import { motion, AnimatePresence } from "framer-motion";
import { X, Globe, Loader2, ArrowRight } from "lucide-react";
import ReCAPTCHA from "react-google-recaptcha";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import { Button } from "../../../components/ui/Button";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:5000";
const RECAPTCHA_SITE_KEY = import.meta.env.VITE_RECAPTCHA_SITE_KEY || "";

interface DashboardNewScanModalProps {
    isOpen: boolean;
    onClose: () => void;
}

export default function DashboardNewScanModal({ isOpen, onClose }: DashboardNewScanModalProps) {
    const [url, setUrl] = useState("");
    const [step, setStep] = useState<"url" | "captcha">("url");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const recaptchaRef = useRef<ReCAPTCHA>(null);
    const navigate = useNavigate();

    useEffect(() => {
        if (isOpen) {
            setUrl("");
            setStep("url");
            setError(null);
            setLoading(false);
            if (recaptchaRef.current) recaptchaRef.current.reset();
        }
    }, [isOpen]);

    const isValidUrl = (input: string) => {
        const pattern = new RegExp(
            '^(https?:\\/\\/)?' +              // protocol
            '(([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,})' + // domain
            '(\\:[0-9]{1,5})?' +               // port
            '(\\/.*)?$',                       // path
            'i'
        );
        return pattern.test(input);
    };

    const handleUrlSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);
        if (!url || url.trim() === "") {
            setError("Please enter a valid URL.");
            return;
        }
        if (!isValidUrl(url)) {
            setError("Invalid website URL format.");
            return;
        }
        setStep("captcha");
    };

    const handleCaptchaVerify = async (token: string | null) => {
        if (token) {
            setError(null);
            const authToken = localStorage.getItem("token") || localStorage.getItem("accessToken");
            if (!authToken) {
                setError("Your session has expired. Please log in again.");
                return;
            }

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
                if (recaptchaRef.current) recaptchaRef.current.reset();
            } finally {
                setLoading(false);
            }
        }
    };

    if (!isOpen) return null;

    return createPortal(
        <AnimatePresence>
            <div className="fixed inset-0 bg-black/20 backdrop-blur-sm z-9999 flex items-center justify-center p-4">
                <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
                    className="bg-white border border-slate-200 rounded-[24px] w-full max-w-[450px] p-8 shadow-2xl overflow-hidden relative"
                >
                    <div className="flex justify-between items-center mb-6">
                        <div className="flex items-center gap-3">
                            <div className="w-10 h-10 bg-primary/10 text-primary rounded-xl flex items-center justify-center">
                                <Globe className="w-5 h-5" />
                            </div>
                            <h2 className="text-2xl font-black m-0 text-text-dark tracking-tight">New Scan</h2>
                        </div>
                        <Button type="button" variant="custom" size="none" display="" rounded="" fontWeight="" className="w-8 h-8 rounded-full bg-slate-50 border border-slate-200 text-slate-500 hover:bg-slate-100 hover:text-text-dark flex items-center justify-center transition-colors p-0 focus:outline-none" onClick={onClose}>
                            <X className="w-5 h-5" />
                        </Button>
                    </div>
                    {step === "url" && (
                        <p className="text-slate-500 font-medium text-sm mb-6">Please enter the URL of the website you want to scan.</p>
                    )}
                    {step === "captcha" && (
                        <div className="mb-6">
                            <label className="block text-sm text-slate-600 mb-2 font-bold tracking-wide">Scanning URL</label>
                            <div className="py-3 px-4 bg-slate-50 rounded-xl text-slate-600 overflow-hidden text-ellipsis whitespace-nowrap border border-slate-200 font-mono text-sm shadow-inner group-hover:border-primary/40 transition-colors">
                                {url}
                            </div>
                        </div>
                    )}
                    {error && (
                        <div className="mb-6 p-4 bg-red-50 border-l-4 border-red-500 rounded-r-xl text-red-700 text-sm font-bold flex items-center shadow-sm">
                            {error}
                        </div>
                    )}

                    <div className="relative min-h-[160px]">
                        <AnimatePresence mode="wait">
                            {step === "url" && (
                                <motion.form
                                    key="url"
                                    initial={{ opacity: 0, y: 0 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    exit={{ opacity: 0, y: -20 }}
                                    transition={{ duration: 0.2 }}
                                    onSubmit={handleUrlSubmit}
                                    className="space-y-6"
                                >
                                    <div>
                                        <label className="block text-sm text-slate-600 mb-2 font-bold tracking-wide">Enter your website URL</label>
                                        <input
                                            type="url"
                                            placeholder="https://example.com"
                                            className="w-full bg-slate-50 border border-slate-200 text-slate-800 text-base font-medium rounded-xl px-5 py-3 focus:outline-none focus:border-primary/50 focus:ring-4 focus:ring-primary/10 transition-all placeholder:text-slate-400 shadow-inner"
                                            value={url}
                                            onChange={(e) => setUrl(e.target.value)}
                                            autoFocus
                                        />
                                    </div>
                                    <Button
                                        type="submit"
                                        variant="primary"
                                        size="md"
                                        className="w-full flex items-center justify-center gap-2"
                                        text="Start Scanning"
                                        endIcon={<ArrowRight className="w-4 h-4" />}
                                    />
                                </motion.form>
                            )}

                            {step === "captcha" && (
                                <motion.div
                                    key="captcha"
                                    initial={{ opacity: 0, x: 20 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    exit={{ opacity: 0, x: 20 }}
                                    transition={{ duration: 0.2 }}
                                    className="flex items-center justify-center flex-col py-2"
                                >
                                    <div className="mb-4 text-center">
                                        <h3 className="text-text-dark font-bold text-lg mb-1 tracking-tight">Security Check</h3>
                                        <p className="text-slate-500 text-sm font-medium">Please verify you are human to continue.</p>
                                    </div>

                                    {loading ? (
                                        <div className="py-6 flex flex-col items-center justify-center text-primary">
                                            <Loader2 className="w-10 h-10 animate-spin mb-4" />
                                            <span className="font-bold text-sm">Initializing Crawler...</span>
                                        </div>
                                    ) : (
                                        <div className="flex justify-center my-2 shadow-sm rounded-xl overflow-hidden p-1 bg-slate-50 border border-slate-100 hover:border-primary/30 transition-all">
                                            <ReCAPTCHA
                                                ref={recaptchaRef}
                                                sitekey={RECAPTCHA_SITE_KEY}
                                                onChange={handleCaptchaVerify}
                                                theme="light"
                                            />
                                        </div>
                                    )}
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </div>
                </motion.div>
            </div>
        </AnimatePresence>,
        document.body
    );
}
