import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import Button from './ui/Button';

const CookieConsent: React.FC = () => {
    const [isVisible, setIsVisible] = useState(false);

    useEffect(() => {
        const hasAccepted = localStorage.getItem('cookieConsent');
        if (!hasAccepted) {
            // Show the banner with a slight delay
            const timer = setTimeout(() => {
                setIsVisible(true);
            }, 1000);
            return () => clearTimeout(timer);
        }
    }, []);

    const handleAccept = () => {
        localStorage.setItem('cookieConsent', 'true');
        setIsVisible(false);
    };

    const handleDecline = () => {
        localStorage.setItem('cookieConsent', 'false');
        setIsVisible(false);
    };

    return (
        <AnimatePresence>
            {isVisible && (
                <motion.div
                    initial={{ y: 100, opacity: 0 }}
                    animate={{ y: 0, opacity: 1 }}
                    exit={{ y: 100, opacity: 0 }}
                    transition={{ type: 'spring', stiffness: 300, damping: 30 }}
                    className="fixed bottom-4 left-4 right-4 md:left-1/2 md:-translate-x-1/2 md:w-full md:max-w-5xl bg-[#0A0E17] border border-glass-border rounded-xl md:rounded-2xl p-5 md:py-6 md:px-8 shadow-[0_10px_40px_-5px_rgba(0,0,0,0.1)] z-50 text-gray-800"
                >
                    <div className="flex flex-col md:flex-row items-center justify-between gap-6 md:gap-10">
                        <div className="flex-1">
                            <p className="text-sm md:text-[15px] text-[#6b7280] leading-relaxed font-medium">
                                This website uses cookies to improve your experience and analyze site usage. You can accept or decline cookies. If you decline, only a single cookie will be used to remember your preference.
                            </p>
                        </div>
                        <div className="flex gap-3 w-full md:w-auto shrink-0 justify-end">
                            <Button
                                variant="secondary"
                                onClick={handleDecline}
                                className="border-[#6032D6] text-[#6032D6] hover:bg-purple-50 rounded-full px-8"
                            >
                                Decline
                            </Button>
                            <Button
                                variant="outline"
                                onClick={handleAccept}
                                className="bg-primary/10 hover:bg-primary/20 text-white rounded-full px-8"
                            >
                                Accept
                            </Button>
                        </div>
                    </div>
                </motion.div>
            )}
        </AnimatePresence>
    );
};

export default CookieConsent;
