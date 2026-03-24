import { ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Button } from './ui/Button';

interface CtaSectionProps {
    onScanClick?: () => void;
    href?: string;
}

export default function CtaSection({ onScanClick, href }: CtaSectionProps) {

    return (
        <div className="text-center bg-white border border-slate-100 py-12 md:py-20 px-6 md:px-12 rounded-[24px] md:rounded-[48px] max-w-[1100px] w-full mx-auto relative z-10 my-16 md:my-32 overflow-hidden shadow-[0_30px_70px_-20px_rgba(0,0,0,0.08)] group">
            <div className="absolute inset-0 bg-dot-grid opacity-[0.2] pointer-events-none" />

            <div className="relative z-10 flex flex-col items-center">
                <h2 className="text-2xl sm:text-3xl md:text-5xl lg:text-6xl font-black mb-6 text-text-dark leading-tight tracking-tight max-w-[900px]">
                    Ready to <span className="text-primary italic">secure</span> your digital presence?
                </h2>
                <p className="text-slate-500 mb-10 text-base md:text-xl font-medium max-w-2xl mx-auto leading-relaxed px-4">
                    Join 2,000+ brands using RiskLayer to automate their digital compliance and trust posture today.
                </p>
                <div className="flex flex-col items-center gap-8 w-full">
                    {href ? (
                        <Link to={href} className="w-full sm:w-auto">
                            <Button variant="primary" size="lg" className="w-full sm:w-auto px-8 md:px-12 py-4 md:py-6 text-base md:text-xl h-auto rounded-xl md:rounded-2xl shadow-2xl shadow-primary/20 hover:-translate-y-1 hover:shadow-primary/30 transition-all font-black" text="Get Started Free" endIcon={<ArrowRight className="w-6 h-6 ml-2" />} />
                        </Link>
                    ) : (
                        <Button
                            type="button"
                            variant="primary"
                            size="lg"
                            onClick={onScanClick}
                            className="w-full sm:w-auto px-8 md:px-12 py-4 md:py-6 text-base md:text-xl h-auto rounded-xl md:rounded-2xl shadow-2xl shadow-primary/20 hover:-translate-y-1 hover:shadow-primary/30 transition-all font-black"
                            text="Get Started Free"
                            endIcon={<ArrowRight className="w-6 h-6 ml-2" />}
                        />
                    )}
                    <div className="flex flex-wrap justify-center items-center gap-x-6 gap-y-3">
                        <span className="flex items-center gap-2 text-[11px] md:text-xs font-black text-slate-400 uppercase tracking-widest"><svg className="w-4 h-4 text-primary" fill="none" stroke="currentColor" strokeWidth="3.5" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg> No Credit Card</span>
                        <span className="hidden sm:block w-1.5 h-1.5 rounded-full bg-slate-200" />
                        <span className="flex items-center gap-2 text-[11px] md:text-xs font-black text-slate-400 uppercase tracking-widest"><svg className="w-4 h-4 text-primary" fill="none" stroke="currentColor" strokeWidth="3.5" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg> Instant Setup</span>
                    </div>
                </div>
            </div>
        </div>
    );
}
