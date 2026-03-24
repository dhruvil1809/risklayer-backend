import { Search } from 'lucide-react';
import { Button } from '../../../components/ui/Button';
import toast from 'react-hot-toast';

export const isValidUrl = (url: string): boolean => {
    const pattern = new RegExp(
        '^(https?:\\/\\/)?' +              // protocol
        '(([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,})' + // domain
        '(\\:[0-9]{1,5})?' +               // port
        '(\\/.*)?$',                       // path
        'i'
    );
    return pattern.test(url);
};

export const normalizeUrl = (inputUrl: string): string => {
    try {
        // Add https if no protocol specified
        let cleanUrl = inputUrl.trim();
        if (!/^https?:\/\//i.test(cleanUrl)) {
            cleanUrl = `https://${cleanUrl}`;
        }

        const url = new URL(cleanUrl);
        // Normalize to domain but KEEP path and search (e.g., phinexis.com/about)
        return url.hostname.toLowerCase() + url.pathname + url.search;
    } catch (e) {
        return inputUrl.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/$/, "");
    }
};

interface HeroSectionProps {
    url: string;
    setUrl: (url: string) => void;
    onScan: () => void;
}

export default function HeroSection({ url, setUrl, onScan }: HeroSectionProps) {
    const handleScanClick = () => {
        if (!url || url.trim() === '') {
            toast.error("Please enter a URL to scan");
            return;
        }

        if (!isValidUrl(url)) {
            toast.error("Please enter a valid website URL");
            return;
        }

        // Normalize URL (e.g., http://phinexis.com/about -> https://phinexis.com)
        const normalized = normalizeUrl(url);
        setUrl(normalized);
        onScan();
    };


    return (
        <section className="flex flex-col items-center justify-center text-center pt-24 pb-20 md:pt-10 md:pb-10 px-[5%] relative z-10 min-h-[90vh] bg-white overflow-hidden">
            {/* Background Grid & Gradient */}
            <div className="bg-grid-effect-sides opacity-60" />

            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-full pointer-events-none overflow-hidden opacity-40">
                <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-primary/10 blur-[130px] rounded-full" />
                <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-primary/10 blur-[130px] rounded-full" />
            </div>

            <div className="inline-flex items-center gap-2.5 bg-primary/10 border border-primary/20 text-primary px-4 py-1.5 md:px-5 md:py-2 rounded-full text-[11px] font-bold mb-8 tracking-wide uppercase animate-in fade-in slide-in-from-bottom-4 duration-700">
                <span className="w-2 md:w-2.5 h-2 md:h-2.5 rounded-full bg-primary animate-pulse shadow-[0_0_10px_rgba(243,146,0,0.5)]" />
                AI-Powered Compliance Audit
            </div>

            <h1 className="text-[36px] sm:text-[42px] md:text-[64px] xl:text-[74px] font-black leading-[1.1] mb-6 md:mb-8 max-w-[1200px] text-text-dark tracking-tighter animate-in fade-in slide-in-from-bottom-8 duration-700 delay-100">
                Audit Your Website <br className="hidden sm:block" />
                For <span className="text-primary italic">Risk & Compliance</span>
            </h1>

            <p className="text-base md:text-xl text-slate-500 max-w-[700px] mb-10 md:mb-14 leading-relaxed font-medium animate-in fade-in slide-in-from-bottom-8 duration-700 delay-200 px-4">
                The world's most advanced AI scanner for accessibility gaps,
                legal risks, and trust signals. Trusted by 2,000+ brands.
            </p>

            <div className="flex flex-col items-center gap-10 w-full animate-in fade-in slide-in-from-bottom-8 duration-700 delay-300">
                <div className="w-full max-w-[340px] sm:max-w-md md:max-w-[650px] bg-white p-1.5 rounded-2xl flex flex-col md:flex-row items-center transition-all duration-500 shadow-[0_15px_40px_-10px_rgba(0,0,0,0.08)] border border-primary/20 group focus-within:ring-8 focus-within:ring-primary/5 focus-within:border-primary/20">
                    <div className="flex-1 flex items-center w-full px-4 md:px-5">
                        <Search className="w-5 h-5 text-slate-400 mr-3 md:mr-4 shrink-0 group-focus-within:text-primary transition-colors" />
                        <input
                            id="hero-url-input"
                            type="url"
                            className="flex-1 w-full bg-transparent border-none text-slate-900 py-3.5 md:py-4 text-sm md:text-lg outline-none placeholder:text-slate-400 font-semibold"
                            placeholder="Enter your website URL"
                            value={url}
                            onChange={(e) => setUrl(e.target.value)}
                            onKeyDown={(e) => {
                                if (e.key === 'Enter') {
                                    e.preventDefault();
                                    handleScanClick();
                                }
                            }}
                        />
                    </div>
                    <Button
                        type="button"
                        onClick={handleScanClick}
                        variant="primary"
                        size="lg"
                        // className="w-full md:w-[180px] h-[48px] md:h-[56px] text-sm md:text-base font-bold rounded-xl shadow-lg shadow-primary/10"
                        text="Analyze Now"
                    />
                </div>
            </div>

            <div className="mt-16 md:mt-24 flex flex-wrap justify-center gap-x-8 md:gap-x-16 gap-y-6 md:gap-y-8 animate-in fade-in slide-in-from-bottom-8 duration-700 delay-500">
                {[
                    { label: 'Accessibility Audit', icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' },
                    { label: 'Legal Compliance', icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' },
                    { label: 'Trust Verification', icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' }
                ].map((feature, i) => (
                    <div key={i} className="flex items-center gap-2.5 md:gap-3 text-slate-400 text-[11px] md:text-[13px] font-bold uppercase tracking-widest md:tracking-[0.15em] hover:text-slate-600 transition-colors">
                        <svg className="w-4 h-4 md:w-5 md:h-5 text-primary" fill="none" stroke="currentColor" strokeWidth="3" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" d={feature.icon} />
                        </svg>
                        {feature.label}
                    </div>
                ))}
            </div>
        </section>
    );
}
