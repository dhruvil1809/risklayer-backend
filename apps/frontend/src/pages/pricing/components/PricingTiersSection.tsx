import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';

const CheckIcon = () => (
    <svg className="w-5 h-5 text-primary shrink-0 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="20 6 9 17 4 12"></polyline>
    </svg>
);

interface PricingInfo {
    currency: string;
    symbol: string;
    singleReport: number;
    agencyStarter: number;
    agencyGrowth: number;
}

const PRICING_MAPPING: Record<string, PricingInfo> = {
    'IN': {
        currency: 'INR',
        symbol: '₹',
        singleReport: 3999,
        agencyStarter: 6499,
        agencyGrowth: 19999
    },
    'GB': {
        currency: 'GBP',
        symbol: '£',
        singleReport: 39,
        agencyStarter: 65,
        agencyGrowth: 199
    },
    'EU': { // Generalized for Eurozone (multiple codes can point here)
        currency: 'EUR',
        symbol: '€',
        singleReport: 45,
        agencyStarter: 75,
        agencyGrowth: 229
    },
    'DEFAULT': {
        currency: 'USD',
        symbol: '$',
        singleReport: 49,
        agencyStarter: 79,
        agencyGrowth: 249
    }
};

const EURO_COUNTRIES = ['AT', 'BE', 'CY', 'EE', 'FI', 'FR', 'DE', 'GR', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PT', 'SK', 'SI', 'ES'];

export default function PricingTiersSection() {
    const [pricing, setPricing] = useState<PricingInfo>(PRICING_MAPPING['DEFAULT']);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const detectCountry = async () => {
            try {
                const storedCountry = localStorage.getItem("user_country");

                let countryCode = storedCountry;

                if (!countryCode) {
                    const response = await axios.get("https://ipapi.co/json/");
                    countryCode = response.data.country_code;
                    if (countryCode) {
                        localStorage.setItem("user_country", countryCode);
                    }
                }

                const finalCode = countryCode || "DEFAULT";
                let selectedPricing = PRICING_MAPPING[finalCode];

                if (!selectedPricing && EURO_COUNTRIES.includes(finalCode)) {
                    selectedPricing = PRICING_MAPPING["EU"];
                }

                if (selectedPricing) {
                    setPricing(selectedPricing);
                }

            } catch (error) {
                console.error("Failed to detect country:", error);
            } finally {
                setLoading(false);
            }
        };

        detectCountry();
    }, []);

    // Placeholder skeleton while loading could be added here for even better premium feel
    // For now we'll just show the default/detected price to avoid layout shift once loaded

    return (
        <div className="grid grid-cols-1 sm:grid-cols-2 [@media(min-width:1312px)]:grid-cols-4 gap-6 md:gap-8 w-full max-w-[1400px] mb-12 md:mb-16 px-4 sm:px-0">
            {/* Free Tier */}
            <div className="bg-white border border-slate-100 p-6 md:p-8 rounded-[24px] md:rounded-[32px] flex flex-col relative transition-all duration-300 hover:-translate-y-2 hover:shadow-2xl shadow-sm group">
                <h2 className="text-lg md:text-xl font-bold mb-4 text-text-dark">Free Preview</h2>
                <div className="flex items-baseline gap-1 mb-4 text-text-dark">
                    <span className="text-xl text-slate-400 font-medium">{pricing.symbol}</span>
                    <span className="text-3xl md:text-4xl lg:text-5xl font-black tracking-tighter">0</span>
                </div>
                <p className="text-slate-500 text-sm leading-relaxed mb-8 flex-1">Basic risk assessment to understand your baseline compliance gaps.</p>
                <div className="space-y-4 mb-10 md:mb-12">
                    <div className="flex items-start gap-3 text-[0.9rem] md:text-[0.95rem] text-text-dark"><CheckIcon /> <span>Up to 5 priority findings</span></div>
                    <div className="flex items-start gap-3 text-[0.9rem] md:text-[0.95rem] text-text-dark"><CheckIcon /> <span>Capped page crawl</span></div>
                    <div className="flex items-start gap-3 text-[0.9rem] md:text-[0.95rem] text-text-dark"><CheckIcon /> <span>High-level categorization</span></div>
                </div>
                <Link to="/" className="w-full py-4 px-6 rounded-2xl border border-slate-200 hover:border-primary text-text-dark font-bold text-center hover:bg-primary/5 hover:text-primary transition-all">Start Free Scan</Link>
            </div>

            {/* Single Report */}
            <div className="bg-white border border-slate-100 p-6 md:p-8 rounded-[24px] md:rounded-[32px] flex flex-col relative transition-all duration-300 hover:-translate-y-2 hover:shadow-2xl shadow-sm group">
                <h2 className="text-lg md:text-xl font-bold mb-4 text-text-dark">Single Report</h2>
                <div className="flex items-baseline gap-1 mb-4 text-text-dark">
                    <span className="text-xl text-slate-400 font-medium">{pricing.symbol}</span>
                    <span className={`text-3xl md:text-4xl lg:text-5xl font-black tracking-tighter transition-opacity duration-300 ${loading ? 'opacity-50' : 'opacity-100'}`}>
                        {pricing.singleReport}
                    </span>
                    <span className="text-sm text-slate-400 font-medium">/scan</span>
                </div>
                <p className="text-slate-500 text-sm leading-relaxed mb-8 flex-1">One-time comprehensive audit with AI explanations and priority fix plans.</p>
                <div className="space-y-4 mb-10 md:mb-12">
                    <div className="flex items-start gap-3 text-[0.9rem] md:text-[0.95rem] text-text-dark"><CheckIcon /> <span>Unlimited findings unlocked</span></div>
                    <div className="flex items-start gap-3 text-[0.9rem] md:text-[0.95rem] text-text-dark"><CheckIcon /> <span>AI plain-English explanations</span></div>
                    <div className="flex items-start gap-3 text-[0.9rem] md:text-[0.95rem] text-text-dark"><CheckIcon /> <span>Step-by-step fix guides</span></div>
                    <div className="flex items-start gap-3 text-[0.9rem] md:text-[0.95rem] text-text-dark"><CheckIcon /> <span>1 Shareable signed PDF</span></div>
                </div>
                <Link to="/" className="w-full py-4 px-6 rounded-2xl border border-slate-200 hover:border-primary text-text-dark font-bold text-center hover:bg-primary/5 hover:text-primary transition-all">Run Paid Scan</Link>
            </div>

            {/* Agency Starter (Popular) */}
            <div className="bg-white border-2 border-primary/50 p-6 md:p-8 rounded-[24px] md:rounded-[32px] flex flex-col relative shadow-xl lg:scale-105 z-10 transition-all duration-300 hover:-translate-y-2">
                <div className="absolute -top-[12px] left-1/2 -translate-x-1/2 bg-primary text-white px-4 py-1 text-[10px] md:text-[11px] font-black uppercase tracking-widest rounded-full shadow-lg shadow-primary/20 z-10">Most Popular</div>
                <h2 className="text-lg md:text-xl font-bold mb-4 text-text-dark">Agency Starter</h2>
                <div className="flex items-baseline gap-1 mb-4 text-text-dark">
                    <span className="text-xl text-slate-400 font-medium">{pricing.symbol}</span>
                    <span className={`text-3xl md:text-4xl lg:text-5xl font-black tracking-tighter transition-opacity duration-300 ${loading ? 'opacity-50' : 'opacity-100'}`}>
                        {pricing.agencyStarter}
                    </span>
                    <span className="text-sm text-slate-400 font-medium">/mo</span>
                </div>
                <p className="text-slate-500 text-sm leading-relaxed mb-8 flex-1">Perfect for boutique agencies auditing and protecting client deliverables.</p>
                <div className="space-y-4 mb-10 md:mb-12">
                    <div className="flex items-start gap-3 text-[0.9rem] md:text-[0.95rem] text-text-dark"><CheckIcon /> <span>10 Full Reports included</span></div>
                    <div className="flex items-start gap-3 text-[0.9rem] md:text-[0.95rem] text-text-dark"><CheckIcon /> <span>Client isolating workspaces</span></div>
                    <div className="flex items-start gap-3 text-[0.9rem] md:text-[0.95rem] text-text-dark"><CheckIcon /> <span>White-label PDF branding</span></div>
                    <div className="flex items-start gap-3 text-[0.9rem] md:text-[0.95rem] text-text-dark"><CheckIcon /> <span>CSV/JSON Exports</span></div>
                </div>
                <button
                    onClick={() => alert("Proceeding to Checkout!")}
                    className="w-full py-4 px-6 rounded-2xl bg-primary text-white font-black text-center shadow-lg shadow-primary/20 hover:shadow-primary/30 transition-all hover:scale-[1.02] active:scale-95"
                >
                    Start Agency Trial
                </button>
            </div>

            {/* Agency Growth / Pro */}
            <div className="bg-white border border-slate-100 p-6 md:p-8 rounded-[24px] md:rounded-[32px] flex flex-col relative transition-all duration-300 hover:-translate-y-2 hover:shadow-2xl shadow-sm group">
                <h2 className="text-lg md:text-xl font-bold mb-4 text-text-dark">Agency Growth</h2>
                <div className="flex items-baseline gap-1 mb-4 text-text-dark">
                    <span className="text-xl text-slate-400 font-medium">{pricing.symbol}</span>
                    <span className={`text-4xl md:text-5xl font-black tracking-tighter transition-opacity duration-300 ${loading ? 'opacity-50' : 'opacity-100'}`}>
                        {pricing.agencyGrowth}
                    </span>
                    <span className="text-sm text-slate-400 font-medium">/mo</span>
                </div>
                <p className="text-slate-500 text-sm leading-relaxed mb-8 flex-1">For scaling teams that require continuous monitoring and structured alerts.</p>
                <div className="space-y-4 mb-10 md:mb-12">
                    <div className="flex items-start gap-3 text-[0.9rem] md:text-[0.95rem] text-text-dark"><CheckIcon /> <span>50 Full Reports included</span></div>
                    <div className="flex items-start gap-3 text-[0.9rem] md:text-[0.95rem] text-text-dark"><CheckIcon /> <span>Scheduled automated scans</span></div>
                    <div className="flex items-start gap-3 text-[0.9rem] md:text-[0.95rem] text-text-dark"><CheckIcon /> <span>Slack notification routing</span></div>
                    <div className="flex items-start gap-3 text-[0.9rem] md:text-[0.95rem] text-text-dark"><CheckIcon /> <span>Jira / ClickUp integration</span></div>
                </div>
                <button
                    onClick={() => alert("Proceeding to Checkout!")}
                    className="w-full py-4 px-6 rounded-2xl border border-slate-200 hover:border-primary text-text-dark font-bold text-center hover:bg-primary/5 hover:text-primary transition-all"
                >
                    Upgrade to Growth
                </button>
            </div>
        </div>
    );
}

