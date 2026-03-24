import { useState, useEffect } from 'react';

function PrivacyPolicyPage() {
    const [activeSection, setActiveSection] = useState('intro');

    useEffect(() => {
        const handleScroll = () => {
            const sections = document.querySelectorAll('section[id]');
            let current = 'intro';
            sections.forEach(section => {
                const sectionTop = section.getBoundingClientRect().top;
                // If the section's top is near or above the viewport top (adjusting for sticky header)
                if (sectionTop <= 200) {
                    current = section.getAttribute('id') || 'intro';
                }
            });
            setActiveSection(current);
        };

        window.addEventListener('scroll', handleScroll);
        // Trigger once to set initial state
        handleScroll();
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    const navLinks = [
        { id: 'intro', label: '1. Introduction' },
        { id: 'data', label: '2. Information We Collect' },
        { id: 'usage', label: '3. How We Use Data' },
        { id: 'security', label: '4. Data Security' },
        { id: 'rights', label: '5. Your Rights' },
        { id: 'contact', label: '6. Contact Us' },
    ];

    const scrollTo = (e: React.MouseEvent<HTMLAnchorElement>, id: string) => {
        e.preventDefault();
        const el = document.getElementById(id);
        if (el) {
            const y = el.getBoundingClientRect().top + window.scrollY - 100;
            window.scrollTo({ top: y, behavior: 'smooth' });
        }
    };

    return (
        <>
            <div className="pt-24 pb-24 relative z-10 w-full">

                {/* Hero Title Area */}
                <div className="max-w-[1280px] mx-auto px-[5%] mb-16 flex flex-col items-center text-center">
                    <div className="inline-flex items-center justify-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-sm font-semibold mb-6">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
                        Legal Documentation
                    </div>
                    <h1 className="text-4xl md:text-6xl font-extrabold leading-tight mb-6 text-text-dark">
                        Privacy Policy
                    </h1>
                    <p className="text-slate-500 text-sm md:text-xl max-w-2xl mx-auto leading-relaxed">
                        We value your privacy. Learn how we collect, use, and protect your data when you use RiskLayer's compliance and scanning engine.
                    </p>
                    <div className="mt-8 flex justify-center items-center gap-4 text-sm text-slate-400 w-full">
                        <span className="flex items-center gap-2">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2" /><line x1="16" y1="2" x2="16" y2="6" /><line x1="8" y1="2" x2="8" y2="6" /><line x1="3" y1="10" x2="21" y2="10" /></svg>
                            Last Updated: March 2026
                        </span>
                    </div>
                </div>

                <div className="max-w-[1280px] mx-auto px-[5%] flex flex-col lg:flex-row gap-12 lg:gap-20">

                    {/* Sticky Sidebar */}
                    <aside className="lg:w-[280px] shrink-0">
                        <div className="sticky top-[120px] bg-white border border-slate-100 p-6 rounded-2xl shadow-sm">
                            <h3 className="text-text-dark font-bold mb-4 uppercase text-sm tracking-wider">Table of Contents</h3>
                            <nav className="flex flex-col gap-1">
                                {navLinks.map((link) => (
                                    <a
                                        key={link.id}
                                        href={`#${link.id}`}
                                        onClick={(e) => scrollTo(e, link.id)}
                                        className={`px-4 py-2.5 rounded-xl transition-all duration-300 text-sm font-medium ${activeSection === link.id
                                            ? 'bg-primary/10 text-primary'
                                            : 'text-slate-500 hover:text-text-dark hover:bg-slate-50'
                                            }`}
                                    >
                                        {link.label}
                                    </a>
                                ))}
                            </nav>
                        </div>
                    </aside>

                    {/* Content Articles */}
                    <div className="flex-1 space-y-12 pb-24">
                        <div className="bg-white border border-slate-100 rounded-3xl p-8 md:p-12 shadow-sm transition-all duration-500 hover:border-slate-200">

                            <section id="intro" className="scroll-mt-[120px] mb-12 relative group">
                                <h2 className="text-2xl md:text-3xl font-bold text-text-dark mb-6 flex items-center gap-3">
                                    <span className="text-primary opacity-50 font-mono text-xl group-hover:opacity-100 transition-opacity">01.</span>
                                    Introduction
                                </h2>
                                <p className="text-slate-500 leading-relaxed text-sm mb-4">
                                    Welcome to RiskLayer. This Privacy Policy outlines how we collect, use, and protect your data when you use our automated compliance and risk scanning services. By accessing our platform, you agree to the practices described in this document.
                                </p>
                            </section>

                            <div className="h-px bg-slate-50 w-full my-12"></div>

                            <section id="data" className="scroll-mt-[120px] mb-12 relative group">
                                <h2 className="text-2xl md:text-3xl font-bold text-text-dark mb-6 flex items-center gap-3">
                                    <span className="text-primary opacity-50 font-mono text-xl group-hover:opacity-100 transition-opacity">02.</span>
                                    Information We Collect
                                </h2>
                                <p className="text-slate-500 leading-relaxed text-sm mb-6">We collect the following types of core platform information:</p>
                                <ul className="space-y-4 text-slate-500">
                                    <li className="flex items-start gap-4 p-4 rounded-xl bg-slate-50 border border-slate-100">
                                        <div className="w-8 h-8 rounded-lg bg-primary/10 text-primary flex items-center justify-center shrink-0 border border-primary/20">
                                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>
                                        </div>
                                        <div>
                                            <strong className="text-text-dark block mb-1">Account Information</strong>
                                            Name, email address, agency details, and payment information provided during registration (processed securely via Stripe).
                                        </div>
                                    </li>
                                    <li className="flex items-start gap-4 p-4 rounded-xl bg-slate-50 border border-slate-100">
                                        <div className="w-8 h-8 rounded-lg bg-primary/10 text-primary flex items-center justify-center shrink-0 border border-primary/20">
                                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></svg>
                                        </div>
                                        <div>
                                            <strong className="text-text-dark block mb-1">Scan Data</strong>
                                            URLs, DOM structures, code snippets, and metadata retrieved during our automated scans of requested properties.
                                        </div>
                                    </li>
                                    <li className="flex items-start gap-4 p-4 rounded-xl bg-slate-50 border border-slate-100">
                                        <div className="w-8 h-8 rounded-lg bg-primary/10 text-primary flex items-center justify-center shrink-0 border border-primary/20">
                                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21.21 15.89A10 10 0 1 1 8 2.83" /><path d="M22 12A10 10 0 0 0 12 2v10z" /></svg>
                                        </div>
                                        <div>
                                            <strong className="text-text-dark block mb-1">Usage Metrics</strong>
                                            Interaction data, IP addresses, browser types, and usage patterns collected via strictly essential functional cookies.
                                        </div>
                                    </li>
                                </ul>
                            </section>

                            <div className="h-px bg-slate-50 w-full my-12"></div>

                            <section id="usage" className="scroll-mt-[120px] mb-12 relative group">
                                <h2 className="text-2xl md:text-3xl font-bold text-text-dark mb-6 flex items-center gap-3">
                                    <span className="text-primary opacity-50 font-mono text-xl group-hover:opacity-100 transition-opacity">03.</span>
                                    How We Use Your Data
                                </h2>
                                <p className="text-slate-500 leading-relaxed text-sm mb-4">
                                    We use the data we collect primarily to operate and improve our automated scanning services. Specifically:
                                </p>
                                <ul className="space-y-3 text-slate-500 mb-4 pl-4 border-l-2 border-primary/30">
                                    <li className="pl-2">To generate and deliver accurate AI-powered compliance reports via email or webhook.</li>
                                    <li className="pl-2">To notify you contextually of critical security gaps (e.g., unexpected mixed content warnings).</li>
                                    <li className="pl-2">To anonymize and analyze platform usage trends to tune scanning algorithms and lower false positive rates.</li>
                                </ul>
                            </section>

                            <div className="h-px bg-slate-50 w-full my-12"></div>

                            <section id="security" className="scroll-mt-[120px] mb-12 relative group">
                                <h2 className="text-2xl md:text-3xl font-bold text-text-dark mb-6 flex items-center gap-3">
                                    <span className="text-primary opacity-50 font-mono text-xl group-hover:opacity-100 transition-opacity">04.</span>
                                    Data Storage & Security
                                </h2>
                                <div className="bg-slate-50 border border-slate-100 p-6 rounded-2xl">
                                    <p className="text-slate-500 leading-relaxed text-sm">
                                        All scan reports and user data are strictly encrypted in transit explicitly utilizing <strong className="text-text-dark">TLS 1.3 protocol</strong> and completely encrypted at rest via <strong className="text-text-dark">AES-256 block ciphers</strong>.
                                    </p>
                                    <p className="text-slate-500 leading-relaxed text-sm mt-4">
                                        We utilize deterministic hashing mechanisms for sensitive client data routing. <strong className="text-text-dark">We never sell personal data or scan results to any third parties under any circumstances.</strong>
                                    </p>
                                </div>
                            </section>

                            <div className="h-px bg-slate-50 w-full my-12"></div>

                            <section id="rights" className="scroll-mt-[120px] mb-12 relative group">
                                <h2 className="text-2xl md:text-3xl font-bold text-text-dark mb-6 flex items-center gap-3">
                                    <span className="text-primary opacity-50 font-mono text-xl group-hover:opacity-100 transition-opacity">05.</span>
                                    Your Rights
                                </h2>
                                <p className="text-slate-500 leading-relaxed text-sm mb-4">
                                    Under modern applicable privacy frameworks (including GDPR, CCPA, and CPRA), you have guaranteed foundational rights to request manual access to, explicit correction of, or permanent deletion of your personal data schemas.
                                </p>
                                <p className="text-slate-500 leading-relaxed text-sm mb-4">
                                    <strong>Data portability:</strong> You may instantly export your workspace data as raw CSV or JSON payloads at any time directly via your secure agency dashboard without requiring a support ticket.
                                </p>
                            </section>

                            <div className="h-px bg-slate-50 w-full my-12"></div>

                            <section id="contact" className="scroll-mt-[120px] relative group">
                                <h2 className="text-2xl md:text-3xl font-bold text-text-dark mb-6 flex items-center gap-3">
                                    <span className="text-primary opacity-50 font-mono text-xl group-hover:opacity-100 transition-opacity">06.</span>
                                    Contact Us
                                </h2>
                                <div className="flex flex-col sm:flex-row gap-6 p-6 md:p-8 bg-slate-50 rounded-2xl border border-slate-100 items-center sm:justify-between">
                                    <div>
                                        <p className="text-slate-500 leading-relaxed text-sm mb-1">
                                            For technical privacy questions or specialized enterprise data deletion requests.
                                        </p>
                                        <p className="text-text-dark font-bold text-sm">Average response time: &lt; 24h</p>
                                    </div>
                                    <a href="mailto:privacy@risklayer.example.com" className="bg-primary text-white px-6 py-3 rounded-full font-bold transition-all whitespace-nowrap shadow-md active:scale-95">
                                        Email DPO Team
                                    </a>
                                </div>
                            </section>
                        </div>
                    </div>
                </div>
            </div>
        </>
    );
}

export default PrivacyPolicyPage;
