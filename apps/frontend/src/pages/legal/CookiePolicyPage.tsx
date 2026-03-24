import { useState, useEffect } from 'react';

function CookiePolicyPage() {
    const [activeSection, setActiveSection] = useState('what-are-cookies');

    useEffect(() => {
        const handleScroll = () => {
            const sections = document.querySelectorAll('section[id]');
            let current = 'what-are-cookies';
            sections.forEach(section => {
                const sectionTop = section.getBoundingClientRect().top;
                if (sectionTop <= 200) {
                    current = section.getAttribute('id') || 'what-are-cookies';
                }
            });
            setActiveSection(current);
        };

        window.addEventListener('scroll', handleScroll);
        handleScroll();
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    const navLinks = [
        { id: 'what-are-cookies', label: '1. What Are Cookies?' },
        { id: 'types', label: '2. Types We Use' },
        { id: 'party', label: '3. First vs. Third-Party' },
        { id: 'managing', label: '4. Managing Preferences' },
        { id: 'updates', label: '5. Policy Updates' },
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
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2a10 10 0 1 0 10 10 4 4 0 0 1-5-5 4 4 0 0 1-5-5" /></svg>
                        Legal Documentation
                    </div>
                    <h1 className="text-4xl md:text-6xl font-extrabold leading-tight mb-6 text-text-dark">
                        Cookie Policy
                    </h1>
                    <p className="text-slate-500 text-sm md:text-xl max-w-2xl mx-auto leading-relaxed">
                        Transparency is trust. Understand exactly what data our system caches on your hardware to keep the scanner secure and functioning.
                    </p>
                    <div className="mt-8 flex justify-center items-center gap-4 text-sm text-slate-400 w-full">
                        <span className="flex items-center gap-2">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2" /><line x1="16" y1="2" x2="16" y2="6" /><line x1="8" y1="2" x2="8" y2="6" /><line x1="3" y1="10" x2="21" y2="10" /></svg>
                            Revision: March 2026
                        </span>
                    </div>
                </div>

                <div className="max-w-[1280px] mx-auto px-[5%] flex flex-col lg:flex-row gap-12 lg:gap-20">

                    {/* Sticky Sidebar */}
                    <aside className="lg:w-[280px] shrink-0">
                        <div className="sticky top-[120px] bg-white border border-slate-100 p-6 rounded-2xl shadow-sm">
                            <h3 className="text-text-dark font-bold mb-4 uppercase text-sm tracking-wider">Navigation</h3>
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

                            <section id="what-are-cookies" className="scroll-mt-[120px] mb-12 relative group">
                                <h2 className="text-2xl md:text-3xl font-bold text-text-dark mb-6 flex items-center gap-3">
                                    What Are Cookies?
                                </h2>
                                <p className="text-slate-500 leading-relaxed text-sm mb-4">
                                    Cookies are cryptographically signed small text payloads placed actively on your local storage device by our routing servers when you visit our web platform.
                                </p>
                                <p className="text-slate-500 leading-relaxed text-sm mb-4">
                                    In RiskLayer's specific infrastructure mapping, they are uniquely essential for establishing persistent authentication tokens, observing high-level platform load balancing, and ensuring our deterministic scanning workers scale correctly to your active logged-in session state securely.
                                </p>
                            </section>

                            <div className="h-px bg-slate-50 w-full my-12"></div>

                            <section id="types" className="scroll-mt-[120px] mb-12 relative group">
                                <h2 className="text-2xl md:text-3xl font-bold text-text-dark mb-6 flex items-center gap-3">
                                    Types of Cookies We Evaluate
                                </h2>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">

                                    <div className="bg-slate-50 border border-slate-100 p-6 rounded-2xl relative overflow-hidden group/card hover:border-primary/30 transition-colors">
                                        <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center text-primary mb-4 border border-primary/20">
                                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
                                        </div>
                                        <h3 className="text-text-dark font-bold text-sm mb-2">Strictly Necessary</h3>
                                        <p className="text-slate-500 text-sm leading-relaxed">
                                            Required for firewall traversal and API. Includes encrypted authentication tokens (JWTs) verifying logged-in state and core security mechanisms protecting against active Cross-Site Request Forgery (CSRF). <strong>Cannot be disabled.</strong>
                                        </p>
                                    </div>

                                    <div className="bg-slate-50 border border-slate-100 p-6 rounded-2xl relative overflow-hidden group/card hover:border-primary/30 transition-colors">
                                        <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center text-primary mb-4 border border-primary/20">
                                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></svg>
                                        </div>
                                        <h3 className="text-text-dark font-bold text-sm mb-2">Performance & Load</h3>
                                        <p className="text-slate-500 text-sm leading-relaxed">
                                            Used implicitly by our background edge network (Vercel/Cloudflare) to distribute caching and minimize latency during high-volume report generation requests. Completely anonymous.
                                        </p>
                                    </div>

                                    <div className="bg-slate-50 border border-slate-100 p-6 rounded-2xl relative overflow-hidden group/card hover:border-primary/30 transition-colors md:col-span-2">
                                        <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center text-primary mb-4 border border-primary/20">
                                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 20h9" /><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z" /></svg>
                                        </div>
                                        <h3 className="text-text-dark font-bold text-sm mb-2">Preference State</h3>
                                        <p className="text-slate-500 text-sm leading-relaxed">
                                            Stores local client-side boolean flags ensuring your active workspace layout context, dark mode adjustments, and collapsed sidebar configurations persist gracefully between browser reloads.
                                        </p>
                                    </div>

                                </div>
                            </section>

                            <div className="h-px bg-slate-50 w-full my-12"></div>

                            <section id="party" className="scroll-mt-[120px] mb-12 relative group">
                                <h2 className="text-2xl md:text-3xl font-bold text-text-dark mb-6 flex items-center gap-3">
                                    First vs. Third-Party Deployment
                                </h2>
                                <p className="text-slate-500 leading-relaxed text-sm mb-4">
                                    RiskLayer architects an engineering stance favoring minimal dependency logic. Thus, the vast majority of cookies allocated against your active payload are cleanly <strong>first-party</strong> (originating directly from risklayer.com infrastructure).
                                </p>
                                <p className="text-slate-500 leading-relaxed text-sm mb-4">
                                    Third-party cookies are aggressively restricted isolated strictly to secure payment iframe processing methodologies (specifically referencing Stripe infrastructure) executing cleanly only during active checkout flows in the billing portal. We deploy absolutely <strong>ZERO</strong> third-party programmatic remarketing advertisement cookies.
                                </p>
                            </section>

                            <div className="h-px bg-slate-50 w-full my-12"></div>

                            <section id="managing" className="scroll-mt-[120px] mb-12 relative group">
                                <h2 className="text-2xl md:text-3xl font-bold text-text-dark mb-6 flex items-center gap-3">
                                    Managing Storage Preferences
                                </h2>
                                <p className="text-slate-500 leading-relaxed text-sm mb-4">
                                    Since our minimal payload of distributed cookies is fundamentally strictly necessary for the SaaS application to securely interact against the API gateway (preventing CSRF and session hijacking models), <strong>blocking them entirely at the network layer level will functionally break JWT authentication cascades</strong>.
                                </p>
                                <div className="bg-slate-50 p-5 rounded-xl border border-slate-100 text-sm text-slate-500 font-mono leading-relaxed inline-block">
                                    &gt; IF NOT auth_token THEN throw UnauthenticatedError()<br />
                                    &gt; Solution: Allow standard first-party headers.
                                </div>
                            </section>

                            <div className="h-px bg-slate-50 w-full my-12"></div>

                            <section id="updates" className="scroll-mt-[120px] relative group">
                                <h2 className="text-2xl md:text-3xl font-bold text-text-dark mb-6 flex items-center gap-3">
                                    Policy Infrastructure Updates
                                </h2>
                                <p className="text-slate-500 leading-relaxed text-sm mb-4">
                                    Our platform roadmap mandates minimal bloat. Should we pivot dynamically to introduce new auxiliary analytical or third-party CRM mechanisms in a future sprint timeline, we will synchronously deploy a compliant conditional consent banner requiring your active implicit opt-in before initialization proceeds.
                                </p>
                            </section>
                        </div>
                    </div>
                </div>
            </div>
        </>
    );
}

export default CookiePolicyPage;
