import { useState, useEffect } from 'react';

function TermsOfServicePage() {
    const [activeSection, setActiveSection] = useState('acceptance');

    useEffect(() => {
        const handleScroll = () => {
            const sections = document.querySelectorAll('section[id]');
            let current = 'acceptance';
            sections.forEach(section => {
                const sectionTop = section.getBoundingClientRect().top;
                if (sectionTop <= 200) {
                    current = section.getAttribute('id') || 'acceptance';
                }
            });
            setActiveSection(current);
        };

        window.addEventListener('scroll', handleScroll);
        handleScroll();
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    const navLinks = [
        { id: 'acceptance', label: '1. Acceptance of Terms' },
        { id: 'description', label: '2. Service Overview' },
        { id: 'permissions', label: '3. Scanning Permissions' },
        { id: 'billing', label: '4. Subscriptions & Billing' },
        { id: 'uptime', label: '5. SLA & Availability' },
        { id: 'liability', label: '6. Limitation of Liability' },
        { id: 'changes', label: '7. Updates to Terms' },
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
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /><polyline points="10 9 9 9 8 9" /></svg>
                        Legal Documentation
                    </div>
                    <h1 className="text-4xl md:text-6xl font-extrabold leading-tight mb-6 text-text-dark">
                        Terms of Service
                    </h1>
                    <p className="text-slate-500 text-sm md:text-xl max-w-2xl mx-auto leading-relaxed">
                        Read the rules, guidelines, and agreements for utilizing the RiskLayer platform and automated compliance scanning services safely.
                    </p>
                    <div className="mt-8 flex justify-center items-center gap-4 text-sm text-slate-400 w-full">
                        <span className="flex items-center gap-2">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2" /><line x1="16" y1="2" x2="16" y2="6" /><line x1="8" y1="2" x2="8" y2="6" /><line x1="3" y1="10" x2="21" y2="10" /></svg>
                            Effective Date: March 2026
                        </span>
                    </div>
                </div>

                <div className="max-w-[1280px] mx-auto px-[5%] flex flex-col lg:flex-row gap-12 lg:gap-20">

                    {/* Sticky Sidebar */}
                    <aside className="lg:w-[280px] shrink-0">
                        <div className="sticky top-[120px] bg-white border border-slate-100 p-6 rounded-2xl shadow-sm">
                            <h3 className="text-text-dark font-bold mb-4 uppercase text-sm tracking-wider">Document Outline</h3>
                            <nav className="flex flex-col gap-1">
                                {navLinks.map((link) => (
                                    <a
                                        key={link.id}
                                        href={`#${link.id}`}
                                        onClick={(e) => scrollTo(e, link.id)}
                                        className={`px-4 py-2.5 rounded-xl transition-all duration-300 text-sm font-medium border border-transparent ${activeSection === link.id
                                            ? 'bg-primary/10 text-primary border-primary/20 shadow-sm'
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

                            <section id="acceptance" className="scroll-mt-[120px] mb-12 relative group">
                                <h2 className="text-2xl md:text-3xl font-bold text-text-dark mb-6 flex items-center gap-3">
                                    <span className="text-primary opacity-50 font-mono text-xl group-hover:opacity-100 transition-opacity">01.</span>
                                    Acceptance of Terms
                                </h2>
                                <p className="text-slate-500 leading-relaxed text-sm mb-4 bg-slate-50 p-6 border border-slate-100 rounded-2xl">
                                    By accessing, registering, or using the RiskLayer platform (the "Service"), you agree explicitly to be bound unconditionally by these Terms of Service. If you are executing these terms on behalf of an enterprise company or digital agency, you legally represent that you have the undisputed authority to bind that corporate entity to these Terms. If you do not have such authority, you must not use the Service.
                                </p>
                            </section>

                            <div className="h-px bg-slate-50 w-full my-12"></div>

                            <section id="description" className="scroll-mt-[120px] mb-12 relative group">
                                <h2 className="text-2xl md:text-3xl font-bold text-text-dark mb-6 flex items-center gap-3">
                                    <span className="text-primary opacity-50 font-mono text-xl group-hover:opacity-100 transition-opacity">02.</span>
                                    Description of Service
                                </h2>
                                <p className="text-slate-500 leading-relaxed text-sm mb-6">
                                    RiskLayer operates as an automated B2B SaaS architecture designed to systematically identify security weaknesses, accessibility (WCAG/ADA) gaps, structural errors, and missing baseline legal compliance markers on publicly accessible URLs.
                                </p>
                                <div className="p-5 border border-primary/20 bg-primary/5 rounded-xl text-primary">
                                    <strong className="block mb-2 text-primary flex items-center gap-2">
                                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>
                                        Critical Explicit Disclaimer
                                    </strong>
                                    RiskLayer is exclusively a technical informational tool utilizing heuristic analysis. It does NOT in any capacity provide licensed legal, recognized financial, or valid regulatory advice. You are responsible for consulting real attorneys regarding actual compliance liability.
                                </div>
                            </section>

                            <div className="h-px bg-slate-50 w-full my-12"></div>

                            <section id="permissions" className="scroll-mt-[120px] mb-12 relative group">
                                <h2 className="text-2xl md:text-3xl font-bold text-text-dark mb-6 flex items-center gap-3">
                                    <span className="text-primary opacity-50 font-mono text-xl group-hover:opacity-100 transition-opacity">03.</span>
                                    Scanning Permissions
                                </h2>
                                <p className="text-slate-500 leading-relaxed text-sm mb-4">
                                    Core to our operational integrity, you explicitly agree to solely initiate automated scans on domains for which you possess verified authorization (for example, your own web property or a contracted client's specific digital deliverable).
                                </p>
                                <p className="text-primary font-bold leading-relaxed bg-primary/10 p-4 rounded-xl border border-primary/20 flex gap-3">
                                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="shrink-0 mt-1"><polygon points="12 2 2 22 22 22 12 2" /><line x1="12" y1="8" x2="12" y2="14" /><line x1="12" y1="18" x2="12.01" y2="18" /></svg>
                                    <span>Using the Service API limits or frontend dashboards for malicious reconnaissance, competitive scraping, or denial-of-service simulation against unprotected third parties will trigger immediate, permanent account termination WITHOUT refund.</span>
                                </p>
                            </section>

                            <div className="h-px bg-slate-50 w-full my-12"></div>

                            <section id="billing" className="scroll-mt-[120px] mb-12 relative group">
                                <h2 className="text-2xl md:text-3xl font-bold text-text-dark mb-6 flex items-center gap-3">
                                    <span className="text-primary opacity-50 font-mono text-xl group-hover:opacity-100 transition-opacity">04.</span>
                                    Subscriptions & Billing
                                </h2>
                                <p className="text-slate-500 leading-relaxed text-sm mb-4">
                                    Premium, non-rate-limited features, such as recursive deep directory crawls and white-labeled agency PDF exports, require an active Stripe subscription.
                                </p>
                                <ul className="space-y-3 text-slate-500 pl-4 border-l-2 border-slate-100">
                                    <li className="pl-2">Payments are processed categorically in advance.</li>
                                    <li className="pl-2">Payments are strictly non-refundable following the expiration of the standard 7-day initial satisfaction period.</li>
                                    <li className="pl-2">You remain actively responsible for ensuring your payment cryptographic method remains valid and funded.</li>
                                    <li className="pl-2">Automated scan quotas strictly apply governed by your active billing tier parameters.</li>
                                </ul>
                            </section>

                            <div className="h-px bg-slate-50 w-full my-12"></div>

                            <section id="uptime" className="scroll-mt-[120px] mb-12 relative group">
                                <h2 className="text-2xl md:text-3xl font-bold text-text-dark mb-6 flex items-center gap-3">
                                    <span className="text-primary opacity-50 font-mono text-xl group-hover:opacity-100 transition-opacity">05.</span>
                                    Uptime & Availability Guarantee
                                </h2>
                                <p className="text-slate-500 leading-relaxed text-sm mb-4">
                                    Our operational DevOps team targets a <strong className="text-primary">99.9% uptime</strong> standard for scheduled background cron scans and webhook alert deployments.
                                </p>
                                <p className="text-slate-500 leading-relaxed text-sm">
                                    However, the RiskLayer SaaS operates functionally on an "as-is" and "as available" basis without implied continuous warranties of any kind. Service interruptions linked to upstream vendor outages (AWS/GCP), networking bottlenecks, or emergency patching do not qualify as breach of contract.
                                </p>
                            </section>

                            <div className="h-px bg-slate-50 w-full my-12"></div>

                            <section id="liability" className="scroll-mt-[120px] mb-12 relative group">
                                <h2 className="text-2xl md:text-3xl font-bold text-text-dark mb-6 flex items-center gap-3">
                                    <span className="text-primary opacity-50 font-mono text-xl group-hover:opacity-100 transition-opacity">06.</span>
                                    Limitation of Liability
                                </h2>
                                <div className="p-6 bg-slate-50 border border-slate-100 rounded-xl">
                                    <p className="text-slate-500 leading-relaxed text-sm uppercase tracking-wide font-bold">
                                        Under no verifiable circumstances shall RiskLayer, its executive operators, or contracted infrastructure partners be liable for indirect, incidental, special, consequential, or punitive damages, including loss of enterprise profits, unrecoverable data corruption, or damaged goodwill, arising from your continued use or inability to connect to the Service.
                                    </p>
                                </div>
                            </section>

                            <div className="h-px bg-slate-50 w-full my-12"></div>

                            <section id="changes" className="scroll-mt-[120px] relative group">
                                <h2 className="text-2xl md:text-3xl font-bold text-text-dark mb-6 flex items-center gap-3">
                                    <span className="text-primary opacity-50 font-mono text-xl group-hover:opacity-100 transition-opacity">07.</span>
                                    Changes to Terms
                                </h2>
                                <p className="text-slate-500 leading-relaxed text-sm mb-4">
                                    We explicitly reserve the administrative right to materially alter or modify these operative terms dynamically at any time. Active verified subscribers will be notified directly via registered email addresses of any significant overriding updates affecting active workloads.
                                </p>
                            </section>
                        </div>
                    </div>
                </div>
            </div>
        </>
    );
}

export default TermsOfServicePage;
