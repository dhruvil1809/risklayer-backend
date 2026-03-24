export default function A11yStructureSection() {
    return (
        <section className="flex flex-col md:flex-row-reverse items-center gap-16 max-w-[1200px] mx-auto mb-24 px-[5%] relative z-10 text-left w-full">
            <div className="flex-1">
                <h2 className="text-3xl md:text-4xl font-bold mb-6 text-text-dark flex items-center gap-4">
                    <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-slate-50 border border-slate-100 shrink-0">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2"><path d="M12 2A10 10 0 1 0 22 12A10 10 0 0 0 12 2z" /><path d="M12 8v4" /><path d="M12 16h.01" /></svg>
                    </div>
                    A11y & Structure Audits
                </h2>
                <p className="text-sm text-slate-500 leading-relaxed mb-6">Accessibility isn't just about inclusion—it's federal statute. We parse DOMs sequentially to verify WCAG/ADA baseline requirements alongside critical SEO metadata structures.</p>
                <ul className="grid grid-cols-1 sm:grid-cols-2 gap-4 list-none p-0 m-0">
                    <li className="flex items-center gap-2 text-slate-600 text-[0.95rem] bg-slate-50 px-4 py-2.5 rounded-lg border border-slate-100"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2" className="shrink-0"><path d="M20 6L9 17l-5-5" /></svg> Image ALT Attributes</li>
                    <li className="flex items-center gap-2 text-slate-600 text-[0.95rem] bg-slate-50 px-4 py-2.5 rounded-lg border border-slate-100"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2" className="shrink-0"><path d="M20 6L9 17l-5-5" /></svg> Form Labels & ARIA</li>
                    <li className="flex items-center gap-2 text-slate-600 text-[0.95rem] bg-slate-50 px-4 py-2.5 rounded-lg border border-slate-100"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2" className="shrink-0"><path d="M20 6L9 17l-5-5" /></svg> Heading Hierarchies</li>
                    <li className="flex items-center gap-2 text-slate-600 text-[0.95rem] bg-slate-50 px-4 py-2.5 rounded-lg border border-slate-100"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2" className="shrink-0"><path d="M20 6L9 17l-5-5" /></svg> Duplicate XML Titles</li>
                </ul>
            </div>
            <div className="flex-1 flex justify-center relative w-full">
                <div className="w-full max-w-[550px] bg-white border border-slate-100 rounded-2xl overflow-hidden shadow-2xl">
                    <div className="bg-slate-50 py-3 px-4 border-b border-slate-100 flex items-center">
                        <div className="text-xs opacity-50 font-mono tracking-widest text-primary">SCANNER / XML_PARSER</div>
                    </div>
                    <div className="p-8 font-mono text-primary/70 text-sm leading-loose">
                        <p className="mb-2">&gt; parsing node tree...</p>
                        <p className="text-primary mb-2">&gt; [PASS] 42/42 alt tags</p>
                        <p className="text-primary/40 mb-2">&gt; [FAIL] H1 missing on route /blog</p>
                        <p className="mb-2">&gt; generating payload...</p>
                        <p className="animate-pulse mb-0">_</p>
                    </div>
                </div>
            </div>
        </section>
    );
}
