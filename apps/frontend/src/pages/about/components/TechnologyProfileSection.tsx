export default function TechnologyProfileSection() {
    return (
        <section className="flex flex-col md:flex-row items-center gap-16 max-w-[1240px] mx-auto mb-40 relative z-10 w-full px-6">
            <div className="flex-1">
                <div className="flex items-center justify-center w-14 h-14 rounded-2xl bg-primary/10 border border-primary/20 text-primary mb-8 shadow-sm">
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6" /></svg>
                </div>
                <h2 className="text-3xl md:text-5xl font-bold mb-8 text-text-dark tracking-tight">
                    Beyond Heuristics
                </h2>
                <p className="text-lg text-slate-500 leading-relaxed mb-8">
                    Unlike basic linters or keyword scanners, RiskLayer operates a headless rendering engine to dynamically evaluate your application exactly as a modern user (or auditor) would experience it.
                </p>
                <div className="p-6 bg-slate-50 rounded-2xl border border-slate-100">
                    <p className="text-sm text-slate-500 leading-relaxed font-semibold">
                        We wait for JavaScript payloads to execute, evaluate CSSOM tree states, and verify accessibility attributes on fully hydrated DOM nodes. We capture the true state of your application at the exact moment of deployment.
                    </p>
                </div>
            </div>
            <div className="flex-1 flex w-full relative">
                <div className="w-full max-w-[540px] mx-auto grid grid-cols-2 gap-4">
                    {[
                        { title: 'Node Traversal', desc: 'Deep DOM analysis down to shadow roots.', color: 'text-primary' },
                        { title: 'State Execution', desc: 'Waits for hydration and fetch requests.', color: 'text-slate-700' },
                        { title: 'Legal NLP', desc: 'Token analysis of document validity.', color: 'text-primary' },
                        { title: 'A11y Trees', desc: 'Full contrast and ARIA matrix scoring.', color: 'text-slate-700' }
                    ].map((feature, i) => (
                        <div key={i} className="bg-white border border-slate-100 rounded-2xl p-6 shadow-sm hover:shadow-md hover:border-slate-200 transition-all group">
                            <div className={`${feature.color} font-bold text-base mb-2 group-hover:translate-x-1 transition-transform inline-block`}>{feature.title}</div>
                            <div className="text-[13px] text-slate-500 leading-relaxed">{feature.desc}</div>
                        </div>
                    ))}
                </div>
            </div>
        </section>
    );
}
