export default function SolutionSection() {
    return (
        <section className="flex flex-col md:flex-row-reverse items-center gap-16 max-w-[1240px] mx-auto mb-40 relative z-10 w-full px-6">
            <div className="flex-1">
                <div className="flex items-center justify-center w-14 h-14 rounded-2xl bg-primary/10 border border-primary/20 text-primary mb-8 shadow-sm">
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" /></svg>
                </div>
                <h2 className="text-3xl md:text-5xl font-bold mb-8 text-text-dark tracking-tight">
                    The Deterministic Checkpoint
                </h2>
                <p className="text-lg text-slate-500 leading-relaxed mb-10">
                    We don't try to auto-fix your code with unpredictable AI black boxes. We believe developers and automated systems should understand their strict liability gaps clearly.
                </p>
                <p className="text-lg text-slate-500 leading-relaxed font-semibold italic">
                    RiskLayer translates chaotic DOM states, missing compliance footprints, and complex structure rules into a single, plain-English priority payload. We act as the final programmatic checkpoint before your deliverable ships.
                </p>
            </div>
            <div className="flex-1 flex justify-center w-full">
                <div className="w-full max-w-[480px] bg-white border border-slate-100 rounded-[32px] p-8 relative shadow-[0_40px_80px_-20px_rgba(0,0,0,0.06)] overflow-hidden">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-primary/5 blur-3xl rounded-full translate-x-1/2 -translate-y-1/2" />

                    <div className="flex items-center justify-between mb-8">
                        <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center text-primary shadow-sm border border-primary/10">
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"></polyline></svg>
                            </div>
                            <div>
                                <div className="font-bold text-sm text-text-dark">Scan Complete</div>
                                <div className="text-[10px] text-slate-400 font-black uppercase tracking-widest">id: RL-2024-X9</div>
                            </div>
                        </div>
                        <div className="px-3 py-1 bg-slate-50 border border-slate-100 rounded-lg text-slate-400 text-[10px] font-black tracking-widest uppercase">
                            Stable
                        </div>
                    </div>

                    <div className="space-y-4 mb-8">
                        {[
                            { label: 'Accessibility', score: 'Pass', color: 'text-primary' },
                            { label: 'Legal Footprint', score: '98%', color: 'text-text-dark' },
                            { label: 'Privacy Signals', score: 'Valid', color: 'text-primary' }
                        ].map((item, i) => (
                            <div key={i} className="flex items-center justify-between py-3 border-b border-slate-50 last:border-none">
                                <div className="text-[13px] font-semibold text-slate-500">{item.label}</div>
                                <div className={`text-[13px] font-black ${item.color}`}>{item.score}</div>
                            </div>
                        ))}
                    </div>

                    <div className="bg-slate-50 rounded-2xl p-6 flex items-center justify-between border border-slate-100">
                        <div>
                            <div className="text-[11px] font-black text-slate-400 uppercase tracking-widest mb-1">Risk Posture</div>
                            <div className="text-2xl font-black text-text-dark tracking-tighter">Excellent</div>
                        </div>
                        <div className="text-4xl font-black text-primary tracking-tighter">94%</div>
                    </div>
                </div>
            </div>
        </section>
    );
}
