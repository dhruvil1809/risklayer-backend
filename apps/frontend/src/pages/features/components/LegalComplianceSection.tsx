export default function LegalComplianceSection() {
    return (
        <section className="flex flex-col lg:flex-row items-center gap-10 md:gap-14 max-w-[1300px] mx-auto mb-12 md:mb-20 px-[5%] relative z-10 text-left w-full">
            <div className="flex-1 w-full order-2 lg:order-1">
                <div className="inline-flex items-center justify-center p-2.5 rounded-xl bg-primary/5 border border-primary/10 mb-5">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
                </div>
                <h2 className="text-3xl md:text-4xl lg:text-[2.75rem] font-black mb-5 text-text-dark leading-tight tracking-tight">
                    Legal & Compliance Validation
                </h2>
                <p className="text-base md:text-[1.05rem] text-slate-500 leading-relaxed mb-6 font-medium">Every website needs foundational legal documentation to protect against liability. RiskLayer crawls the deepest directories to identify the presence, validity, and linkage of mandatory compliance signals.</p>
                <ul className="grid grid-cols-1 sm:grid-cols-2 gap-4 list-none p-0 m-0">
                    <li className="flex items-center gap-3 text-slate-600 text-[0.9rem] md:text-[0.95rem] font-bold bg-slate-50 px-4 py-3 rounded-xl border border-slate-100 hover:border-primary/20 transition-colors"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="3" className="shrink-0"><path d="M20 6L9 17l-5-5" /></svg> Privacy Policy Detection</li>
                    <li className="flex items-center gap-3 text-slate-600 text-[0.9rem] md:text-[0.95rem] font-bold bg-slate-50 px-4 py-3 rounded-xl border border-slate-100 hover:border-primary/20 transition-colors"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="3" className="shrink-0"><path d="M20 6L9 17l-5-5" /></svg> Terms of Service Links</li>
                    <li className="flex items-center gap-3 text-slate-600 text-[0.9rem] md:text-[0.95rem] font-bold bg-slate-50 px-4 py-3 rounded-xl border border-slate-100 hover:border-primary/20 transition-colors"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="3" className="shrink-0"><path d="M20 6L9 17l-5-5" /></svg> EU/UK Cookie Notices</li>
                    <li className="flex items-center gap-3 text-slate-600 text-[0.9rem] md:text-[0.95rem] font-bold bg-slate-50 px-4 py-3 rounded-xl border border-slate-100 hover:border-primary/20 transition-colors"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="3" className="shrink-0"><path d="M20 6L9 17l-5-5" /></svg> Business Identity Match</li>
                </ul>
            </div>
            <div className="flex-1 flex justify-center relative w-full order-1 lg:order-2">
                <div className="w-full max-w-[550px] bg-white border border-slate-100 rounded-[24px] md:rounded-[32px] overflow-hidden shadow-2xl relative group transform transition-transform hover:scale-[1.02] duration-500">
                    <div className="bg-slate-50/50 py-3 md:py-4 px-6 md:px-8 flex gap-2 border-b border-slate-100 items-center">
                        <div className="w-3 h-3 rounded-full bg-red-400"></div>
                        <div className="w-3 h-3 rounded-full bg-yellow-400"></div>
                        <div className="w-3 h-3 rounded-full bg-green-400"></div>
                        <div className="ml-4 h-4 md:h-5 bg-slate-100 rounded-full w-32 md:w-48"></div>
                    </div>
                    <div className="p-8 md:p-12">
                        <div className="bg-slate-50 rounded-2xl p-6 md:p-8 mb-8 border border-slate-100">
                            <div className="h-6 bg-slate-200 rounded-full mb-6 w-[60%]"></div>
                            <div className="space-y-4">
                                <div className="h-3 bg-slate-100 rounded-full w-full"></div>
                                <div className="h-3 bg-slate-100 rounded-full w-[90%]"></div>
                                <div className="h-3 bg-slate-100 rounded-full w-[75%]"></div>
                            </div>
                        </div>
                        <div className="grid grid-cols-2 gap-4">
                            <div className="bg-primary/5 p-6 rounded-2xl border border-primary/10">
                                <div className="h-2 bg-primary/20 rounded-full mb-3 w-[40%]"></div>
                                <div className="h-6 bg-primary/40 rounded-full w-[80%]"></div>
                            </div>
                            <div className="bg-slate-50 p-6 rounded-2xl border border-slate-100">
                                <div className="h-2 bg-slate-200 rounded-full mb-3 w-[40%]"></div>
                                <div className="h-6 bg-slate-200 rounded-full w-[80%]"></div>
                            </div>
                        </div>
                    </div>
                </div>
                {/* Decoration blob */}
                <div className="absolute -top-10 -right-10 w-40 h-40 bg-primary/10 blur-3xl rounded-full -z-10 group-hover:bg-primary/20 transition-colors duration-500"></div>
            </div>
        </section>
    );
}
