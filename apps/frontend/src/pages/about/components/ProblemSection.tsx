export default function ProblemSection() {
    return (
        <section className="flex flex-col md:flex-row items-center gap-16 max-w-[1240px] mx-auto mb-32 relative z-10 w-full px-6">
            <div className="flex-1">
                <div className="flex items-center justify-center w-14 h-14 rounded-2xl bg-primary/10 border border-primary/20 text-primary mb-8 shadow-sm">
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
                </div>
                <h2 className="text-3xl md:text-5xl font-bold mb-8 text-text-dark tracking-tight">
                    The Liability Gap
                </h2>
                <p className="text-lg text-slate-500 leading-relaxed mb-8">
                    Modern development moves faster than legal review. When an engineering team pushes a new feature or an AI agent automatically scales out new landing pages, standard CI/CD pipelines only check for broken code—not broken laws or accessibility statutes.
                </p>
                <div className="p-6 bg-slate-50 rounded-2xl border border-slate-100">
                    <p className="text-sm text-slate-500 leading-relaxed font-semibold">
                        This gap in the development cycle leaves massive enterprises and small agencies alike completely exposed to civil lawsuits, ADA troll firms, and regulatory fines.
                    </p>
                </div>
            </div>
            <div className="flex-1 flex justify-center w-full">
                <div className="w-full max-w-[500px] bg-white border border-slate-100 rounded-[32px] p-10 relative shadow-[0_20px_50px_-12px_rgba(0,0,0,0.05)]">
                    <div className="absolute -top-4 -left-4 bg-primary text-white text-[10px] font-black px-3 py-1.5 rounded-lg shadow-lg uppercase tracking-widest">
                        Security Alert
                    </div>
                    <div className="space-y-5 font-mono text-[13px]">
                        <div className="flex items-center gap-3 text-primary font-bold">
                            <span className="w-2 h-2 rounded-full bg-primary" />
                            Failed: Missing Privacy Policy on /checkout
                        </div>
                        <div className="flex items-center gap-3 text-primary font-bold">
                            <span className="w-2 h-2 rounded-full bg-primary" />
                            Failed: Empty alt attributes on hero image
                        </div>
                        <div className="flex items-center gap-3 text-primary font-bold">
                            <span className="w-2 h-2 rounded-full bg-primary" />
                            Failed: Button missing contrast ratio (WCAG)
                        </div>
                        <div className="pt-4 border-t border-slate-100 text-slate-300 italic">
                            Pipeline auto-continued anyway...
                        </div>
                    </div>
                </div>
            </div>
        </section>
    );
}
