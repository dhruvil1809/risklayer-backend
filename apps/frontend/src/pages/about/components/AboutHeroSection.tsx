export default function AboutHeroSection() {
    return (
        <section className="relative w-full py-20 overflow-hidden bg-white">
            {/* Background Decorations */}
            <div className="bg-grid-effect-sides opacity-60" />
            <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-primary/5 blur-[120px] rounded-full -translate-y-1/2 translate-x-1/2" />

            <div className="max-w-[1280px] mx-auto px-6 mb-20 flex flex-col items-center text-center relative z-10">
                <div className="inline-flex items-center justify-center gap-2 px-3.5 py-1.5 rounded-full bg-slate-50 border border-slate-100 text-slate-500 text-[11px] font-black mb-8 uppercase tracking-[0.2em] shadow-xs">
                    <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                    Our Core Mission
                </div>
                <h1 className="text-[48px] md:text-[72px] font-extrabold leading-[1.1] mb-10 text-text-dark max-w-5xl tracking-tighter">
                    Building the <span className="text-primary italic">compliance layer</span> for the automated web.
                </h1>
                <p className="text-xl md:text-2xl text-slate-500 max-w-3xl mx-auto leading-relaxed font-medium">
                    As AI agents write code and pipelines deploy sites continuously, human compliance teams represent massive bottlenecks. We created <span className="text-text-dark font-bold">RiskLayer</span> to bridge this gap.
                </p>

                <div className="mt-16 flex items-center justify-center gap-12 grayscale opacity-50">
                    {/* Placeholder for trusted by logos or similar if needed */}
                </div>
            </div>
        </section>
    );
}
