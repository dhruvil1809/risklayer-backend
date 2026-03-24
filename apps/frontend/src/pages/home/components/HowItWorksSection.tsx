import { Box, Wand2, FileText } from 'lucide-react';

export default function HowItWorksSection() {
    return (
        <section className="py-32 px-[5%] relative z-10 w-full overflow-hidden bg-white">
            <div className="max-w-[1280px] mx-auto text-center mb-24">
                <h2 className="text-4xl md:text-6xl font-extrabold text-text-dark mb-8">Simple process, <span className="text-primary">powerful results</span></h2>
                <p className="text-slate-500 text-lg md:text-xl max-w-2xl mx-auto font-medium">From raw URL to actionable compliance roadmap in under 90 seconds. We map the entire invisible layer of your deliverable.</p>
            </div>

            <div className="max-w-[1280px] mx-auto grid grid-cols-1 md:grid-cols-3 gap-16 relative">
                {/* Connecting Line (Desktop) */}
                <div className="hidden md:block absolute top-[50px] left-[15%] right-[15%] h-[2px] bg-slate-100 z-0"></div>

                {[
                    { num: '01', title: 'Deep Crawl', desc: 'Our worker nodes visit your URL, wait for JS frameworks to hydrate, and trace all internal links to map your entire application state.', icon: <Box className="w-8 h-8" />, color: 'primary' },
                    { num: '02', title: 'NLP Analysis', desc: 'We scan DOM trees against WCAG matrices, use NLP to verify privacy policy validity, and perform 42+ distinct structural checks.', icon: <Wand2 className="w-8 h-8" />, color: 'primary' },
                    { num: '03', title: 'Dynamic Report', desc: 'Instead of raw JSON data, you receive a beautifully formatted, plain-English report detailing exactly what is broken and how to fix it legally.', icon: <FileText className="w-8 h-8" />, color: 'primary' }
                ].map((step, i) => (
                    <div key={i} className="flex flex-col items-center text-center relative z-10 group">
                        <div className={`w-24 h-24 rounded-[32px] bg-white border-4 border-slate-50 flex items-center justify-center mb-8 shadow-2xl shadow-black/5 group-hover:scale-105 transition-transform duration-500`}>
                            <div className="text-primary">
                                {step.icon}
                            </div>
                        </div>
                        <div className="inline-block px-3 py-1 bg-slate-100 rounded-full text-xs font-bold text-slate-400 mb-4 tracking-widest uppercase">
                            Step {step.num}
                        </div>
                        <h3 className="text-2xl font-bold text-text-dark mb-4">{step.title}</h3>
                        <p className="text-slate-500 leading-relaxed font-medium">{step.desc}</p>
                    </div>
                ))}
            </div>
        </section>
    );
}
