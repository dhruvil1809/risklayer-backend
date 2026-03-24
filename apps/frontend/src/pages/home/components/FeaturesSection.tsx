import { AlertCircle, Lock, ShieldCheck, Box } from 'lucide-react';

export default function FeaturesSection() {
    return (
        <section id="features" className="py-12 md:py-24 px-[5%] bg-bg-light relative z-10 w-full overflow-hidden">
            <div className="max-w-[1400px] mx-auto">
                <div className="text-center mb-10 md:mb-16 px-4">
                    <h2 className="text-3xl md:text-4xl lg:text-5xl font-black text-text-dark mb-4 tracking-tight leading-tight">
                        Everything you need to <span className="text-primary italic">monitor risk</span>
                    </h2>
                    <p className="text-base md:text-lg max-w-[700px] mx-auto font-medium text-slate-500 leading-relaxed">
                        Powerful automation that works while you sleep. Identify vulnerabilities before they become liabilities with our enterprise-grade AI engine.
                    </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 md:gap-8">
                    {[
                        { title: 'Accessibility', desc: 'Scans for ADA/WCAG compliance baseline to ensure your site is usable for everyone.', icon: <AlertCircle className="w-7 h-7 md:w-8 md:h-8" /> },
                        { title: 'Legal Compliance', desc: 'Detects missing privacy policies, terms of service, and cookie notices automatically.', icon: <Lock className="w-7 h-7 md:w-8 md:h-8" /> },
                        { title: 'Trust Signals', desc: 'Verifies SSL, checks for broken links, and metadata health to build visitor trust.', icon: <ShieldCheck className="w-7 h-7 md:w-8 md:h-8" /> },
                        { title: 'Structure', desc: 'Identifies structural elements like H1s and ensures proper sitemap detection for SEO.', icon: <Box className="w-7 h-7 md:w-8 md:h-8" /> }
                    ].map((feature, idx) => (
                        <div key={idx} className="bg-white rounded-[24px] md:rounded-[40px] p-8 md:p-10 transition-all duration-300 hover:shadow-2xl hover:shadow-primary/10 group border border-slate-100 hover:-translate-y-1">
                            <div className="w-12 h-12 md:w-[60px] md:h-[60px] rounded-xl md:rounded-[20px] flex items-center justify-center mb-6 md:mb-8 bg-primary/10 text-primary group-hover:scale-110 transition-transform group-hover:bg-primary group-hover:text-white duration-500">
                                {feature.icon}
                            </div>
                            <h3 className="text-xl md:text-2xl font-bold text-text-dark mb-3 md:mb-4 group-hover:text-primary transition-colors">{feature.title}</h3>
                            <p className="text-sm md:text-base text-slate-500 leading-relaxed font-medium">{feature.desc}</p>
                        </div>
                    ))}
                </div>
            </div>
        </section>
    );
}
