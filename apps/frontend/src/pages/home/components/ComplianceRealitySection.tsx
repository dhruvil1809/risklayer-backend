import { ShieldCheck, FileWarning, BadgeCheck } from 'lucide-react';

export default function ComplianceRealitySection() {
    return (
        <section className="py-20 px-[5%] relative z-10 w-full bg-slate-50/50 overflow-hidden">
            <div className="max-w-[1200px] mx-auto flex flex-col lg:flex-row gap-16 items-center">
                <div className="flex-1">
                    <div className="bg-primary/10 text-primary px-3 py-1 rounded-full text-[11px] font-black mb-6 border border-primary/20 tracking-widest inline-block uppercase">
                        The Compliance Reality
                    </div>
                    <h2 className="text-3xl md:text-5xl font-black text-text-dark mb-6 leading-[1.1] tracking-tight">
                        Ignorance is no longer a <br />
                        <span className="text-primary italic">legal defense.</span>
                    </h2>
                    <p className="text-md text-slate-500 leading-relaxed mb-8 max-w-[500px] font-medium">
                        Enterprise web compliance lawsuits rose by 43%. Regulatory bodies no longer accept "we didn't know" as an excuse for failing to meet ADA, WCAG 2.2, or GDPR standards.
                    </p>

                    <div className="flex flex-col gap-4">
                        <div className="flex items-start gap-4 text-slate-600 bg-white p-5 rounded-2xl border border-slate-100 shadow-[0_4px_20px_-8px_rgba(0,0,0,0.05)] transition-all hover:shadow-lg hover:shadow-black/5 group">
                            <div className="w-10 h-10 rounded-xl bg-orange-50 text-primary flex items-center justify-center shrink-0 group-hover:bg-primary group-hover:text-white transition-colors">
                                <FileWarning className="w-5 h-5" />
                            </div>
                            <div className="flex flex-col">
                                <span className="text-[15px] font-bold text-text-dark">Settlement Risks</span>
                                <span className="text-[13px] font-medium text-slate-400">Average settlement for accessibility lawsuits is <strong className="text-primary">$35,000+</strong>.</span>
                            </div>
                        </div>

                        <div className="flex items-start gap-4 text-slate-600 bg-white p-5 rounded-2xl border border-slate-100 shadow-[0_4px_20px_-8px_rgba(0,0,0,0.05)] transition-all hover:shadow-lg hover:shadow-black/5 group">
                            <div className="w-10 h-10 rounded-xl bg-orange-50 text-primary flex items-center justify-center shrink-0 group-hover:bg-primary group-hover:text-white transition-colors">
                                <ShieldCheck className="w-5 h-5" />
                            </div>
                            <div className="flex flex-col">
                                <span className="text-[15px] font-bold text-text-dark">GDPR Enforcement</span>
                                <span className="text-[13px] font-medium text-slate-400">Fines can reach up to <strong className="text-primary">€20 million</strong> or 4% of global revenue.</span>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="flex-1 w-full relative">
                    {/* Floating Decorative Elements */}
                    <div className="absolute -top-10 -right-10 w-40 h-40 bg-primary/5 blur-3xl -z-10 animate-pulse"></div>
                    <div className="absolute -bottom-10 -left-10 w-40 h-40 bg-blue-400/5 blur-3xl -z-10"></div>

                    <div className="bg-white border border-slate-100 p-8 rounded-[32px] shadow-[0_30px_60px_-15px_rgba(0,0,0,0.08)] relative overflow-hidden">
                        {/* Card Header */}
                        <div className="flex justify-between items-start mb-8 pb-6 border-b border-slate-50">
                            <div>
                                <div className="text-text-dark font-black text-xl mb-1 flex items-center gap-2">
                                    Risk Assessment
                                    <BadgeCheck className="w-4 h-4 text-primary" />
                                </div>
                                <div className="text-slate-400 text-[10px] font-bold uppercase tracking-widest flex items-center gap-1.5 line-none">
                                    <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse"></span>
                                    Report ID: #RL-2024
                                </div>
                            </div>
                            <div className="px-3.5 py-1.5 bg-primary text-white rounded-lg text-[10px] font-black shadow-lg shadow-primary/20 tracking-wider">
                                AUDIT READY
                            </div>
                        </div>

                        {/* Progress Stats */}
                        <div className="space-y-6">
                            {[
                                { label: 'A11y/WCAG Score', value: 42, color: 'bg-primary/40' },
                                { label: 'Legal Pages Status', value: 60, label_override: 'Incomplete', color: 'bg-primary/60' },
                                { label: 'Trust Signals', value: 95, label_override: 'Optimal', color: 'bg-primary' }
                            ].map((stat, idx) => (
                                <div key={idx}>
                                    <div className="flex justify-between text-[13px] mb-2.5 font-bold">
                                        <span className="text-slate-500">{stat.label}</span>
                                        <span className={stat.value < 50 ? 'text-primary' : 'text-slate-800'}>
                                            {stat.label_override || `${stat.value}/100`}
                                        </span>
                                    </div>
                                    <div className="h-2 w-full bg-slate-50 rounded-full overflow-hidden flex">
                                        <div
                                            className={`h-full ${stat.color} transition-all duration-1000 ease-out rounded-full`}
                                            style={{ width: `${stat.value}%` }}
                                        ></div>
                                    </div>
                                </div>
                            ))}
                        </div>

                        {/* Footer decorative note */}
                        <div className="mt-8 pt-6 border-t border-slate-50 text-center">
                            <span className="text-[11px] font-bold text-slate-300 uppercase tracking-widest italic">
                                Scanned by RiskLayer AI Engine
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    );
}
