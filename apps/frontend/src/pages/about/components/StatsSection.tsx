export default function StatsSection() {
    return (
        <section className="w-full max-w-[1240px] mx-auto mb-40 px-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                {[
                    { val: '~90s', label: 'Avg Scan Time' },
                    { val: '42+', label: 'Metrics Checked' },
                    { val: '2.4k', label: 'Daily Scans' }
                ].map((stat, i) => (
                    <div key={i} className="text-center p-12 bg-white border border-slate-100 rounded-[40px] shadow-[0_15px_35px_-10px_rgba(0,0,0,0.05)] hover:shadow-[0_25px_50px_-12px_rgba(0,0,0,0.08)] transition-all group">
                        <div className="text-6xl font-black text-text-dark mb-4 tracking-tighter group-hover:text-primary transition-colors">{stat.val}</div>
                        <div className="text-[13px] font-bold text-primary uppercase tracking-[0.2em]">{stat.label}</div>
                    </div>
                ))}
            </div>
        </section>
    );
}
