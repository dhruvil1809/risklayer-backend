export default function ContinuousMonitoringSection() {
    return (
        <section className="flex flex-col md:flex-row items-center gap-16 max-w-[1200px] mx-auto mb-20 px-[5%] relative z-10 text-left w-full">
            <div className="flex-1">
                <h2 className="text-3xl md:text-4xl font-bold mb-6 text-text-dark flex items-center gap-4">
                    <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-slate-50 border border-slate-100 shrink-0">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" /></svg>
                    </div>
                    Continuous Monitoring & Webhooks
                </h2>
                <p className="text-sm text-slate-500 leading-relaxed mb-6">Once your audit hits 100%, keep it there. RiskLayer's background workers utilize deterministic diffing algorithms to identify regression drops, alerting your team before users notice.</p>
                <ul className="grid grid-cols-1 sm:grid-cols-2 gap-4 list-none p-0 m-0">
                    <li className="flex items-center gap-2 text-slate-600 text-[0.95rem] bg-slate-50 px-4 py-2.5 rounded-lg border border-slate-100"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2" className="shrink-0"><path d="M20 6L9 17l-5-5" /></svg> Scheduled Cron Scans</li>
                    <li className="flex items-center gap-2 text-slate-600 text-[0.95rem] bg-slate-50 px-4 py-2.5 rounded-lg border border-slate-100"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2" className="shrink-0"><path d="M20 6L9 17l-5-5" /></svg> Delta Comparisons</li>
                    <li className="flex items-center gap-2 text-slate-600 text-[0.95rem] bg-slate-50 px-4 py-2.5 rounded-lg border border-slate-100"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2" className="shrink-0"><path d="M20 6L9 17l-5-5" /></svg> Slack / Email Routing</li>
                    <li className="flex items-center gap-2 text-slate-600 text-[0.95rem] bg-slate-50 px-4 py-2.5 rounded-lg border border-slate-100"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2" className="shrink-0"><path d="M20 6L9 17l-5-5" /></svg> Jira Ticket Sync</li>
                </ul>
            </div>
            <div className="flex-1 flex justify-center relative w-full">
                <div className="w-full max-w-[450px] bg-white rounded-xl p-4 flex gap-4 items-center shadow-2xl border border-slate-100">
                    <div className="w-10 h-10 rounded-lg bg-primary/10 flex shrink-0 items-center justify-center">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
                    </div>
                    <div className="flex-1">
                        <div className="font-bold text-sm text-text-dark">Compliance Alert triggered</div>
                        <div className="text-slate-500 text-xs mt-1 leading-snug">Score dropped from 94 to 88. 2 broken links detected on /checkout.</div>
                    </div>
                </div>
            </div>
        </section>
    );
}
