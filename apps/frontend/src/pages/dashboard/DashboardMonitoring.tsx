import { Button } from '../../components/ui/Button';
import { Activity, Settings } from 'lucide-react';

export default function DashboardMonitoring() {
    return (
        <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500 h-full">
            <div className="flex justify-between items-center mb-6">
                <div>
                    <h2 className="text-2xl font-bold text-text-dark">Monitoring (Crons)</h2>
                    <p className="text-slate-500">Automated scan schedules and system health heartbeats.</p>
                </div>
                <Button variant="primary" size="sm" className="font-bold text-sm">
                    + Schedule New Task
                </Button>
            </div>

            <div className="bg-white border border-slate-100 rounded-3xl overflow-hidden shadow-sm">
                <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="border-b border-slate-50 bg-slate-50/50">
                                <th className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider">Task Name</th>
                                <th className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider">Frequency</th>
                                <th className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider">Last Run</th>
                                <th className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider">Next Run</th>
                                <th className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider">Status</th>
                                <th className="px-6 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-50">
                            {[
                                { name: 'Weekly Security Audit', frequency: 'Every 7 days', last: '2 days ago', next: 'In 5 days', status: 'Active' },
                                { name: 'Daily Compliance Sync', frequency: 'Every 24 hours', last: '4 hours ago', next: 'In 20 hours', status: 'Active' },
                                { name: 'Sitemap Discovery', frequency: 'Every 30 days', last: '12 days ago', next: 'In 18 days', status: 'Paused' },
                                { name: 'SSL Certificate Monitor', frequency: 'Every 12 hours', last: '1 hour ago', next: 'In 11 hours', status: 'Active' },
                            ].map((job, i) => (
                                <tr key={i} className="hover:bg-slate-50 transition-colors group">
                                    <td className="px-6 py-5">
                                        <div className="flex items-center gap-3">
                                            <div className={`w-2 h-2 rounded-full ${job.status === 'Active' ? 'bg-primary animate-pulse' : 'bg-slate-300'}`}></div>
                                            <span className="text-text-dark font-bold text-sm">{job.name}</span>
                                        </div>
                                    </td>
                                    <td className="px-6 py-5 text-sm text-slate-500">{job.frequency}</td>
                                    <td className="px-6 py-5 text-sm text-slate-500">{job.last}</td>
                                    <td className="px-6 py-5 text-sm text-slate-500">{job.next}</td>
                                    <td className="px-6 py-5">
                                        <span className={`text-[10px] px-2 py-0.5 rounded font-bold tracking-wider uppercase bg-primary/10 text-primary`}>
                                            {job.status}
                                        </span>
                                    </td>
                                    <td className="px-6 py-5">
                                        <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                            <button className="p-2 hover:bg-primary/10 rounded-lg text-primary transition-colors">
                                                <Activity className="w-4 h-4" />
                                            </button>
                                            <button className="p-2 hover:bg-slate-100 rounded-lg text-slate-400 transition-colors">
                                                <Settings className="w-4 h-4" />
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}
