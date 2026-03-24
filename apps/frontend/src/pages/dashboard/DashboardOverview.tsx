import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { Button } from '../../components/ui/Button';
import { Activity, ShieldCheck, AlertTriangle, Bug, Clock, Link as LinkIcon, Plus } from 'lucide-react';
import DashboardNewScanModal from './components/DashboardNewScanModal';

export const MetricCard = ({ title, value, target, icon: Icon, alert = false }: any) => (
    <div className={`relative overflow-hidden rounded-2xl p-5 border ${alert ? 'bg-primary/5 border-primary/20' : 'bg-white border-slate-100 hover:border-primary/20'
        } transition-all duration-300 group bg-white border border-slate-200 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)]`}>
        <div className="absolute inset-0 bg-linear-to-br from-primary/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
        <div className="flex justify-between items-start mb-4">
            <div className={`p-2 rounded-lg bg-primary/10 text-primary`}>
                <Icon className="w-5 h-5" />
            </div>
            {target && (
                <div className="text-xs font-semibold px-2 py-1 rounded bg-slate-50 text-slate-500 border border-slate-100">
                    Target: {target}
                </div>
            )}
        </div>
        <div>
            <h4 className="text-slate-500 text-sm font-medium mb-1">{title}</h4>
            <div className={`text-2xl font-bold text-text-dark`}>
                {value}
            </div>
        </div>
    </div>
);

export default function DashboardOverview() {
    const navigate = useNavigate();
    const [recentScans, setScans] = useState<any[]>([]);
    const [loadingScans, setLoadingScans] = useState(true);
    const [isNewScanOpen, setIsNewScanOpen] = useState(false);

    useEffect(() => {
        const fetchScans = async () => {
            try {
                const token = localStorage.getItem('token') || localStorage.getItem('accessToken');
                if (!token) return;
                const API_URL = import.meta.env.VITE_API_URL || "http://localhost:5000";
                const res = await axios.get(`${API_URL}/api/scan`, {
                    headers: { Authorization: `Bearer ${token}` }
                });
                setScans(res.data.data);
            } catch (err) {
                console.error("Error fetching recent scans", err);
            } finally {
                setLoadingScans(false);
            }
        };
        fetchScans();
    }, []);

    const totalScans = recentScans.length;
    const avgScore = totalScans > 0
        ? Math.round(recentScans.reduce((sum, scan) => sum + (scan.score || 0), 0) / totalScans)
        : 0;
    const uniqueSites = new Set(recentScans.map(s => s.domain)).size;
    const criticalSites = recentScans.filter(s => s.score !== null && s.score < 50).length;

    const lowestScoringSites = [...recentScans]
        .filter(s => s.score !== null)
        .sort((a, b) => a.score - b.score)
        .slice(0, 3);

    return (
        <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500 min-h-full">
            <DashboardNewScanModal isOpen={isNewScanOpen} onClose={() => setIsNewScanOpen(false)} />

            {/* Quick Stats */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <MetricCard title="Total Scans" value={totalScans.toString()} icon={Activity} />
                <MetricCard title="Avg. Score" value={`${avgScore}/100`} icon={ShieldCheck} />
                <MetricCard title="Monitored Sites" value={uniqueSites.toString()} icon={LinkIcon} />
                <MetricCard title="At-Risk Sites (Score < 50)" value={criticalSites.toString()} icon={AlertTriangle} alert={criticalSites > 0} />
            </div>

            {/* Main Content Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Recent Scans (Spans 2 columns) */}
                <div className="lg:col-span-2 space-y-4">
                    <div className="flex justify-between items-center min-h-[40px]">
                        <h3 className="text-xl font-bold text-text-dark flex items-center gap-2">
                            <Clock className="text-primary w-5 h-5" /> Recent Scans
                        </h3>
                        <Button variant="primary" size="sm" className="font-bold" startIcon={<Plus size={18} />} onClick={() => setIsNewScanOpen(true)}>
                            New Scan
                        </Button>
                    </div>
                    <div className="bg-white border border-slate-200 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)] rounded-3xl overflow-hidden">
                        {loadingScans ? (
                            <div className="p-8 text-center text-slate-500 font-medium">Loading recent scans...</div>
                        ) : recentScans.length === 0 ? (
                            <div className="p-8 text-center text-slate-500 font-medium h-full flex items-center justify-center ">No scans found. Start your first scan!</div>
                        ) : (
                            <div className="divide-y divide-slate-50">
                                {recentScans.map((scan, i) => {
                                    const date = new Date(scan.created_at).toLocaleDateString();
                                    return (
                                        <div key={i} className="p-5 flex flex-col sm:flex-row sm:items-center justify-between hover:bg-slate-50 transition-colors gap-4 cursor-pointer" onClick={() => navigate(`/dashboard/${scan.id}`)}>
                                            <div className="flex items-center gap-4">
                                                <div className={`w-12 h-12 rounded-xl flex items-center justify-center border font-bold text-lg
                                                    bg-primary/10 border-primary/20 text-primary`}>
                                                    {scan.score || '?'}
                                                </div>
                                                <div>
                                                    <div className="text-text-dark font-medium flex items-center gap-2">
                                                        {scan.domain || scan.url.replace(/^https?:\/\//, '')}
                                                        {scan.ssl_info?.valid ? (
                                                            <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.4)]" title="Valid SSL Certificate" />
                                                        ) : (
                                                            <div className="w-1.5 h-1.5 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.4)]" title={scan.ssl_info?.error || "Invalid SSL"} />
                                                        )}
                                                    </div>
                                                    <div className="text-xs text-slate-400">{date} • {scan.status.replace('_', ' ').toUpperCase()}</div>
                                                </div>
                                            </div>
                                            <Button variant="outline" size="sm" className="whitespace-nowrap px-4 py-2 rounded-lg text-xs" onClick={(e) => { e.stopPropagation(); navigate(`/dashboard/${scan.id}`); }}>
                                                View Report
                                            </Button>
                                        </div>
                                    );
                                })}
                            </div>
                        )}
                    </div>
                </div>

                {/* Top Priority Issues List */}
                <div className="space-y-4">
                    <div className="flex justify-between items-center min-h-[40px]">
                        <h3 className="text-xl font-bold text-text-dark flex items-center gap-2">
                            <Bug className="text-primary w-5 h-5" /> Sites Needing Attention
                        </h3>
                    </div>
                    <div className="bg-white border border-slate-200 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)] rounded-3xl p-5 space-y-4">
                        {lowestScoringSites.length > 0 ? (
                            lowestScoringSites.map((scan, i) => (
                                <div key={i} onClick={() => navigate(`/dashboard/${scan.id}`)} className="flex flex-col gap-2 p-4 rounded-xl bg-slate-50 border border-slate-200 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)] hover:border-primary/20 transition-colors cursor-pointer group">
                                    <div className="flex justify-between items-start">
                                        <span className="text-text-dark text-sm font-bold leading-tight group-hover:text-primary transition-colors">{scan.domain}</span>
                                    </div>
                                    <div className="text-xs text-slate-400 font-medium flex gap-2 justify-between">
                                        <span>Last audited on {new Date(scan.created_at).toLocaleDateString()}</span>
                                        <span className={`text-[10px] px-2 py-0.5 rounded uppercase font-black tracking-widest ${scan.score < 50 ? 'bg-red-100 text-red-600' : 'bg-orange-100 text-orange-600'}`}>Score: {scan.score}</span>
                                    </div>
                                </div>
                            ))
                        ) : (
                            <div className="p-4 text-center text-slate-500 font-medium text-sm">No critical sites found.</div>
                        )}
                        {lowestScoringSites.length > 0 && (
                            <Button variant="custom" size="none" rounded="" display="" fontWeight="" className="w-full text-xs text-primary hover:underline mt-2">
                                View all scans →
                            </Button>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}
