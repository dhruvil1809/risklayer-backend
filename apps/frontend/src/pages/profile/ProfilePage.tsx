import { useNavigate } from 'react-router-dom';
import { LogOut, User, Activity, Settings, ShieldCheck, CreditCard } from 'lucide-react';
import { Button } from '../../components/ui/Button';

export default function ProfilePage() {
    const navigate = useNavigate();

    const handleLogout = () => {
        localStorage.removeItem('token');
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        navigate('/login');
    };

    return (
        <div className="min-h-[80vh] flex flex-col bg-bg-dark text-text-main relative overflow-hidden font-sans pt-24 pb-16 px-[5%]">
            <div className="bg-grid-effect opacity-50"></div>

            <div className="max-w-[1000px] w-full mx-auto relative z-10">
                <div className="mb-10">
                    <h1 className="text-4xl font-extrabold text-white mb-2">Dashboard</h1>
                    <p className="text-text-muted text-lg">Welcome back. Manage your account, view scans, and update settings.</p>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                    {/* Left Sidebar */}
                    <div className="lg:col-span-1 flex flex-col gap-4">
                        <div className="bg-[#0f1423]/60 backdrop-blur-2xl border border-glass-border rounded-3xl p-6 shadow-[0_25px_50px_-12px_rgba(0,0,0,0.5),inset_0_0_0_1px_rgba(255,255,255,0.05)]">
                            <div className="flex items-center gap-4 mb-8">
                                <div className="w-16 h-16 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
                                    <User className="w-8 h-8" />
                                </div>
                                <div>
                                    <h3 className="text-white font-bold text-xl">User</h3>
                                    <span className="text-primary text-sm bg-primary/10 px-2 py-1 rounded-md mt-1 inline-block">Pro Plan</span>
                                </div>
                            </div>

                            <hr className="border-glass-border mb-4" />

                            <nav className="flex flex-col gap-2">
                                <Button variant="custom" size="none" display="" rounded="" fontWeight="" className="flex items-center gap-3 w-full text-left px-4 py-3 rounded-xl bg-white/5 text-white font-medium border border-white/5 transition-colors">
                                    <User className="w-5 h-5 text-primary" />
                                    Account Details
                                </Button>
                                <Button variant="custom" size="none" display="" rounded="" fontWeight="" className="flex items-center gap-3 w-full text-left px-4 py-3 rounded-xl text-text-muted hover:bg-white/5 hover:text-white transition-colors">
                                    <Activity className="w-5 h-5" />
                                    Recent Scans
                                </Button>
                                <Button variant="custom" size="none" display="" rounded="" fontWeight="" className="flex items-center gap-3 w-full text-left px-4 py-3 rounded-xl text-text-muted hover:bg-white/5 hover:text-white transition-colors">
                                    <CreditCard className="w-5 h-5" />
                                    Billing
                                </Button>
                                <Button variant="custom" size="none" display="" rounded="" fontWeight="" className="flex items-center gap-3 w-full text-left px-4 py-3 rounded-xl text-text-muted hover:bg-white/5 hover:text-white transition-colors">
                                    <Settings className="w-5 h-5" />
                                    Settings
                                </Button>
                            </nav>

                            <hr className="border-glass-border my-4" />

                            <Button variant="custom" size="none" display="" rounded="" fontWeight=""
                                onClick={handleLogout}
                                className="flex items-center gap-3 w-full text-left px-4 py-3 rounded-xl text-danger hover:bg-danger/10 transition-colors"
                            >
                                <LogOut className="w-5 h-5" />
                                Sign Out
                            </Button>
                        </div>
                    </div>

                    {/* Main Content Area */}
                    <div className="lg:col-span-2 flex flex-col gap-6">
                        {/* Summary Cards */}
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div className="bg-[#0f1423]/60 backdrop-blur-2xl border border-glass-border rounded-3xl p-6 relative overflow-hidden group">
                                <div className="absolute inset-0 bg-primary/5 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                                <ShieldCheck className="w-8 h-8 text-primary mb-4" />
                                <h4 className="text-white font-semibold text-lg mb-1">Total Scans</h4>
                                <p className="text-3xl font-bold text-white">12</p>
                            </div>
                            <div className="bg-[#0f1423]/60 backdrop-blur-2xl border border-glass-border rounded-3xl p-6 relative overflow-hidden group">
                                <div className="absolute inset-0 bg-primary/5 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                                <Activity className="w-8 h-8 text-primary mb-4" />
                                <h4 className="text-white font-semibold text-lg mb-1">Active Projects</h4>
                                <p className="text-3xl font-bold text-white">3</p>
                            </div>
                        </div>

                        {/* Recent Activity */}
                        <div className="bg-[#0f1423]/60 backdrop-blur-2xl border border-glass-border rounded-3xl p-6">
                            <h3 className="text-xl font-bold text-white mb-6">Recent Scans</h3>

                            <div className="flex flex-col gap-4">
                                {[1, 2, 3].map((i) => (
                                    <div key={i} className="flex flex-col sm:flex-row sm:items-center justify-between p-4 rounded-2xl border border-white/5 bg-white/[0.02] hover:bg-white/[0.04] transition-colors">
                                        <div className="flex flex-col mb-3 sm:mb-0">
                                            <span className="text-white font-medium">example-site-{i}.com</span>
                                            <span className="text-text-muted text-sm mt-1">Scanned 2 days ago</span>
                                        </div>
                                        <Button
                                            variant="secondary"
                                            size="sm"
                                            text="View Report"
                                            className="w-full sm:w-auto text-xs py-2"
                                        />
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
