import { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation, Outlet, Link } from 'react-router-dom';
import axios from 'axios';
import { Button } from '../../components/ui/Button';
import DashboardNewScanModal from './components/DashboardNewScanModal';
import {
    LayoutDashboard,
    Users,
    Settings,
    CreditCard,
    Activity,
    LogOut,
    X,
    Globe,
    ChevronDown,
    Plus,
    Menu
} from 'lucide-react';

const SidebarItem = ({ icon: Icon, label, isActive, path }: any) => {
    const navigate = useNavigate();
    return (
        <Button
            variant="custom"
            size="none"
            fontWeight=""
            display=""
            rounded=""
            onClick={() => navigate(path)}
            className={`flex items-center gap-3 w-full text-left text-sm px-4 py-3 rounded-xl transition-all duration-300 ${isActive
                ? 'bg-primary text-white shadow-lg shadow-primary/20'
                : 'text-slate-500 hover:bg-slate-50 hover:text-text-dark'
                }`}
        >
            <Icon className={`w-5 h-5 ${isActive ? 'text-white' : ''}`} />
            <span className="font-medium">{label}</span>
        </Button>
    );
};

const ProjectSwitcher = () => {
    const location = useLocation();
    const navigate = useNavigate();
    const [scans, setScans] = useState<any[]>([]);
    const [isOpen, setIsOpen] = useState(false);
    const [isNewScanOpen, setIsNewScanOpen] = useState(false);
    const dropdownRef = useRef<HTMLDivElement>(null);

    // Determine current active project from URL (e.g. /dashboard/:id)
    const pathParts = location.pathname.split('/');
    const possibleId = pathParts.length > 2 ? pathParts[2] : '';

    // Find active project or default to first
    const activeProject = scans.find(s => s.id === possibleId) || scans[0];

    useEffect(() => {
        const fetchScans = async () => {
            try {
                const token = localStorage.getItem('token') || localStorage.getItem('accessToken');
                if (!token) return;
                const API_URL = import.meta.env.VITE_API_URL || "http://localhost:5000";
                const res = await axios.get(`${API_URL}/api/scan`, {
                    headers: { Authorization: `Bearer ${token}` }
                });
                setScans(res.data.data || []);
            } catch (err) {
                console.error("Error fetching projects for switcher", err);
            }
        };
        fetchScans();
    }, []);

    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
                setIsOpen(false);
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    if (scans.length === 0) {
        return (
            <div className="flex items-center gap-3 px-4 py-2 bg-primary/10 text-primary rounded-xl min-w-[200px] md:min-w-[240px] border border-primary/20 animate-pulse">
                <Globe className="w-5 h-5 opacity-50" />
                <span className="font-bold text-sm">Loading Projects...</span>
            </div>
        );
    }

    return (
        <div className="relative" ref={dropdownRef}>
            <button
                onClick={() => setIsOpen(!isOpen)}
                className="flex items-center gap-3 px-4 py-2 bg-primary/10 hover:bg-primary/20 text-primary rounded-xl transition-colors min-w-[200px] md:min-w-[240px] border border-primary/20 focus:outline-none"
            >
                <Globe className="w-5 h-5 text-primary shrink-0" />
                <span className="font-bold flex-1 text-left truncate text-sm">{activeProject?.domain || "Select Project"}</span>
                <ChevronDown className={`w-4 h-4 text-primary transition-transform duration-200 shrink-0 ${isOpen ? 'rotate-180' : ''}`} />
            </button>

            {isOpen && (
                <div className="absolute top-full left-0 mt-3 w-full md:w-[320px] bg-white rounded-2xl shadow-[0_20px_60px_-15px_rgba(0,0,0,0.15)] border border-slate-100 py-2 z-50 animate-in fade-in slide-in-from-top-2 duration-200">
                    <div className="max-h-[300px] overflow-y-auto custom-scrollbar">
                        {scans.map(scan => (
                            <button
                                key={scan.id}
                                onClick={() => {
                                    setIsOpen(false);
                                    // Navigate directly inside the dashboard
                                    navigate(`/dashboard/${scan.id}`);
                                }}
                                className="w-full flex items-start gap-3 px-5 py-3 hover:bg-slate-50 transition-colors text-left group border-b border-transparent hover:border-slate-100"
                            >
                                <Globe className="w-5 h-5 text-slate-400 group-hover:text-primary mt-0.5 shrink-0 transition-colors" />
                                <div className="flex flex-col min-w-0 flex-1">
                                    <div className="flex items-center justify-between">
                                        <span className="font-bold text-slate-800 text-sm truncate">{scan.domain}</span>
                                        {scan.is_paid && (
                                            <span className="text-[10px] uppercase tracking-wider font-bold bg-green-100 text-green-700 px-2 py-0.5 rounded-md shrink-0 ml-2">Pro</span>
                                        )}
                                    </div>
                                    <span className="text-xs text-slate-400 truncate mt-0.5">*.{scan.domain}/*</span>
                                </div>
                                {scan.id === activeProject?.id && (
                                    <div className="w-2 h-2 rounded-full bg-primary mt-2 shrink-0 shadow-[0_0_8px_rgba(var(--color-primary-rgb),0.5)]" />
                                )}
                            </button>
                        ))}
                    </div>
                    <div className="px-3 pt-3 pb-1 mt-1 border-t border-slate-50">
                        <button
                            onClick={() => { setIsOpen(false); setIsNewScanOpen(true); }}
                            className="w-full flex items-center justify-center gap-2 bg-primary text-white hover:bg-primary-hover hover:scale-[0.98] transition-all font-bold px-4 py-2.5 rounded-xl text-sm shadow-md shadow-primary/20"
                        >
                            <Plus className="w-4 h-4" />
                            Create Project
                        </button>
                    </div>
                </div>
            )}

            <DashboardNewScanModal
                isOpen={isNewScanOpen}
                onClose={() => setIsNewScanOpen(false)}
            />
        </div>
    );
};

const MasterDashboard = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const [isSidebarOpen, setSidebarOpen] = useState(false);
    const [userEmail, setUserEmail] = useState('User');

    useEffect(() => {
        try {
            const token = localStorage.getItem('token') || localStorage.getItem('accessToken');
            if (token) {
                const payload = JSON.parse(atob(token.split('.')[1]));
                if (payload && payload.email) {
                    setUserEmail(payload.email);
                }
            }
        } catch (e) {
            console.error('Failed to parse token', e);
        }
    }, []);

    const handleLogout = () => {
        localStorage.removeItem('token');
        localStorage.removeItem('accessToken');
        localStorage.removeItem('user');
        navigate('/login');
    };

    // Active state logic for overview: matches /dashboard and /dashboard/:scanId, 
    // but not /dashboard/team, /dashboard/settings, etc.
    const isOverviewActive = location.pathname === '/dashboard' ||
        (location.pathname.startsWith('/dashboard/') &&
            !['/dashboard/team', '/dashboard/settings', '/dashboard/monitoring', '/dashboard/billing'].includes(location.pathname));


    return (
        <div className="min-h-screen flex bg-slate-50 text-text-main font-sans overflow-hidden">
            {/* Sidebar Overlay for Mobile */}
            {isSidebarOpen && (
                <div 
                    className="fixed inset-0 bg-black/20 backdrop-blur-xs z-40 md:hidden" 
                    onClick={() => setSidebarOpen(false)}
                />
            )}

            {/* Sidebar */}
            <div className={`fixed inset-y-0 left-0 z-50 w-64 bg-white border-r border-slate-100 transform transition-transform duration-300 ease-in-out ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full'} md:relative md:translate-x-0 flex flex-col shadow-2xl md:shadow-none`}>
                <div className="h-20 px-6 flex items-center justify-between border-b border-slate-100">
                    {/* Logo matching Header */}
                    <Link
                        to="/"
                        onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
                        className="flex items-center gap-2.5 text-xl md:text-2xl font-bold tracking-tight text-text-dark no-underline group"
                    >
                        <div className="w-8 h-8 md:w-9 md:h-9 flex items-center justify-center bg-primary rounded-lg md:rounded-xl text-white shadow-lg shadow-primary/20 transition-transform group-hover:scale-105">
                            <svg className="w-5 h-5 md:w-6 md:h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                            </svg>
                        </div>
                        <span className="bg-gradient-to-r from-text-dark to-slate-700 bg-clip-text">RiskLayer</span>
                    </Link>
                    <button className="md:hidden text-slate-400 hover:text-text-dark flex-shrink-0 ml-2" onClick={() => setSidebarOpen(false)}>
                        <X className="w-5 h-5" />
                    </button>
                </div>

                <div className="px-4 py-2 mt-4 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    Workspace
                </div>
                <nav className="flex-1 px-3 space-y-1 mb-6">
                    <SidebarItem icon={LayoutDashboard} label="Dashboard Overview" isActive={isOverviewActive} path="/dashboard" />
                    <SidebarItem icon={Users} label="Team Members" isActive={location.pathname === '/dashboard/team'} path="/dashboard/team" />
                    <SidebarItem icon={Settings} label="Settings & API" isActive={location.pathname === '/dashboard/settings'} path="/dashboard/settings" />
                </nav>

                <div className="px-4 py-2 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    Billing & Usage
                </div>
                <nav className="px-3 pb-4 space-y-1 mb-auto">
                    <SidebarItem icon={Activity} label="Monitoring (Crons)" isActive={location.pathname === '/dashboard/monitoring'} path="/dashboard/monitoring" />
                    <SidebarItem icon={CreditCard} label="Billing & Plans" isActive={location.pathname === '/dashboard/billing'} path="/dashboard/billing" />
                </nav>

                <div className="p-4 mt-auto border-t border-slate-100">
                    <button 
                        onClick={handleLogout}
                        className="flex items-center gap-3 w-full text-left px-4 py-3 rounded-xl text-slate-400 hover:text-primary hover:bg-primary/5 transition-colors font-bold text-sm"
                    >
                        <LogOut className="w-5 h-5" />
                        <span>Sign Out</span>
                    </button>
                </div>
            </div>

            {/* Main Content */}
            <div className="flex-1 flex flex-col h-screen overflow-hidden relative">
                {/* Topbar */}
                <div className="h-16 md:h-20 border-b border-slate-100 bg-white flex items-center justify-between px-4 md:px-6 z-20 shrink-0 gap-3 md:gap-4">
                    <div className="flex items-center flex-1 gap-3">
                        <button 
                            className="md:hidden p-2 text-slate-500 hover:text-primary hover:bg-primary/5 rounded-lg transition-colors"
                            onClick={() => setSidebarOpen(true)}
                        >
                            <Menu className="w-6 h-6" />
                        </button>
                        <ProjectSwitcher />
                    </div>

                    <div className="flex items-center gap-4 shrink-0">
                        <div className="text-right hidden sm:block">
                            <div className="text-sm font-bold text-text-dark">{userEmail.split('@')[0]}</div>
                            <div className="text-xs text-slate-500 font-medium">{userEmail}</div>
                        </div>
                        <div className="w-10 h-10 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center text-primary font-bold uppercase shrink-0">
                            {userEmail.charAt(0)}
                        </div>
                    </div>
                </div>

                <div className="flex-1 overflow-y-auto p-6 md:p-10 z-10 custom-scrollbar flex flex-col">
                    <div className="max-w-[1400px] w-full mx-auto flex-1 flex flex-col min-h-full">
                        <Outlet />
                    </div>
                </div>
            </div>

            <style>{`
                .custom-scrollbar::-webkit-scrollbar {
                    width: 8px;
                }
                .custom-scrollbar::-webkit-scrollbar-track {
                    background: transparent;
                }
                .custom-scrollbar::-webkit-scrollbar-thumb {
                    background: rgba(255, 255, 255, 0.1);
                    border-radius: 4px;
                }
                .custom-scrollbar::-webkit-scrollbar-thumb:hover {
                    background: rgba(var(--primary), 0.5);
                }
            `}</style>
        </div>
    );
};

export default MasterDashboard;
