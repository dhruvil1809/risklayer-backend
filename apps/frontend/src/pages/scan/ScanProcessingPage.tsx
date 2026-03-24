import { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation, useParams } from 'react-router-dom';
import axios from 'axios';
import { Button } from '../../components/ui/Button';

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:5000";

const PIPELINE_STAGES = [
    { id: 'queued', label: 'Initializing Engine', desc: 'Waking up crawler nodes' },
    { id: 'crawling', label: 'Deep Crawl', desc: 'Extracting DOM & signals' },
    { id: 'rules_evaluation', label: 'Rules Engine', desc: 'Validating WCAG & compliance' },
    { id: 'preview_ready', label: 'AI Powered Report Generation', desc: 'Aggregating findings' },
];

interface LogEntry {
    id: string;
    timestamp: string;
    message: string;
    type: 'info' | 'success' | 'warning' | 'error';
}

function ScanProcessingPage() {
    const [status, setStatus] = useState<string>("queued");
    const [error, setError] = useState<string | null>(null);
    const [scanPages, setScanPages] = useState<{ url: string; status_code: number }[]>([]);
    const [findingCount, setFindingCount] = useState(0);
    const [logs, setLogs] = useState<LogEntry[]>([{
        id: 'start-0',
        timestamp: new Date().toLocaleTimeString(),
        message: 'System core initialized. Waiting for task payload...',
        type: 'info'
    }]);

    const navigate = useNavigate();
    const location = useLocation();
    const { id: paramId } = useParams();
    const logsEndRef = useRef<HTMLDivElement>(null);
    const searchParams = new URLSearchParams(location.search);
    const scanId = paramId || searchParams.get('id');

    // Auto-scroll logs
    useEffect(() => {
        logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [logs]);

    const addLog = (message: string, type: 'info' | 'success' | 'warning' | 'error' = 'info') => {
        setLogs(prev => [...prev, {
            id: Math.random().toString(36).substring(7),
            timestamp: new Date().toLocaleTimeString(),
            message,
            type
        }]);
    };

    useEffect(() => {
        if (!scanId) {
            setError("No Scan ID provided. Please start a scan from the home page.");
            return;
        }

        const token = localStorage.getItem("token");
        addLog(`Received scan task ID: ${scanId.substring(0,8)}...`, 'info');

        let seenPages = new Set<string>();
        let currentFindings = 0;
        let lastStatus = "queued";

        const pollInterval = setInterval(async () => {
            try {
                const res = await axios.get(`${API_URL}/api/scan/${scanId}/status`, {
                    headers: { Authorization: `Bearer ${token}` }
                });

                const data = res.data.data;
                const newStatus = data.status;

                if (newStatus !== lastStatus) {
                    addLog(`[SYSTEM] Pipeline stage advanced to: ${newStatus.replace('_', ' ').toUpperCase()}`, 'info');
                    lastStatus = newStatus;
                }

                setStatus(newStatus);
                
                // Diff pages
                if (data.scan_pages && Array.isArray(data.scan_pages)) {
                    setScanPages(data.scan_pages);
                    data.scan_pages.forEach((page: any) => {
                        if (!seenPages.has(page.url)) {
                            seenPages.add(page.url);
                            const pathname = new URL(page.url).pathname;
                            addLog(`[CRAWLER] Successfully extracted DOM from ${pathname || '/'} (${page.status_code || 200})`, 'success');
                        }
                    });
                }

                // Diff findings
                if (data._count && typeof data._count.findings === 'number') {
                    if (data._count.findings > currentFindings) {
                        const newFindings = data._count.findings - currentFindings;
                        currentFindings = data._count.findings;
                        setFindingCount(currentFindings);
                        addLog(`[RULES] Detected ${newFindings} new issues. Total findings: ${currentFindings}`, 'warning');
                    }
                }

                if (newStatus === "failed") {
                    setError("Scan failed. Our engine encountered an error while processing this URL.");
                    addLog('[ERROR] Fatal engine failure detected.', 'error');
                    clearInterval(pollInterval);
                    return;
                }

                if (newStatus === "preview_ready" || newStatus === "complete") {
                    addLog('[SYSTEM] All checks passed. Generating final comprehensive payload...', 'success');
                    clearInterval(pollInterval);
                    setTimeout(() => addLog('[SYSTEM] Handshake successful. Initializing report view...', 'info'), 1000);
                    setTimeout(() => {
                        if (location.pathname.includes('/dashboard')) {
                             window.location.reload(); // Reload to let dashboard load report
                        } else {
                             navigate(`/report/preview?id=${scanId}`);
                        }
                    }, 2500);
                }
            } catch (err: any) {
                console.error("Polling error:", err);
            }
        }, 1500);

        return () => clearInterval(pollInterval);
    }, [scanId, navigate]);

    const activeStageIndex = PIPELINE_STAGES.findIndex(s => s.id === status);
    const progressPercentage = activeStageIndex >= 0 ? Math.min(((activeStageIndex + 1) / PIPELINE_STAGES.length) * 100, 100) : 100;

    if (error) {
        return (
            <div className="min-h-screen pt-32 pb-16 flex items-center justify-center bg-bg-light text-text-main p-6 font-sans">
                <div className="bg-white border border-red-100 rounded-[32px] p-10 max-w-md w-full shadow-2xl shadow-red-500/10 text-center relative z-10">
                    <div className="w-16 h-16 bg-red-50 border border-red-100 rounded-2xl flex items-center justify-center mx-auto mb-6 text-red-500 shadow-sm">
                        <span className="text-3xl font-black">!</span>
                    </div>
                    <h2 className="text-2xl font-black mb-4 text-text-dark tracking-tight">Operation Aborted</h2>
                    <p className="text-slate-500 font-medium mb-8">{error}</p>
                    <Button variant="primary" text="Return to Base" onClick={() => navigate('/')} className="w-full bg-red-500 hover:bg-red-600 border-none text-white rounded-xl py-3" />
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen pt-32 pb-16 bg-bg-light text-text-main font-sans px-4 md:px-8 flex flex-col relative overflow-hidden">
            {/* Background Effects */}
            <div className="bg-grid-effect opacity-50 absolute inset-0 pointer-events-none z-0"></div>

            <div className="max-w-7xl mx-auto w-full flex-1 flex flex-col z-10 relative">
                {/* Header */}
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h1 className="text-2xl md:text-3xl font-black text-text-dark tracking-tighter flex items-center gap-3">
                            <span className="w-3 h-3 rounded-full bg-primary animate-pulse"></span>
                            Scanner Engine
                        </h1>
                        <p className="text-slate-500 text-xs mt-1 uppercase tracking-widest font-mono font-semibold">Session ID: {scanId}</p>
                    </div>
                </div>

                {/* Main Content Area */}
                <div className="w-full grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
                    
                    {/* Left Panel: Pipeline Visualizer (Dictates grid row height) */}
                    <div className="col-span-1 lg:col-span-4 flex flex-col gap-6 h-full">
                        {/* Progress Card */}
                        <div className="bg-white border border-slate-200 rounded-[32px] p-6 lg:p-8 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)] shrink-0">
                            <div className="flex justify-between items-end mb-6">
                                <h3 className="text-sm font-bold text-slate-800 uppercase tracking-widest">Overall Progress</h3>
                                <span className="text-3xl font-black text-primary">{Math.round(progressPercentage)}%</span>
                            </div>
                            <div className="h-2 w-full bg-slate-100 rounded-full overflow-hidden mb-10 shadow-inner">
                                <div 
                                    className="h-full bg-primary transition-all duration-1000 ease-out rounded-full relative"
                                    style={{ width: `${progressPercentage}%` }}
                                >
                                    <div className="absolute top-0 right-0 bottom-0 left-0 bg-[linear-gradient(90deg,transparent,rgba(255,255,255,0.4),transparent)] animate-[shimmer_2s_infinite]"></div>
                                </div>
                            </div>

                            {/* Stages List */}
                            <div className="space-y-6">
                                {PIPELINE_STAGES.map((stage, idx) => {
                                    const isDone = activeStageIndex > idx || activeStageIndex === PIPELINE_STAGES.length - 1;
                                    const isActive = activeStageIndex === idx;
                                    const isPending = activeStageIndex < idx;

                                    return (
                                        <div key={stage.id} className={`flex items-start gap-4 transition-all duration-500 ${isPending ? 'opacity-40' : 'opacity-100'}`}>
                                            <div className="mt-1 shrink-0 relative">
                                                {isDone ? (
                                                    <div className="w-8 h-8 rounded-full bg-green-100 text-green-600 flex items-center justify-center border border-green-200 font-bold">✓</div>
                                                ) : isActive ? (
                                                    <div className="w-8 h-8 rounded-full flex items-center justify-center relative">
                                                        <div className="absolute inset-0 border-[3px] border-primary border-t-transparent rounded-full animate-spin"></div>
                                                        <div className="w-2.5 h-2.5 bg-primary rounded-full animate-pulse"></div>
                                                    </div>
                                                ) : (
                                                    <div className="w-8 h-8 rounded-full bg-slate-50 border border-slate-200 text-slate-400 flex items-center justify-center text-xs font-bold">{idx + 1}</div>
                                                )}
                                            </div>
                                            <div>
                                                <h4 className={`font-bold ${isActive ? 'text-text-dark' : 'text-slate-600'}`}>{stage.label}</h4>
                                                <p className="text-xs text-slate-500 mt-1 font-medium">{stage.desc}</p>
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>

                        {/* Stats Card */}
                        <div className="bg-white border border-slate-200 rounded-[32px] p-6 lg:p-8 flex-1 flex flex-col justify-center shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)] min-h-[140px]">
                            <div className="grid grid-cols-2 gap-4 h-full">
                                <div className="bg-slate-50 p-5 rounded-2xl border border-slate-200 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)] text-center flex flex-col justify-center">
                                    <p className="text-slate-500 text-[10px] font-bold uppercase tracking-widest mb-2">Pages Extracted</p>
                                    <p className="text-4xl font-black text-slate-800 leading-none">{scanPages.length}</p>
                                </div>
                                <div className="bg-orange-50/50 p-5 rounded-2xl border border-orange-200 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)] text-center relative overflow-hidden flex flex-col justify-center">
                                    {findingCount > 0 && <div className="absolute inset-0 bg-orange-100/20 animate-pulse"></div>}
                                    <p className="text-orange-600/70 text-[10px] font-bold uppercase tracking-widest mb-2 relative z-10">Issues Found</p>
                                    <p className="text-4xl font-black text-orange-600 relative z-10 leading-none">{findingCount}</p>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Right Panel: Live Terminal Engine Logs - Exact match left side height on desktop */}
                    <div className="col-span-1 lg:col-span-8 relative mt-6 lg:mt-0 h-[500px] lg:h-auto min-h-0">
                        <div className="static lg:absolute lg:inset-0 w-full h-full bg-white border border-slate-200 rounded-[32px] overflow-hidden flex flex-col shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)]">
                            {/* Terminal Header */}
                            <div className="bg-slate-50 px-6 py-4 flex items-center justify-between border-b border-slate-200 shrink-0">
                                <div className="flex items-center gap-2">
                                    <div className="flex gap-1.5">
                                        <div className="w-3 h-3 rounded-full bg-red-400"></div>
                                        <div className="w-3 h-3 rounded-full bg-amber-400"></div>
                                        <div className="w-3 h-3 rounded-full bg-green-400"></div>
                                    </div>
                                    <span className="text-xs font-mono font-bold text-slate-500 ml-4 uppercase tracking-widest">Live Execution Stream</span>
                                </div>
                                <div className="flex items-center gap-2">
                                     <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
                                     <span className="text-[10px] font-bold text-green-600 uppercase tracking-widest">Online</span>
                                </div>
                            </div>

                            {/* Logs Body */}
                            <div className="flex-1 overflow-y-auto p-6 lg:p-8 font-mono text-sm sm:text-[13px] leading-relaxed relative bg-[#fafafa]">
                                {logs.map((log) => (
                                    <div key={log.id} className="mb-3 flex gap-4 break-all items-start">
                                        <span className="text-slate-400 shrink-0 font-medium whitespace-nowrap">[{log.timestamp}]</span>
                                        <span className={`flex-1 font-medium ${
                                            log.type === 'error' ? 'text-red-500' : 
                                            log.type === 'success' ? 'text-green-600' :
                                            log.type === 'warning' ? 'text-orange-500' :
                                            'text-slate-700'
                                        }`}>
                                            <span className="opacity-40 mr-2 text-slate-400 font-bold">&gt;</span>
                                            {log.message}
                                        </span>
                                    </div>
                                ))}
                                <div ref={logsEndRef} />
                            </div>
                        </div>
                    </div>

                </div>
            </div>
            
            {/* Custom Tailwind animation definitions */}
            <style dangerouslySetInnerHTML={{__html: `
                @keyframes shimmer {
                    100% { transform: translateX(100%); }
                }
            `}} />
        </div>
    );
}

export default ScanProcessingPage;