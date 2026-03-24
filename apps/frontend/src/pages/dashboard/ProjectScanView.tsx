import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import ScanProcessingPage from '../scan/ScanProcessingPage';
import ReportPreviewPage from '../report/ReportPreviewPage';
import { Loader2, AlertCircle } from 'lucide-react';
import { Button } from '../../components/ui/Button';

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:5000";

export default function ProjectScanView() {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const [status, setStatus] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [reportReady, setReportReady] = useState(false);

    useEffect(() => {
        if (!id) return;
        
        let isMounted = true;
        const fetchStatus = async () => {
            try {
                const token = localStorage.getItem("token") || localStorage.getItem("accessToken");
                const res = await axios.get(`${API_URL}/api/scan/${id}/status`, {
                    headers: { Authorization: `Bearer ${token}` }
                });
                
                if (isMounted) {
                    setStatus(res.data.data.status);
                    setLoading(false);
                }
            } catch (err: any) {
                console.error("Error fetching scan status:", err);
                if (isMounted) {
                    setError(err.response?.data?.message || "Failed to load scan");
                    setLoading(false);
                }
            }
        };

        fetchStatus();
    }, [id]);

    const isComplete = status === 'preview_ready' || status === 'complete';
    const showMainLoader = loading || (isComplete && !reportReady);

    return (
        <div className="w-[calc(100%+48px)] md:w-[calc(100%+80px)] min-h-[calc(100%+48px)] md:min-h-[calc(100%+80px)] -m-6 md:-m-10 animate-in fade-in duration-500 relative flex flex-col bg-slate-50/50">
            {showMainLoader && !error && (
                <div className="absolute inset-0 flex flex-col items-center justify-center p-12 text-slate-500 z-100 bg-slate-50/50 backdrop-blur-sm">
                    <Loader2 className="w-12 h-12 animate-spin text-primary mb-6" />
                    <p className="font-black text-xl text-text-dark animate-pulse tracking-tight">Initializing Workspace</p>
                    <p className="text-sm text-slate-400 mt-2 font-medium">Checking project status and loading crawler results...</p>
                </div>
            )}

            {error ? (
                <div className="flex-1 flex items-center justify-center p-6">
                    <div className="bg-white border border-red-100 rounded-[32px] p-12 max-w-md w-full shadow-2xl shadow-red-500/5 text-center">
                        <div className="w-20 h-20 bg-red-50 rounded-2xl flex items-center justify-center mx-auto mb-8 text-red-500">
                            <AlertCircle className="w-10 h-10" />
                        </div>
                        <h2 className="text-2xl font-black mb-4 text-text-dark tracking-tight">Access Restricted</h2>
                        <p className="text-slate-500 font-medium mb-10 text-sm leading-relaxed">{error}</p>
                        <Button variant="outline" text="Return to Dashboard" onClick={() => navigate('/dashboard')} className="w-full rounded-2xl py-4 border-slate-200" />
                    </div>
                </div>
            ) : isComplete ? (
                // Wrapper to hide the main standalone header from ReportPreviewPage
                <div className={`embedded-report-view relative flex-1 ${!reportReady ? 'invisible h-0' : ''}`}>
                    <style>{`
                        .embedded-report-view header { display: none !important; }
                        .embedded-report-view main { padding-top: 1.5rem !important; padding-bottom: 2.5rem !important; padding-left: 1.5rem !important; padding-right: 1.5rem !important; }
                        @media (min-width: 768px) {
                            .embedded-report-view main { padding-top: 2.5rem !important; padding-bottom: 2.5rem !important; padding-left: 2.5rem !important; padding-right: 2.5rem !important; }
                        }
                    `}</style>
                    <ReportPreviewPage hideLoader={true} onReady={() => setReportReady(true)} />
                </div>
            ) : !loading && (
                // Wrapper to adjust the padding and remove full-screen bg from ScanProcessingPage
                <div className="embedded-scan-view relative flex-1 min-h-[500px]">
                     <style>{`
                        .embedded-scan-view > div { 
                            min-height: 100% !important; 
                            background: transparent !important;
                            padding-top: 2rem !important;
                        }
                    `}</style>
                    <ScanProcessingPage />
                </div>
            )}
        </div>
    );
}
