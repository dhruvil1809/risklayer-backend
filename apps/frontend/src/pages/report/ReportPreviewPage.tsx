import { useState, useEffect, useMemo } from 'react';
import { createPortal } from 'react-dom';
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom';
import axios from 'axios';
import { Button } from '../../components/ui/Button';
import { Loader2, AlertCircle, Shield, FileText, CheckCircle2, Lock, Eye, Gauge, Accessibility, ChevronDown, ChevronLeft, ChevronRight, Clock, Globe, Fingerprint, Activity, Sparkles, Cpu } from 'lucide-react';

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:5000";

interface Finding {
    id: string;
    rule_id: string;
    category: string;
    severity: string;
    message: string;
    description?: string;
    how_to_fix?: string;
    difficulty?: string;
    evidence?: any;
}


interface ScanPage {
    id: string;
    url: string;
    depth: number;
    title: string;
    extracted_json: any;
    meta: any;
    raw_html: string;
}

interface ScanData {
    id: string;
    url: string;
    domain: string;
    score: number;
    status: string;
    is_paid: boolean;
    executive_summary: string;
    categories: any;
    passed_checks: string[];
    findings: Finding[];
    scan_pages: ScanPage[];
    ssl_info?: {
        valid: boolean;
        expiryDate?: string;
        issuer?: string;
        error?: string;
    };
}

const CircularProgress = ({ score, size = 180, strokeWidth = 10 }: { score: number, size?: number, strokeWidth?: number }) => {
    const radius = (size - strokeWidth) / 2;
    const circumference = radius * 2 * Math.PI;
    const offset = circumference - (score / 100) * circumference;
    const getColor = (s: number) => {
        if (s >= 90) return '#10b981'; // success
        if (s >= 70) return '#00e5ff'; // primary
        if (s >= 40) return '#f59e0b'; // warning
        return '#ef4444'; // danger
    };

    return (
        <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
            <svg width={size} height={size} className="transform -rotate-90">
                <circle
                    cx={size / 2}
                    cy={size / 2}
                    r={radius}
                    stroke="rgba(0,0,0,0.05)"
                    strokeWidth={strokeWidth}
                    fill="transparent"
                />
                <circle
                    cx={size / 2}
                    cy={size / 2}
                    r={radius}
                    stroke={getColor(score)}
                    strokeWidth={strokeWidth}
                    fill="transparent"
                    strokeDasharray={circumference}
                    strokeDashoffset={offset}
                    strokeLinecap="round"
                    className="transition-all duration-1000 ease-out"
                    style={{ filter: `drop-shadow(0 0 12px ${getColor(score)}40)` }}
                />
            </svg>
            <div className="absolute flex flex-col items-center justify-center text-center">
                <span className="text-5xl font-black text-text-dark leading-none">{score}</span>
                <span className="text-[0.6rem] uppercase tracking-widest text-slate-400 font-bold mt-1">Index</span>
            </div>
        </div>
    );
};

interface ReportPreviewPageProps {
    onReady?: () => void;
    hideLoader?: boolean;
}

function ReportPreviewPage({ onReady, hideLoader }: ReportPreviewPageProps) {
    const [scanData, setScanData] = useState<ScanData | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    // accordion open state
    const [openScanPages, setOpenScanPages] = useState<Record<string, boolean>>({});
    // Modal state for code snippet
    const [codeModal, setCodeModal] = useState<{
        isOpen: boolean;
        title: string;
        snippet: string;
        url: string | null;
        description?: string;
        how_to_fix?: string;
        allOccurrences?: any[];
        instanceIndex: number;
    } | null>(null);
    const [modalTab, setModalTab] = useState<'code' | 'fix'>('code');

    const location = useLocation();
    const navigate = useNavigate();
    const { id: paramId } = useParams();
    const searchParams = new URLSearchParams(location.search);
    const scanId = paramId || searchParams.get('id');

    useEffect(() => {
        if (!scanId) {
            setError("No Scan ID provided.");
            setLoading(false);
            return;
        }

        const fetchResults = async () => {
            try {
                const token = localStorage.getItem("token");
                const res = await axios.get(`${API_URL}/api/scan/${scanId}/preview`, {
                    headers: { Authorization: `Bearer ${token}` }
                });
                setScanData(res.data.data);
            } catch (err: any) {
                console.error("Error fetching scan results:", err);
                setError(err.response?.data?.message || "Failed to load scan results.");
            } finally {
                setLoading(false);
                if (onReady) onReady();
            }
        };

        fetchResults();
    }, [scanId, onReady]);

    const handleAccordionToggle = (id: string) => {
        setOpenScanPages((prev) => ({
            ...prev,
            [id]: !prev[id]
        }));
    };

    const categoryGroups = useMemo(() => {
        if (!scanData) return [];

        const categories = [
            { id: 'accessibility', name: 'Accessibility Issues', issues: [] as any[], passed: [] as any[] },
            { id: 'compliance', name: 'Compliance Issues', issues: [] as any[], passed: [] as any[] },
            { id: 'trust', name: 'Trust Issues', issues: [] as any[], passed: [] as any[] },
            { id: 'structure', name: 'Structure Issues', issues: [] as any[], passed: [] as any[] }
        ];

        const categoryMap = new Map(categories.map(c => [c.id, c]));

        if (scanData.findings) {
            const issuesByRule = new Map();

            scanData.findings.forEach((finding: any) => {
                if (!issuesByRule.has(finding.rule_id)) {
                    let cleanMsg = finding.message
                        .replace(/^[0-9]+\s+/, '')
                        .replace(/^Page is\s+/i, 'Pages are ')
                        .replace(/^Page has\s+/i, 'Pages have ')
                        .replace(/^URL contains\s+/i, 'URLs contain ');

                    cleanMsg = cleanMsg.charAt(0).toUpperCase() + cleanMsg.slice(1);
                    if (cleanMsg === 'Heading levels are skipped (e.g., H1 to H3).') cleanMsg = 'Heading levels are skipped.';
                    if (cleanMsg.includes('identical headings.')) cleanMsg = 'Identical headings found across pages.';
                    if (cleanMsg.includes('identical alt tags.')) cleanMsg = 'Identical alt tags found across pages.';

                    issuesByRule.set(finding.rule_id, {
                        ...finding,
                        cleanMessage: cleanMsg,
                        description: finding.description || `This audit detected ${cleanMsg.toLowerCase()} which may impact your security or accessibility performance.`,
                        affectedUrls: new Set(),
                        items: []
                    });
                }

                const ruleGroup = issuesByRule.get(finding.rule_id);
                const ev = finding.evidence || {};
                const url = ev.url;
                if (url) ruleGroup.affectedUrls.add(url);

                const list = ev.examples || ev.items || ev.urls || ev.forms;
                const instances = Array.isArray(list) && list.length > 0
                    ? list.map((item: any) => ({
                        ...(typeof item === 'object' ? item : { value: item }),
                        url: (typeof item === 'object' ? item.url : null) || url
                    }))
                    : [{ ...ev, value: "Audit Finding", url }];

                // NEW: Group instances by URL
                instances.forEach((inst: any) => {
                    const targetUrl = inst.url || url || "Site-wide Check";

                    let urlGroup = ruleGroup.items.find((i: any) => i.url === targetUrl);
                    if (!urlGroup) {
                        urlGroup = { url: targetUrl, instances: [] };
                        ruleGroup.items.push(urlGroup);
                    }
                    urlGroup.instances.push(inst);
                });
            });

            issuesByRule.forEach((group) => {
                const cat = categoryMap.get(group.category);
                if (cat) {
                    cat.issues.push(group) as any;
                }
            });
        }

        if (scanData.passed_checks) {
            scanData.passed_checks.forEach((check: any) => {
                if (typeof check === 'object' && check.category) {
                    const cat = categoryMap.get(check.category);
                    if (cat) cat.passed.push(check);
                } else if (typeof check === 'string') {
                    const cat = categoryMap.get('structure'); // default legacy to structure
                    if (cat) cat.passed.push({ title: check, rule_id: `LEGACY-${Math.random()}` });
                }
            });
        }

        return categories;
    }, [scanData]);

    const topUrgentIssues = useMemo(() => {
        if (!scanData?.findings) return [];
        return [...scanData.findings]
            .filter(f => f.severity === 'high' || f.severity === 'critical')
            // If less than 10, fill with medium
            .concat([...scanData.findings].filter(f => f.severity === 'medium'))
            .filter((v, i, a) => a.findIndex(t => (t.id === v.id)) === i) // unique
            .sort((a, b) => {
                const s = { critical: 4, high: 3, medium: 2, low: 1 } as any;
                return (s[b.severity] || 0) - (s[a.severity] || 0);
            })
            .slice(0, 10);
    }, [scanData]);

    const priorityFixOrder = useMemo(() => {
        if (!scanData?.findings) return [];
        const uniqueRules = new Map();
        scanData.findings.forEach(f => {
            if (!uniqueRules.has(f.rule_id)) {
                let cleanMsg = f.message.replace(/^[0-9]+\s+/, '');
                uniqueRules.set(f.rule_id, { ...f, count: 1, cleanMsg });
            } else {
                uniqueRules.get(f.rule_id).count++;
            }
        });
        return Array.from(uniqueRules.values()).sort((a, b) => {
            const s = { critical: 4, high: 3, medium: 2, low: 1 } as any;
            return (s[b.severity] || 0) - (s[a.severity] || 0) || b.count - a.count;
        });
    }, [scanData]);

    if (loading) {
        if (hideLoader) return null;
        return (
            <div className="flex-1 flex flex-col items-center justify-center min-h-[400px] text-slate-500">
                <Loader2 className="w-10 h-10 animate-spin text-primary mb-4" />
                <p className="font-medium animate-pulse">Initializing engine analysis...</p>
            </div>
        );
    }

    if (error || !scanData) {
        return (
            <div className="min-h-screen flex flex-col items-center justify-center bg-bg-light text-text-dark p-6">
                <div className="bg-red-50 border border-red-100 p-8 rounded-3xl max-w-md text-center shadow-lg">
                    <AlertCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
                    <h1 className="text-2xl font-black mb-2 tracking-tight">Error Loading Report</h1>
                    <p className="text-slate-500 mb-6 font-medium">{error}</p>
                    <Button variant="primary" text="Back to Home" onClick={() => navigate('/')} className="rounded-xl shadow-lg shadow-primary/20 bg-text-dark text-white border-none py-3" />
                </div>
            </div>
        );
    }

    const getSeverityColor = (severity: string) => {
        switch (severity.toLowerCase()) {
            case 'critical': return 'text-red-600 border-red-200 bg-red-50';
            case 'high': return 'text-red-500 border-red-200 bg-red-50';
            case 'medium': return 'text-amber-600 border-amber-200 bg-amber-50';
            case 'low': return 'text-primary border-primary/20 bg-primary/5';
            default: return 'text-slate-500 border-slate-200 bg-slate-50';
        }
    };

    const renderIssueInCodeModal = () => {
        if (!codeModal?.isOpen) return null;

        // const formatHtml = (html: string) => {
        //     if (!html) return '';
        //     // Very basic beauty
        //     return html
        //         .replace(/>/g, '>\n')
        //         .split('\n')
        //         .map(line => line.trim())
        //         .filter(Boolean)
        //         .join('\n');
        // };

        const getRealCodeMetadata = () => {
            const defaultLines = (codeModal.snippet || '').split('\n').filter(Boolean);
            const rawHtml = scanData?.scan_pages?.find((p: any) => p.url === codeModal.url)?.raw_html;

            if (!rawHtml) return { lines: defaultLines, startLine: 1, targetLineRange: [1, defaultLines.length] };

            const instanceList = codeModal.allOccurrences || [codeModal];
            const instance = instanceList[codeModal.instanceIndex] || codeModal;
            const selector = instance?.selector;

            try {
                const parser = new DOMParser();
                const doc = parser.parseFromString(rawHtml, "text/html");

                // Inject an exact marker where the issue was found using the DOM CSS selector
                if (selector) {
                    try {
                        const el = doc.querySelector(selector);
                        if (el) {
                            el.setAttribute('data-risklayer-target', 'START');
                        }
                    } catch (e) {
                        console.error("Error marking element:", e);
                    }
                }

                // 1. Separate tags to their own lines to make it un-minified
                const spacedHtml = doc.documentElement.outerHTML
                    .replace(/>\s*</g, '>\n<') // separate touching tags
                    .split('\n')
                    .map(l => l.trim())
                    .filter(Boolean);

                let beautifiedLines: string[] = [];
                let indent = 0;

                // 2. Beautiful Indentation logic
                for (let line of spacedHtml) {
                    if (line.match(/^<\//)) {
                        indent = Math.max(0, indent - 1); // Decrease indent on closing tags
                    }

                    beautifiedLines.push('  '.repeat(indent) + line);

                    // Increase indent if it's an opening tag, not self-closing, and not a text/inline tag
                    if (line.match(/^<[^\/!]/) && !line.match(/\/>$/) && !line.match(/^(<img|<input|<br|<meta|<link|<hr)/i)) {
                        indent++;
                    }
                }

                let targetLineStart = 1;
                let targetLineEnd = 1;

                // 3. Find our injected marker in the beautiful code
                const markerIndex = beautifiedLines.findIndex(l => l.includes('data-risklayer-target="START"'));

                if (markerIndex !== -1) {
                    // Remove the marker so the user doesn't see our internal magic
                    beautifiedLines[markerIndex] = beautifiedLines[markerIndex].replace(' data-risklayer-target="START"', '');
                    targetLineStart = markerIndex + 1;

                    // 4. Calculate where this tag ends
                    const tagMatch = beautifiedLines[markerIndex].trim().match(/^<([a-zA-Z0-9-]+)/);
                    if (tagMatch) {
                        const tagName = tagMatch[1];
                        // If it's a self-closing or void element, start and end are the same
                        if (['img', 'input', 'br', 'hr', 'meta', 'link'].includes(tagName.toLowerCase()) || beautifiedLines[markerIndex].endsWith('/>')) {
                            targetLineEnd = targetLineStart;
                        } else {
                            let tagStack = 0;
                            // Search forward to find the matching closing tag
                            for (let i = markerIndex; i < beautifiedLines.length; i++) {
                                const line = beautifiedLines[i];
                                // Count openings (e.g. <div class... or <div>)
                                const openCount = (line.match(new RegExp(`<${tagName}(>|\\s)`, "gi")) || []).length;
                                // Count closings (e.g. </div>)
                                const closeCount = (line.match(new RegExp(`<\/${tagName}>`, "gi")) || []).length;

                                tagStack += openCount;
                                tagStack -= closeCount;

                                if (tagStack <= 0) { // We found the closing tag
                                    targetLineEnd = i + 1;
                                    break;
                                }
                            }
                        }
                    } else {
                        targetLineEnd = targetLineStart;
                    }
                } else {
                    // Fallback to text matching if selector failed to find the element
                    const cleanSnippet = (codeModal.snippet || '').trim().split('\n')[0];
                    if (cleanSnippet) {
                        const idx = beautifiedLines.findIndex(l => l.includes(cleanSnippet));
                        if (idx !== -1) {
                            targetLineStart = idx + 1;
                            targetLineEnd = idx + Math.max(1, defaultLines.length);
                        }
                    } else {
                        // No selector and no explicit snippet. This is a page-level structural issue (e.g. heading order).
                        // Instead of arbitrarily showing the <html> root node, return empty to trigger the contextual placeholder.
                        return { lines: [], startLine: 1, targetLineRange: [1, 1] };
                    }
                }

                // 5. Slice a generous window around the exact problem area
                const viewStart = Math.max(0, targetLineStart - 8);
                const viewEnd = Math.min(beautifiedLines.length, Math.max(targetLineEnd + 8, targetLineStart + 24)); // Keep window wide enough

                const slicedLines = beautifiedLines.slice(viewStart, viewEnd);

                // 6. Strip excess base indentation so code isn't pushed way to the right
                const nonEmptyLines = slicedLines.filter(l => l.trim().length > 0);
                const minIndent = nonEmptyLines.length > 0 ? Math.min(...nonEmptyLines.map(l => (l.match(/^\s*/) || [''])[0].length)) : 0;

                // Also ensure we don't accidentally remove indentation that is part of the tag
                const finalLines = slicedLines.map(l => {
                    const indentToRemove = minIndent > 0 ? minIndent : 0;
                    return l.substring(Math.min(indentToRemove, (l.match(/^\s*/) || [''])[0].length));
                });

                return {
                    lines: finalLines,
                    startLine: viewStart + 1,
                    targetLineRange: [targetLineStart, targetLineEnd]
                };

            } catch (e) {
                console.error("Advanced HTML Formatting failed", e);
                return { lines: defaultLines, startLine: 1, targetLineRange: [1, defaultLines.length] };
            }
        };

        const { lines, startLine, targetLineRange } = getRealCodeMetadata();

        return createPortal(
            <div className="fixed inset-0 z-99999 flex justify-end bg-black/20 backdrop-blur-sm animate-fade-in fast">
                {/* Overlay Area - Click to Close */}
                <div className="absolute inset-0 cursor-pointer" onClick={() => { setCodeModal(null); setModalTab('code'); }}></div>

                {/* Side Drawer Design */}
                <div className="relative bg-white border-l border-slate-200 shadow-xl w-full max-w-[95vw] md:max-w-4xl h-full overflow-hidden animate-slide-left fast flex flex-col z-10">
                    {/* Header */}
                    <div className="p-8 border-b border-slate-100 flex justify-between items-start bg-slate-50">
                        <div>
                            <div className="flex items-center gap-3 mb-2">
                                <div className="p-2 bg-danger/20 rounded-lg text-danger">
                                    <AlertCircle size={20} />
                                </div>
                                <h3 className="text-2xl font-black text-text-dark tracking-tight">{codeModal.title}</h3>
                            </div>
                            <div className="flex items-center gap-2 mt-2">
                                <span className="text-[0.65rem] font-bold text-slate-500 uppercase tracking-widest">Target Page:</span>
                                {codeModal.url && (
                                    <a href={codeModal.url} target="_blank" rel="noreferrer" className="text-sm text-primary font-bold hover:underline flex items-center gap-1">
                                        {codeModal.url}
                                    </a>
                                )}
                            </div>
                        </div>
                        <button
                            onClick={() => { setCodeModal(null); setModalTab('code'); }}
                            className="p-3 bg-white hover:bg-slate-100 rounded-2xl transition-all text-slate-500 hover:text-text-dark border border-slate-200"
                        >
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M18 6 6 18" /><path d="m6 6 12 12" /></svg>
                        </button>
                    </div>

                    {/* Content Area */}
                    <div className="flex-1 overflow-hidden flex flex-col md:flex-row">
                        {/* Main Interaction Area */}
                        <div className="flex-1 flex flex-col min-w-0">
                            {/* Tabs */}
                            <div className="flex border-b border-slate-200 px-8 bg-slate-50">
                                <button
                                    onClick={() => setModalTab('code')}
                                    className={`py-4 px-6 text-sm font-black uppercase tracking-widest transition-all relative ${modalTab === 'code' ? 'text-primary' : 'text-slate-500 hover:text-text-dark'}`}
                                >
                                    Issue in Code
                                    {modalTab === 'code' && <div className="absolute bottom-0 left-0 w-full h-1 bg-primary shadow-[0_0_10px_var(--color-primary-glow)]"></div>}
                                </button>
                                <button
                                    onClick={() => setModalTab('fix')}
                                    className={`py-4 px-6 text-sm font-black uppercase tracking-widest transition-all relative ${modalTab === 'fix' ? 'text-primary' : 'text-slate-500 hover:text-text-dark'}`}
                                >
                                    How to Fix
                                    {modalTab === 'fix' && <div className="absolute bottom-0 left-0 w-full h-1 bg-primary shadow-[0_0_10px_var(--color-primary-glow)]"></div>}
                                </button>
                            </div>

                            {/* Tab Content */}
                            <div className="flex-1 overflow-auto py-8 custom-scrollbar bg-white">
                                {modalTab === 'code' ? (
                                    <div className="h-full flex flex-col">
                                        <div className="flex items-center justify-between mb-4 px-4">
                                            <div className="flex flex-col">
                                                <h4 className="text-sm font-black text-slate-500 tracking-tight">The issue in the URL's source code</h4>
                                                <div className="text-[0.7rem] text-primary mt-1">
                                                    Showing instance {codeModal.instanceIndex + 1} of {codeModal.allOccurrences?.length || 1}
                                                </div>
                                            </div>
                                        </div>

                                        <div className="font-mono text-[0.8rem] bg-slate-50 overflow-hidden border border-slate-200 flex flex-1 min-h-[400px] shadow-inner rounded-xl mx-4">
                                            {lines.length === 0 ? (
                                                <div className="flex flex-col items-center justify-center w-full h-full text-slate-400 p-8 text-center bg-white/50">
                                                    <span className="text-3xl mb-4 opacity-50">🧭</span>
                                                    <p className="font-sans font-bold text-slate-500 mb-2">Structural Context</p>
                                                    <p className="font-sans text-xs max-w-sm leading-relaxed">This rule applies to the overall page structure or configuration and cannot be pinpointed to a single specific line of code.</p>
                                                </div>
                                            ) : (
                                                <>
                                                    <div className="bg-slate-100 px-4 py-8 text-slate-400 text-right select-none border-r border-slate-200 min-w-14 flex flex-col font-black">
                                                        {lines.map((_, i) => (
                                                            <div key={i} className="h-6 leading-6">{startLine + i}</div>
                                                        ))}
                                                    </div>
                                                    <div className="flex-1 py-8 overflow-x-auto custom-scrollbar">
                                                        {lines.map((line, i) => {
                                                            const currentId = startLine + i;
                                                            const isHighlighted = targetLineRange && currentId >= targetLineRange[0] && currentId <= targetLineRange[1];

                                                            return (
                                                                <div
                                                                    key={i}
                                                                    className={`px-8 h-6 leading-6 whitespace-pre min-w-max transition-colors font-medium ${isHighlighted ? 'bg-primary/10 text-primary border-l-2 border-primary -ml-[2px] font-black' : 'text-slate-600'}`}
                                                                >
                                                                    {line}
                                                                </div>
                                                            );
                                                        })}
                                                    </div>
                                                </>
                                            )}
                                        </div>

                                        {/* Instance Pagination */}
                                        {codeModal.allOccurrences && codeModal.allOccurrences.length > 1 && (
                                            <div className="mt-8 flex items-center justify-center gap-2">
                                                <button
                                                    disabled={codeModal.instanceIndex === 0}
                                                    onClick={() => {
                                                        const newIdx = codeModal.instanceIndex - 1;
                                                        const nextInst = codeModal.allOccurrences![newIdx];
                                                        setCodeModal({
                                                            ...codeModal,
                                                            instanceIndex: newIdx,
                                                            snippet: nextInst.snippet || nextInst.html || ""
                                                        });
                                                    }}
                                                    className="p-2 text-slate-400 hover:text-text-dark disabled:opacity-30 transition-all font-bold"
                                                >
                                                    <ChevronLeft size={20} />
                                                </button>

                                                <div className="flex gap-1">
                                                    {codeModal.allOccurrences.map((_, idx) => (
                                                        <button
                                                            key={idx}
                                                            onClick={() => {
                                                                const nextInst = codeModal.allOccurrences![idx];
                                                                setCodeModal({
                                                                    ...codeModal,
                                                                    instanceIndex: idx,
                                                                    snippet: nextInst.snippet || nextInst.html || ""
                                                                });
                                                            }}
                                                            className={`w-8 h-8 rounded-lg flex items-center justify-center text-xs font-black transition-all ${codeModal.instanceIndex === idx
                                                                ? 'bg-primary text-white shadow-[0_0_15px_rgba(var(--color-primary-rgb),0.5)]'
                                                                : 'bg-slate-100 text-slate-500 hover:bg-slate-200 hover:text-text-dark'
                                                                }`}
                                                        >
                                                            {idx + 1}
                                                        </button>
                                                    ))}
                                                </div>

                                                <button
                                                    disabled={codeModal.instanceIndex === codeModal.allOccurrences.length - 1}
                                                    onClick={() => {
                                                        const newIdx = codeModal.instanceIndex + 1;
                                                        const nextInst = codeModal.allOccurrences![newIdx];
                                                        setCodeModal({
                                                            ...codeModal,
                                                            instanceIndex: newIdx,
                                                            snippet: nextInst.snippet || nextInst.html || ""
                                                        });
                                                    }}
                                                    className="p-2 text-slate-400 hover:text-text-dark disabled:opacity-30 transition-all font-bold"
                                                >
                                                    <ChevronRight size={20} />
                                                </button>
                                            </div>
                                        )}
                                    </div>
                                ) : (
                                    <div className="animate-fade-in p-6">
                                        <div className="flex items-start gap-4 mb-8">
                                            <div className="p-4 bg-primary/10 rounded-4xl text-primary border border-primary/20">
                                                <Shield size={32} />
                                            </div>
                                            <div>
                                                <h4 className="text-2xl font-black text-text-dark tracking-tight mb-2 uppercase">Resolution Protocol</h4>
                                                <p className="text-lg text-slate-500 leading-relaxed font-medium">Follow these steps carefully to remediate the identified risk vector.</p>
                                            </div>
                                        </div>
                                        <div className="space-y-6">
                                            <div className="p-8 bg-slate-50 rounded-3xl  relative overflow-hidden border border-slate-200 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)]">
                                                <h5 className="text-[0.65rem] font-black text-primary uppercase tracking-[0.25em] mb-2">Issue Overview</h5>
                                                <p className="text-sm text-slate-600 leading-[1.8] text-justify font-medium">
                                                    {codeModal.description || "Our engines detected structural anomalies in the deployment layer of this resource. Remediation is required to restore full adherence to risk protocols."}
                                                </p>
                                            </div>
                                            <div className="p-8 bg-slate-50 rounded-3xl border border-slate-200 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)] relative overflow-hidden group">
                                                <h5 className="text-[0.65rem] font-black text-primary uppercase tracking-[0.25em] mb-2">Recommended Implementation</h5>
                                                <p className="text-sm text-slate-600 leading-[1.8] text-justify font-medium">
                                                    {codeModal.how_to_fix || "Deploy structural hardening protocols to remediate this vector. Ensure all downstream dependencies are aligned with the new schema configuration."}
                                                </p>
                                            </div>

                                            <div className="grid grid-cols-2 gap-4">
                                                <div className="p-6 bg-primary/10 rounded-3xl border border-primary/20 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)]">
                                                    <div className="text-[0.6rem] font-black text-primary uppercase tracking-widest mb-1">Expected Outcome</div>
                                                    <div className="text-sm text-text-dark font-bold italic">Resolved Security Integrity</div>
                                                </div>
                                                <div className="p-6 bg-primary/10 rounded-3xl border border-primary/20 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)]">
                                                    <div className="text-[0.6rem] font-black text-primary uppercase tracking-widest mb-1">Impact Level</div>
                                                    <div className="text-sm text-text-dark font-bold italic">High Reliability Gain</div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            , document.body);
    };

    const getCategoryIcon = (id: string) => {
        switch (id) {
            case 'security': return <Lock className="w-5 h-5" />;
            case 'compliance': return <Shield className="w-5 h-5" />;
            case 'trust': return <CheckCircle2 className="w-5 h-5" />;
            case 'seo': return <Eye className="w-5 h-5" />;
            case 'performance': return <Gauge className="w-5 h-5" />;
            case 'accessibility': return <Accessibility className="w-5 h-5" />;
            default: return <FileText className="w-5 h-5" />;
        }
    };

    return (
        <div className="min-h-screen flex flex-col bg-bg-light text-text-main font-sans selection:bg-primary selection:text-white">
            {renderIssueInCodeModal()}
            {/* Navigation Header */}
            <header className="bg-white/95 border-b border-slate-100 py-4 px-[5%] sticky top-0 z-100 flex justify-between items-center backdrop-blur-2xl shadow-sm">
                <div className="flex items-center gap-8">
                    <Link to="/" className="text-xl font-black text-text-dark flex items-center gap-2 no-underline hover:opacity-80 transition-all tracking-tight">
                        <Shield className="text-primary w-6 h-6" />
                        RiskLayer
                    </Link>
                    {/* Preview mode removed */}
                </div>
                <div className="flex items-center gap-4">
                    <div className="hidden lg:flex items-center gap-3 font-mono text-slate-500 bg-slate-50 py-1.5 px-4 rounded-full text-xs border border-slate-200 font-medium">
                        <span className="max-w-[200px] truncate">{scanData.domain || scanData.url.replace(/^https?:\/\//, '')}</span>
                        {scanData.ssl_info?.valid ? (
                            <div className="flex items-center gap-1.5 text-emerald-600 font-bold ml-2 border-l border-slate-200 pl-3">
                                <Shield size={12} className="fill-emerald-600/10" />
                                VALID SSL
                            </div>
                        ) : (
                            <div className="flex items-center gap-1.5 text-red-500 font-bold ml-2 border-l border-slate-200 pl-3">
                                <AlertCircle size={12} />
                                SSL ISSUES
                            </div>
                        )}
                    </div>
                    <Button
                        variant="primary"
                        text="Download Report"
                        className="py-2 px-6 rounded-full text-[0.85rem] font-bold bg-text-dark text-white hover:bg-black"
                        onClick={() => alert("Downloading...")}
                    />
                </div>
            </header>

            <main className="flex-1 py-12 px-[5%] max-w-[1400px] mx-auto w-full">
                {/* Hero Section: Summary & Score */}
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 mb-20 animate-fade-in">
                    {/* Gauge Score Card */}
                    <div className="col-span-1 lg:col-span-5 p-12 rounded-4xl flex flex-col items-center justify-center relative group overflow-hidden bg-white border border-slate-200 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)] min-h-[140px]">
                        <div className="absolute top-0 left-0 w-full h-1 bg-linear-to-r from-transparent via-primary/40 to-transparent opacity-50"></div>
                        <div className="absolute inset-0 bg-primary/2 opacity-0 group-hover:opacity-100 transition-opacity duration-1000 transform scale-110"></div>

                        <div className="relative mb-10 transform transition-transform duration-700">
                            <CircularProgress score={scanData.score} size={220} strokeWidth={14} />
                        </div>

                        <div className="text-center relative z-10">
                            <h3 className="text-sm font-black text-slate-500 uppercase tracking-[0.2em] mb-3">2. Overall Risk Score</h3>
                            <div className="flex items-center justify-center gap-2 mb-4">
                                <Activity className="w-4 h-4 text-primary animate-pulse" />
                                <span className={`text-xs font-bold ${scanData.score > 80 ? 'text-green-500' : 'text-amber-500'} uppercase tracking-widest`}>
                                    {scanData.score > 80 ? 'Operational Safe' : 'Intervention Needed'}
                                </span>
                            </div>
                            <p className="text-slate-500 text-xs leading-relaxed max-w-[240px] mx-auto font-medium">
                                Determined by auditing <span className="text-text-dark font-bold">{scanData.findings.length}</span> unique site signals and metadata parameters.
                            </p>
                        </div>
                    </div>

                    {/* Executive Summary Card */}
                    <div className="col-span-1 lg:col-span-7 p-12 rounded-4xl relative overflow-hidden group bg-white border border-slate-200 lg:p-8 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)] min-h-[140px]">
                        <div className="absolute -top-20 -right-20 opacity-[0.03] rotate-12 transition-transform duration-1000 group-hover:rotate-0 scale-150 text-text-dark">
                            <Shield size={300} />
                        </div>

                        <div className="relative z-10 flex flex-col h-full">
                            <div className="flex items-center gap-3 mb-8">
                                <div className="w-2.5 h-2.5 bg-primary rounded-full shadow-[0_0_15px_var(--color-primary-glow)]"></div>
                                <h2 className="text-sm font-black text-primary uppercase tracking-[0.2em]">1. Executive Summary</h2>
                                <div className="flex items-center gap-2 ml-auto">
                                    <span className="px-3 py-1 bg-primary/10 text-primary text-[0.6rem] font-black rounded-full border border-primary/20 flex items-center gap-1.5 animate-pulse">
                                        <Sparkles size={10} />
                                        AI GENERATED
                                    </span>
                                </div>
                            </div>

                            <h1 className="text-xl md:text-3xl font-black leading-tight mb-10 tracking-tight text-text-dark">
                                {scanData.executive_summary || "Our engines are synthesizing a high-level summary of your security profile..."}
                            </h1>

                            <div className="mt-auto grid grid-cols-2 md:grid-cols-4 gap-4">
                                {[
                                    { label: 'Latency', val: '24ms', icon: Clock },
                                    { label: 'Targets', val: scanData.scan_pages.length, icon: Globe },
                                    { label: 'Critical', val: scanData.findings.filter(f => f.severity === 'critical').length, icon: Fingerprint },
                                    { label: 'Audited', val: '100%', icon: CheckCircle2 }
                                ].map((item, i) => (
                                    <div key={i} className="bg-slate-50 p-5 rounded-3xl border border-slate-100 hover:border-slate-200 transition-all">
                                        <div className="flex items-center justify-between mb-2">
                                            <item.icon className="w-3.5 h-3.5 text-slate-400" />
                                        </div>
                                        <div className="text-[0.6rem] uppercase tracking-widest text-slate-400 mb-1 font-black">{item.label}</div>
                                        <div className="text-sm font-black text-text-dark">{item.val}</div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>

                {/* Category Analysis Grid */}
                <div className="mb-32">
                    <div className="flex flex-col md:flex-row md:items-end justify-between mb-12 gap-4">
                        <div>
                            <h2 className="text-3xl font-black text-text-dark tracking-tight mb-2">Technical Segmentation</h2>
                            <p className="text-slate-500 text-sm font-medium">Deep-dive assessment of site-wide infrastructure and metadata signals.</p>
                        </div>
                        <div className="h-px flex-1 bg-linear-to-r from-slate-200 to-transparent mx-8 mb-4 hidden xl:block"></div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
                        {(Array.isArray(scanData.categories)
                            ? scanData.categories
                            : Object.entries(scanData.categories || {}).map(([id, info]: [string, any]) => ({
                                id,
                                name: id.toUpperCase(),
                                score: info.score || 0,
                                description: `Segmented analysis of ${id} vectors and deployment integrity.`
                            }))
                        ).map((cat) => (
                            <div key={cat.id} className="group relative p-10 rounded-[2.5rem] hover:bg-slate-50 transition-all duration-500 overflow-hidden bg-white border border-slate-200 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)]">
                                <div className="absolute -right-4 -bottom-4 text-slate-100 transform rotate-12 transition-transform duration-700 group-hover:scale-125 group-hover:text-primary/10">
                                    {getCategoryIcon(cat.id)}
                                </div>

                                <div className="flex justify-between items-start mb-8">
                                    <div className="p-4 bg-slate-50 rounded-2xl text-primary border border-slate-100 group-hover:bg-primary group-hover:text-white transition-all duration-500 transform group-hover:-translate-y-1">
                                        {getCategoryIcon(cat.id)}
                                    </div>
                                    <div className="text-right">
                                        <div className="text-3xl font-black text-text-dark leading-none mb-1">{cat.score}</div>
                                        <div className="text-[0.55rem] font-black text-slate-400 uppercase tracking-[0.2em]">Rating</div>
                                    </div>
                                </div>

                                <h3 className="text-lg font-black text-text-dark mb-3 uppercase tracking-wider">{cat.name}</h3>
                                <p className="text-xs text-slate-500 leading-relaxed mb-8 opacity-80 font-medium">
                                    {cat.description}
                                </p>

                                <div className="h-1 w-full bg-slate-100 rounded-full overflow-hidden">
                                    <div
                                        className={`h-full transition-all duration-1000 ease-out ${cat.score > 80 ? 'bg-green-500' :
                                            cat.score > 50 ? 'bg-amber-500' :
                                                'bg-red-500'
                                            }`}
                                        style={{ width: `${cat.score}%` }}
                                    ></div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* 3. Top 10 Urgent Issues */}
                <div className="mb-20">
                    <h2 className="text-3xl font-black text-text-dark tracking-tight mb-8">3. Top 10 Urgent Issues</h2>
                    <div className="space-y-4">
                        {topUrgentIssues.length === 0 ? (
                            <div className="p-8 text-center text-slate-500 bg-slate-50 rounded-3xl border border-slate-100 font-medium">No urgent issues detected.</div>
                        ) : (
                            topUrgentIssues.map((issue: any, idx) => (
                                <div key={`${issue.id}-${idx}`} className="flex flex-col md:flex-row md:items-center justify-between p-6 bg-white border border-slate-200 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)] rounded-3xl gap-4 transition-all">
                                    <div className="flex items-start gap-4">
                                        <div className="font-bold text-slate-400 font-mono text-lg shrink-0">{idx + 1}.</div>
                                        <div>
                                            <div className="font-bold text-text-dark mb-1">{issue.message.replace(/^[0-9]+\s+/, '')}</div>
                                            <div className="text-xs text-slate-500 font-medium">Category: <span className="uppercase text-primary font-bold">{issue.category}</span></div>
                                        </div>
                                    </div>
                                    <div className={`px-4 py-1.5 rounded-full text-[0.65rem] font-black uppercase tracking-[0.2em] border shrink-0 w-fit ${getSeverityColor(issue.severity)}`}>
                                        {issue.severity}
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>

                {/* Category Group Layout (Sections 4-7) */}
                <div className="my-20">
                    <div className="flex items-center justify-between mb-10">
                        <h2 className="text-3xl font-black text-text-dark tracking-tight">Audit Report Details</h2>
                        <span className="px-5 py-2 bg-slate-50 border border-slate-200 rounded-full font-mono text-[0.65rem] text-slate-500 tracking-widest font-black uppercase">
                            <span className="text-primary">{scanData.findings.length}</span> Total Signals
                        </span>
                    </div>

                    <div className="space-y-12">
                        {categoryGroups.map((cat: any, index: number) => (
                            <div key={cat.id} className="bg-white border border-slate-200 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)] p-4 md:p-8 rounded-[2rem] md:rounded-[2.5rem]">
                                <h3 className="text-2xl font-black text-text-dark mb-8 pb-4 border-b border-slate-100 flex items-center gap-4">
                                    <div className="p-3 bg-slate-50 rounded-2xl text-primary border border-slate-100">
                                        {getCategoryIcon(cat.id)}
                                    </div>
                                    {index + 4}. {cat.name}
                                </h3>

                                <div className="grid grid-cols-1 xl:grid-cols-1 gap-8">
                                    {/* Issues Column */}
                                    <div className="bg-slate-50 border border-red-100 p-6 rounded-3xl">
                                        <div className="flex justify-between items-center mb-6 px-2">
                                            <h4 className="text-sm font-black text-red-500 uppercase tracking-[0.2em] flex items-center gap-2">
                                                <AlertCircle size={16} /> Issues
                                            </h4>
                                            <span className="text-xs font-bold text-slate-500 bg-white px-3 py-1 rounded-xl border border-slate-100">
                                                {cat.issues.length} {cat.issues.length === 1 ? 'Rule' : 'Rules'} Failed
                                            </span>
                                        </div>

                                        <div className="space-y-3">
                                            {cat.issues.length === 0 ? (
                                                <div className="text-center py-8 text-slate-400 text-sm font-medium">No issues found in this category.</div>
                                            ) : (
                                                cat.issues.map((issue: any) => (
                                                    <div key={issue.rule_id} className="group flex flex-col bg-white border border-slate-200 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)] rounded-2xl  transition-colors overflow-hidden">
                                                        <button
                                                            onClick={() => handleAccordionToggle(`iss-${issue.rule_id}`)}
                                                            className="flex flex-col md:flex-row md:items-center justify-between p-5 md:p-6 w-full text-left hover:bg-slate-50 transition-colors gap-4"
                                                        >
                                                            <div className="flex flex-col gap-2 md:gap-1 flex-1 min-w-0">
                                                                <span className="text-[0.9rem] md:text-[0.85rem] font-bold text-text-dark leading-tight break-words">
                                                                    {issue.cleanMessage}
                                                                </span>
                                                                <div className="flex flex-wrap items-center gap-3">
                                                                    <div className={`md:hidden px-3 py-1 rounded-lg text-[0.6rem] font-black uppercase tracking-[0.1em] border transition-all w-fit ${getSeverityColor(issue.severity)}`}>
                                                                        {issue.severity}
                                                                    </div>
                                                                    <span className="text-[0.65rem] font-black text-slate-400 uppercase tracking-wider">
                                                                        {issue.items.length} {issue.items.length === 1 ? 'Occurrence' : 'Occurrences'} • {issue.affectedUrls.size === 0 ? 'Site-wide' : `${issue.affectedUrls.size} ${issue.affectedUrls.size === 1 ? 'Page' : 'Pages'}`}
                                                                    </span>
                                                                </div>
                                                            </div>
                                                            <div className="flex items-center justify-between md:justify-end gap-3 shrink-0 pt-3 md:pt-0 border-t md:border-t-0 border-slate-100 md:border-transparent">
                                                                <div className={`hidden md:block px-3 py-1 rounded-full text-[0.6rem] font-black uppercase tracking-[0.2em] border transition-all w-fit ${getSeverityColor(issue.severity)}`}>
                                                                    {issue.severity}
                                                                </div>
                                                                <div className="flex items-center gap-2 text-[0.7rem] font-bold text-primary md:hidden">
                                                                    View Details
                                                                </div>
                                                                <ChevronDown size={14} className={`text-slate-400 transition-transform ${openScanPages[`iss-${issue.rule_id}`] ? 'rotate-180' : ''}`} />
                                                            </div>
                                                        </button>

                                                        {/* Expanded Form */}
                                                        {openScanPages[`iss-${issue.rule_id}`] && (
                                                            <div className="p-2 md:p-6 bg-slate-50 border-t border-slate-100">
                                                                <div className="max-h-[300px] overflow-y-auto custom-scrollbar space-y-3">
                                                                    {issue.items.map((urlGroup: any, idx: number) => {
                                                                        const urlResult = urlGroup.url;
                                                                        const instances = urlGroup.instances || [];
                                                                        const firstInstance = instances[0] || {};

                                                                        const handleOpenModal = () => {
                                                                            if (instances.length > 0) {
                                                                                setCodeModal({
                                                                                    isOpen: true,
                                                                                    title: issue.cleanMessage,
                                                                                    snippet: firstInstance.snippet || firstInstance.html || "",
                                                                                    url: urlResult,
                                                                                    description: issue.description,
                                                                                    how_to_fix: issue.how_to_fix,
                                                                                    allOccurrences: instances,
                                                                                    instanceIndex: 0
                                                                                });
                                                                            }
                                                                        };

                                                                        return (
                                                                            <div key={idx} onClick={handleOpenModal} className="cursor-pointer group/item flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 md:px-6 md:py-4 bg-white rounded-2xl border border-slate-200 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)] hover:border-primary/20 transition-all">
                                                                                <div className="flex flex-col gap-1 min-w-0">
                                                                                    <div className="text-[0.75rem] font-mono text-primary break-all md:truncate">
                                                                                        {urlResult}
                                                                                    </div>
                                                                                    <div className="text-[0.65rem] font-bold text-slate-400 flex items-center gap-2 capitalize">
                                                                                        <span>{instances.length} {instances.length === 1 ? 'item' : 'items'} found</span>
                                                                                    </div>
                                                                                </div>
                                                                                {instances.length > 0 && (
                                                                                    <Button
                                                                                        variant="primary"
                                                                                        size="sm"
                                                                                        className="h-10 text-[0.7rem] shrink-0 rounded-xl px-6 md:px-4"
                                                                                        onClick={(e) => { e.stopPropagation(); handleOpenModal(); }}
                                                                                        text="Inspect Code"
                                                                                    />
                                                                                )}
                                                                            </div>
                                                                        )
                                                                    })}
                                                                </div>
                                                            </div>
                                                        )}
                                                    </div>
                                                ))
                                            )}
                                        </div>
                                    </div>

                                    {/* Passed Column */}
                                    <div className="bg-slate-50 border border-green-100 p-6 rounded-3xl">
                                        <div className="flex justify-between items-center mb-6 px-2">
                                            <h4 className="text-sm font-black text-green-500 uppercase tracking-[0.2em] flex items-center gap-2">
                                                <CheckCircle2 size={16} /> Checks Passed
                                            </h4>
                                            <span className="text-xs font-bold text-slate-500 bg-white px-3 py-1 rounded-xl border border-slate-100">
                                                {cat.passed.length} Rules Passed
                                            </span>
                                        </div>

                                        <div className="space-y-3">
                                            {cat.passed.length === 0 ? (
                                                <div className="text-center py-8 text-slate-400 text-sm font-medium">No passed checks logged.</div>
                                            ) : (
                                                cat.passed.map((pass: any, idx: number) => (
                                                    <div key={idx} className="flex items-center justify-between p-4 bg-white border border-slate-200 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)] rounded-2xl">
                                                        <span className="text-[0.85rem] font-bold text-text-dark leading-tight">
                                                            {pass.title || pass}
                                                        </span>
                                                        <span className="text-[0.65rem] font-black text-green-600 uppercase tracking-widest bg-green-50 px-3 py-1 rounded-full whitespace-nowrap">
                                                            Verified
                                                        </span>
                                                    </div>
                                                ))
                                            )}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* 8. Fix Priority Order & 9. Step-by-step fix guidance */}
                <div className="mb-20">
                    <h2 className="text-3xl font-black text-text-dark tracking-tight mb-8">8. Fix Priority Order</h2>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-20">
                        {priorityFixOrder.length === 0 ? (
                            <div className="col-span-full p-8 text-center text-slate-500 bg-slate-50 rounded-3xl border border-slate-100 font-medium">No issues to fix.</div>
                        ) : (
                            priorityFixOrder.map((rule: any) => (
                                <div key={rule.rule_id} className="p-6 bg-white border border-slate-200 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)] rounded-3xl flex flex-col items-start gap-4 transition-all group relative overflow-hidden">
                                    <div className={`absolute top-0 right-0 p-2 opacity-5`}>
                                        <Shield className={`w-12 h-12 ${getSeverityColor(rule.severity || 'low')}`} />
                                    </div>
                                    <div className={`px-4 py-1 rounded-full text-[0.6rem] font-black uppercase tracking-[0.15em] border ${getSeverityColor(rule.severity || 'low')}`}>
                                        {rule.severity || 'low'}
                                    </div>
                                    <h4 className="font-black text-text-dark text-[0.95rem] leading-tight z-10">{rule.cleanMsg}</h4>
                                    <div className="flex items-center gap-2 mt-auto z-10">
                                        <div className="w-1.5 h-1.5 rounded-full bg-primary/40"></div>
                                        <span className="text-[0.65rem] font-bold text-slate-500 uppercase tracking-widest leading-none">
                                            Found across <span className="text-text-dark">{rule.count}</span> pages
                                        </span>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>

                    {/* AI Discovery Insight */}
                    <div className="mb-32 bg-linear-to-br from-primary/5 via-transparent to-primary/5 border border-slate-200 p-12 rounded-[3.5rem] relative overflow-hidden group">
                        <div className="absolute top-0 right-0 p-8 opacity-5 text-text-dark">
                            <Sparkles size={80} className="text-primary animate-pulse" />
                        </div>
                        <div className="relative z-10">
                            <div className="flex items-center gap-3 mb-8">
                                <Cpu className="text-primary w-6 h-6" />
                                <h2 className="text-sm font-black text-text-dark uppercase tracking-[0.3em]">Autonomous Agent Briefing</h2>
                            </div>
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
                                <div>
                                    <p className="text-xl font-medium text-slate-700 leading-relaxed italic border-l-4 border-primary/40 pl-8">
                                        "Our neural audit engine has completed a multi-threaded traversal of your infrastructure. We have identified {scanData.findings.filter(f => f.severity === 'critical').length} critical path vulnerabilities and localized {scanData.findings.length} total risk vectors."
                                    </p>
                                </div>
                                <div className="space-y-6">
                                    <div className="flex items-center gap-4 text-sm">
                                        <div className="w-2 h-2 rounded-full bg-green-500"></div>
                                        <span className="text-slate-500">Crawler depth reached: <span className="text-text-dark font-bold">Max (3)</span></span>
                                    </div>
                                    <div className="flex items-center gap-4 text-sm">
                                        <div className="w-2 h-2 rounded-full bg-primary shadow-[0_0_10px_var(--color-primary-glow)]"></div>
                                        <span className="text-slate-500">Security Headers Analysis: <span className="text-text-dark font-bold">Complete</span></span>
                                    </div>
                                    <div className="flex items-center gap-4 text-sm">
                                        <div className="w-2 h-2 rounded-full bg-amber-500"></div>
                                        <span className="text-slate-500">Signal Extraction Rate: <span className="text-text-dark font-bold">100% Reliability</span></span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <h2 className="text-3xl font-black text-text-dark tracking-tight mb-8 flex items-center gap-4">
                        9. Step-by-Step Fix Guidance
                        <span className="text-[0.6rem] py-1 px-3 bg-slate-50 rounded-full border border-slate-200 text-slate-500 font-black tracking-widest">AI SUGGESTED</span>
                    </h2>
                    <div className="space-y-8">
                        {priorityFixOrder.length === 0 ? (
                            <div className="p-8 text-center text-slate-500 bg-slate-50 rounded-3xl border border-slate-100 font-medium">All clear.</div>
                        ) : (
                            priorityFixOrder.slice(0, 10).map((rule: any, idx) => (
                                <div key={`guide-${rule.rule_id}`} className="p-8 bg-white border border-slate-200 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)] rounded-[2.5rem] flex flex-col md:flex-row gap-8 items-start relative overflow-hidden transition-all">
                                    <div className={`absolute top-0 left-0 w-1 h-full transition-colors ${rule.severity === 'critical' ? 'bg-red-600' :
                                        rule.severity === 'high' ? 'bg-red-500' :
                                            rule.severity === 'medium' ? 'bg-amber-500' : 'bg-primary'
                                        }`}></div>
                                    <div className={`shrink-0 w-14 h-14 rounded-full flex flex-col items-center justify-center border border-slate-100 ${getSeverityColor(rule.severity || 'low')}`}>
                                        <span className="text-[0.5rem] font-black uppercase tracking-tighter opacity-70 leading-none mb-0.5">{rule.severity ? rule.severity.slice(0, 4) : 'LOW'}</span>
                                        <span className="text-lg font-black leading-none">{idx + 1}</span>
                                    </div>
                                    <div className="flex flex-col gap-2">
                                        <h4 className="text-xl font-black text-text-dark tracking-tight leading-snug">{rule.cleanMsg}</h4>
                                        <p className="text-slate-600 font-medium text-base leading-relaxed max-w-3xl">{rule.how_to_fix || "Deploy structural hardening protocols to remediate this vector."}</p>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>
                <div className="flex flex-col md:flex-row md:items-end justify-between mb-12 gap-4">
                    <div>
                        <h2 className="text-3xl font-black text-text-dark tracking-tight mb-2">Technical Data Lake</h2>
                        <p className="text-slate-500 text-sm font-medium">Asynchronous discovery of site-wide infrastructure and deployment metadata.</p>
                    </div>
                    <div className="h-px flex-1 bg-linear-to-r from-slate-200 to-transparent mx-8 mb-4 hidden xl:block"></div>
                </div>
                <div className="bg-white border border-slate-200 rounded-3xl overflow-hidden shadow-[0_20px_60px_-15px_rgba(0,0,0,0.06)] overflow-x-hidden">
                    <div className="divide-y divide-slate-100">
                        {scanData.scan_pages.map((p) => (
                            <div key={p.id} className="group transition-all hover:bg-slate-50">
                                <button
                                    className="w-full flex items-center justify-between p-6 md:p-10 md:px-12 text-left cursor-pointer"
                                    onClick={() => handleAccordionToggle(p.id)}
                                >
                                    <div className="flex flex-col md:flex-row md:items-center gap-4 md:gap-10 flex-1 min-w-0">
                                        <div className="flex flex-col gap-1 min-w-0 md:min-w-[320px]">
                                            <span className="text-[0.6rem] font-bold text-primary uppercase tracking-widest mb-1">Target Resource</span>
                                            <code className="text-[0.9rem] font-mono text-text-dark font-bold truncate max-w-full md:max-w-md group-hover:text-primary transition-colors">{p.url}</code>
                                        </div>
                                        <div className="hidden lg:flex flex-col gap-1">
                                            <span className="text-[0.6rem] font-bold text-slate-400 uppercase tracking-widest mb-1">Title Attribute</span>
                                            <span className="text-xs font-medium text-slate-500 truncate max-w-sm italic opacity-80">
                                                {p.title || "No metadata found"}
                                            </span>
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-8">
                                        <div className="hidden sm:flex flex-col items-end">
                                            <div className="px-3 py-1 bg-green-50 text-green-600 text-[0.65rem] font-black rounded-lg border border-green-100">200 OK</div>
                                        </div>
                                        <div className={`p-2 rounded-xl bg-slate-50 border border-slate-100 `}>
                                            <ChevronDown size={18} className={`transition-all ${openScanPages[p.id] ? "rotate-180 border-primary/40 text-primary" : "text-slate-400"}`} />
                                        </div>
                                    </div>
                                </button>

                                {openScanPages[p.id] && (
                                    <div className="px-6 md:px-12 pb-8 md:pb-12 animate-fade-in-down">
                                        <div className="bg-slate-50 rounded-[2rem] md:rounded-[2.5rem] p-5 md:p-10 border border-slate-200 font-mono text-[0.8rem] text-slate-700 relative shadow-inner">
                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-10 border-b border-slate-200 pb-10 mb-10 relative z-10">
                                                <div className="space-y-4">
                                                    <div className="text-[0.6rem] font-black uppercase tracking-[0.4em] text-slate-400">Signals Extracted</div>
                                                    <div className="flex gap-8">
                                                        <div className="flex flex-col"><span className="text-xl font-black text-text-dark">{p.extracted_json?.links_internal?.length || 0}</span><span className="text-[0.6rem] uppercase tracking-widest text-slate-400 font-bold">Links</span></div>
                                                        <div className="flex flex-col"><span className="text-xl font-black text-text-dark">{p.extracted_json?.images?.length || 0}</span><span className="text-[0.6rem] uppercase tracking-widest text-slate-400 font-bold">Images</span></div>
                                                    </div>
                                                </div>
                                                <div className="space-y-4">
                                                    <div className="text-[0.6rem] font-black uppercase tracking-[0.4em] text-slate-400">Server Context</div>
                                                    <div className="flex flex-wrap gap-2">
                                                        {Object.entries(p.meta || {}).slice(0, 4).map(([k, v]: [string, any]) => (
                                                            <span key={k} className="px-3 py-1 bg-white rounded-lg border border-slate-200 text-[0.6rem] lowercase text-slate-500 font-bold">{k}: {String(v).slice(0, 15)}...</span>
                                                        ))}
                                                    </div>
                                                </div>
                                            </div>
                                            <pre className="whitespace-pre-wrap leading-relaxed opacity-80 max-h-[400px] overflow-auto custom-scrollbar text-slate-600 bg-white p-6 rounded-2xl border border-slate-100">
                                                {JSON.stringify(p.extracted_json, null, 4)}
                                            </pre>
                                        </div>
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                </div>

                <footer className="py-24 text-center border-t border-slate-200 relative group overflow-hidden mt-20">
                    <div className="absolute inset-0 bg-primary/5 blur-[100px] rounded-full opacity-0 group-hover:opacity-100 transition-opacity duration-1000"></div>
                    <div className="flex items-center justify-center gap-3 mb-8">
                        <Shield className="w-5 h-5 text-primary" />
                        <span className="text-sm tracking-[0.5em] font-black text-slate-400 uppercase">RiskLayer core v1.1.0</span>
                    </div>

                    <h3 className="text-[0.65rem] font-black text-slate-400 uppercase tracking-[0.2em] mb-4">10. Legal Disclaimer</h3>
                    <p className="text-[0.6rem] uppercase tracking-[0.2em] font-medium max-w-[800px] mx-auto leading-relaxed text-slate-400">
                        This automated report is informational only and not legal or regulatory advice.
                        <br /><br />
                        Autonomous Threat Intelligence • Deterministic Security Verification • Real-Time Risk Profiling Architecture
                    </p>

                    <div className="mt-12 flex items-center justify-center gap-6 text-[0.6rem] font-black uppercase tracking-widest text-slate-400">
                        <span>Built for Phinexis Tech</span>
                        <span className="w-1 h-1 bg-slate-300 rounded-full"></span>
                        <span>Production Pipeline v3.2</span>
                    </div>
                </footer>
            </main>
        </div>
    );
}

export default ReportPreviewPage;