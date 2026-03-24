import { Button } from '../../components/ui/Button';
import { Settings, Link as LinkIcon, Check, Plus, Key } from 'lucide-react';

export default function DashboardConfig() {
    return (
        <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500 h-full">
            <div>
                <h2 className="text-2xl font-bold text-text-dark mb-2">Platform Configuration</h2>
                <p className="text-slate-500">Settings, integrations, API keys, and workflow rules.</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                {/* General Settings */}
                <div className="bg-white border border-slate-100 rounded-3xl p-6 space-y-6 shadow-sm">
                    <div className="flex items-center gap-3 border-b border-slate-50 pb-4">
                        <Settings className="w-6 h-6 text-primary" />
                        <h3 className="text-lg font-bold text-text-dark">General Settings</h3>
                    </div>

                    <div className="space-y-4">
                        <div>
                            <label className="block text-sm font-medium text-slate-500 mb-2">Organization Name</label>
                            <input type="text" defaultValue="Acme Corp" className="w-full bg-slate-50 border border-slate-100 rounded-xl px-4 py-3 text-text-dark focus:outline-none focus:border-primary transition-colors" />
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-slate-500 mb-2">Default Scan Domain</label>
                            <input type="url" defaultValue="https://acmecorp.com" className="w-full bg-slate-50 border border-slate-100 rounded-xl px-4 py-3 text-text-dark focus:outline-none focus:border-primary transition-colors" />
                        </div>
                        <div className="flex items-center justify-between p-4 bg-slate-50 rounded-xl border border-slate-100">
                            <div>
                                <h4 className="text-text-dark font-bold text-sm">Two-Factor Auth (2FA)</h4>
                                <p className="text-xs text-slate-400">Require 2FA for all org members</p>
                            </div>
                            <div className="w-12 h-6 bg-primary rounded-full relative cursor-pointer">
                                <div className="absolute right-1 top-1 w-4 h-4 bg-white rounded-full"></div>
                            </div>
                        </div>
                    </div>
                    <div className="flex justify-end">
                        <Button variant="primary" size="sm" rounded="rounded-xl" className="font-bold text-sm">
                            Save Changes
                        </Button>
                    </div>
                </div>

                {/* Integrations */}
                <div className="bg-white border border-slate-100 rounded-3xl p-6 space-y-6 shadow-sm">
                    <div className="flex items-center gap-3 border-b border-slate-50 pb-4">
                        <LinkIcon className="w-6 h-6 text-primary" />
                        <h3 className="text-lg font-bold text-text-dark">Integrations & Workflows</h3>
                    </div>

                    <div className="space-y-4">
                        {/* Slack Integration */}
                        <div className="flex items-center justify-between p-4 bg-slate-50 rounded-2xl border border-slate-100 hover:border-primary/20 hover:bg-slate-100 transition-all duration-300 group">
                            <div className="flex items-center gap-4">
                                <div className="w-11 h-11 rounded-xl bg-white border border-slate-200 flex items-center justify-center p-2 group-hover:scale-105 transition-transform">
                                    <img src="/Slack.png" alt="Slack" className="w-full h-full object-contain" />
                                </div>
                                <div>
                                    <div className="text-text-dark font-bold text-sm">Slack Alerts</div>
                                    <div className="text-[11px] text-slate-400">#security-alerts</div>
                                </div>
                            </div>
                            <button
                                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-primary/10 text-primary border border-primary/20 text-[11px] font-bold uppercase tracking-wider"
                            >
                                <Check className="w-3.5 h-3.5" />
                                Connected
                            </button>
                        </div>

                        {/* Jira Integration */}
                        <div className="flex items-center justify-between p-4 bg-slate-50 rounded-2xl border border-slate-100 hover:border-primary/20 hover:bg-slate-100 transition-all duration-300 group">
                            <div className="flex items-center gap-4">
                                <div className="w-11 h-11 rounded-xl bg-white border border-slate-200 flex items-center justify-center p-2 group-hover:scale-105 transition-transform">
                                    <img src="/jira.png" alt="Jira" className="w-full h-full object-contain" />
                                </div>
                                <div>
                                    <div className="text-text-dark font-bold text-sm">Jira Software</div>
                                    <div className="text-[11px] text-slate-400">Tickets for criticals</div>
                                </div>
                            </div>
                            <Button
                                variant="outline"
                                size="sm"
                                rounded="rounded-lg"
                                className="flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-bold uppercase tracking-wider border-slate-200 hover:text-primary hover:border-primary/30 transition-all"
                            >
                                <Plus className="w-3.5 h-3.5" />
                                Connect
                            </Button>
                        </div>

                        {/* ClickUp Integration */}
                        <div className="flex items-center justify-between p-4 bg-slate-50 rounded-2xl border border-slate-100 hover:border-primary/20 hover:bg-slate-100 transition-all duration-300 group">
                            <div className="flex items-center gap-4">
                                <div className="w-11 h-11 rounded-xl bg-white border border-slate-200 flex items-center justify-center p-2 group-hover:scale-105 transition-transform">
                                    <img src="/clickup.png" alt="ClickUp" className="w-full h-full object-contain" />
                                </div>
                                <div>
                                    <div className="text-text-dark font-bold text-sm">ClickUp</div>
                                    <div className="text-[11px] text-slate-400">Sync tasks and issues</div>
                                </div>
                            </div>
                            <Button
                                variant="outline"
                                size="sm"
                                rounded="rounded-lg"
                                className="flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-bold uppercase tracking-wider border-slate-200 hover:text-primary hover:border-primary/30 transition-all"
                            >
                                <Plus className="w-3.5 h-3.5" />
                                Connect
                            </Button>
                        </div>

                        {/* Webhooks Integration */}
                        <div className="flex items-center justify-between p-4 bg-slate-50 rounded-2xl border border-slate-100 hover:border-primary/20 hover:bg-slate-100 transition-all duration-300 group">
                            <div className="flex items-center gap-4">
                                <div className="w-11 h-11 rounded-xl bg-primary/10 flex items-center justify-center p-2 text-primary group-hover:scale-105 transition-transform">
                                    <Key className="w-5 h-5" />
                                </div>
                                <div>
                                    <div className="text-text-dark font-bold text-sm">API Webhooks</div>
                                    <div className="text-[11px] text-slate-400">Outbound event streaming</div>
                                </div>
                            </div>
                            <button
                                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-100 text-slate-500 hover:text-text-dark border border-slate-200 text-[11px] font-bold uppercase tracking-wider transition-all"
                            >
                                <Settings className="w-3.5 h-3.5" />
                                Configure
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
