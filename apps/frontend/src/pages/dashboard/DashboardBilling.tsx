import { Button } from '../../components/ui/Button';
import { ShieldCheck } from 'lucide-react';

export default function DashboardBilling() {
    return (
        <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500 h-full">
            <div>
                <h2 className="text-2xl font-bold text-text-dark mb-2">Billing & Usage</h2>
                <p className="text-slate-500">Manage your subscription, view usage, and download invoices.</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="md:col-span-1 space-y-6">
                    <div className="bg-primary border border-primary/20 rounded-3xl p-6 relative overflow-hidden group">
                        <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:scale-110 transition-transform">
                            <ShieldCheck className="w-20 h-20 text-white" />
                        </div>
                        <h3 className="text-white/60 text-sm font-semibold uppercase tracking-wider mb-2">Current Plan</h3>
                        <div className="text-3xl font-bold text-white mb-1">Scale Pro</div>
                        <div className="text-white/80 font-medium mb-6">$149 / month</div>
                        <div className="space-y-3 mb-8">
                            <div className="flex items-center gap-2 text-sm text-white/90">
                                <ShieldCheck className="w-4 h-4" /> Unlimited Org Members
                            </div>
                            <div className="flex items-center gap-2 text-sm text-white/90">
                                <ShieldCheck className="w-4 h-4" /> API Access & Webhooks
                            </div>
                            <div className="flex items-center gap-2 text-sm text-white/90">
                                <ShieldCheck className="w-4 h-4" /> Priority Support
                            </div>
                        </div>
                        <Button variant="outline" fullWidth className="bg-white/20 border-white/30 text-white hover:bg-white/30">
                            Upgrade Plan
                        </Button>
                    </div>

                    <div className="bg-white border border-slate-100 rounded-3xl p-6 shadow-sm">
                        <h3 className="text-text-dark font-bold mb-4">Usage Analytics</h3>
                        <div className="space-y-6">
                            <div>
                                <div className="flex justify-between text-sm mb-2">
                                    <span className="text-slate-500">Monthly Scans</span>
                                    <span className="text-text-dark font-medium">124 / 500</span>
                                </div>
                                <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
                                    <div className="h-full bg-primary" style={{ width: '24.8%' }}></div>
                                </div>
                            </div>
                            <div>
                                <div className="flex justify-between text-sm mb-2">
                                    <span className="text-slate-500">Seats Used</span>
                                    <span className="text-text-dark font-medium">4 / 10</span>
                                </div>
                                <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
                                    <div className="h-full bg-primary" style={{ width: '40%' }}></div>
                                </div>
                                <p className="text-[10px] text-slate-400 mt-2 uppercase tracking-tighter">* Next reset in 12 days</p>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="md:col-span-2">
                    <div className="bg-white border border-slate-100 rounded-3xl overflow-hidden h-full shadow-sm">
                        <div className="p-6 border-b border-slate-50">
                            <h3 className="text-lg font-bold text-text-dark">Billing History</h3>
                        </div>
                        <div className="overflow-x-auto">
                            <table className="w-full text-left border-collapse">
                                <tbody className="divide-y divide-slate-50">
                                    {[
                                        { id: 'INV-2024-001', date: 'Mar 1, 2024', amount: '$149.00', status: 'Paid' },
                                        { id: 'INV-2024-002', date: 'Feb 1, 2024', amount: '$149.00', status: 'Paid' },
                                        { id: 'INV-2024-003', date: 'Jan 1, 2024', amount: '$149.00', status: 'Paid' },
                                        { id: 'INV-2023-012', date: 'Dec 1, 2023', amount: '$149.00', status: 'Paid' },
                                    ].map((inv, i) => (
                                        <tr key={i} className="hover:bg-slate-50 transition-colors">
                                            <td className="px-6 py-5 text-sm text-text-dark font-medium">{inv.id}</td>
                                            <td className="px-6 py-5 text-sm text-slate-500">{inv.date}</td>
                                            <td className="px-6 py-5 text-sm text-text-dark">{inv.amount}</td>
                                            <td className="px-6 py-5">
                                                <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-primary/10 text-primary uppercase">
                                                    {inv.status}
                                                </span>
                                            </td>
                                            <td className="px-6 py-5 text-right">
                                                <button className="text-xs text-primary font-bold hover:underline">Download PDF</button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
