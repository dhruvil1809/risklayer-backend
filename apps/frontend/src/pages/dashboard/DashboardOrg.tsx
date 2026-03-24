import { useState, useEffect } from 'react';
import { Button } from '../../components/ui/Button';
import { ChevronDown } from 'lucide-react';

const rolesList = ['Owner', 'Admin', 'Member', 'Viewer'];

export const RoleDropdown = ({ currentRole }: { currentRole: string }) => {
    const [isOpen, setIsOpen] = useState(false);
    const [selectedRole, setSelectedRole] = useState(currentRole);

    return (
        <div className="relative">
            <Button
                variant="custom"
                size="none"
                display="flex"
                rounded="rounded-lg"
                fontWeight="font-medium"
                onClick={() => setIsOpen(!isOpen)}
                onBlur={() => setTimeout(() => setIsOpen(false), 200)}
                className="bg-slate-50 border border-slate-100 text-text-dark text-sm px-3 py-1.5 outline-none hover:border-primary/50 focus:border-primary transition-all items-center gap-2 min-w-[110px] justify-between relative z-10"
            >
                {selectedRole}
                <ChevronDown className={`w-4 h-4 text-slate-400 transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`} />
            </Button>

            {isOpen && (
                <div className="absolute right-0 top-full mt-2 w-full min-w-[120px] bg-white border border-slate-100 rounded-xl shadow-[0_10px_40px_rgba(0,0,0,0.1)] py-1 z-50 animate-in fade-in slide-in-from-top-1 duration-200">
                    {rolesList.map((r) => (
                        <div
                            key={r}
                            onClick={() => {
                                setSelectedRole(r);
                                setIsOpen(false);
                            }}
                            className={`px-3 py-2 text-sm cursor-pointer transition-colors flex items-center justify-between ${selectedRole === r
                                ? 'text-primary bg-primary/10 font-medium'
                                : 'text-slate-600 hover:text-text-dark hover:bg-slate-50'
                                }`}
                        >
                            {r}
                            {selectedRole === r && (
                                <div className="w-1.5 h-1.5 rounded-full bg-primary" />
                            )}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

export default function DashboardOrg() {
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
            console.error('Failed to parse token in Org', e);
        }
    }, []);

    const members = [
        { name: userEmail.split('@')[0], email: userEmail, role: 'Owner', status: 'Active' },
        { name: 'Alice Smith', email: 'alice@agency.com', role: 'Admin', status: 'Active' },
        { name: 'Bob Jones', email: 'bob@dev.com', role: 'Member', status: 'Pending' },
        { name: 'Eva Davis', email: 'eva@client.com', role: 'Viewer', status: 'Active' },
    ];

    return (
        <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500 h-full">
            <div className="flex justify-between items-center mb-6">
                <div>
                    <h2 className="text-2xl font-bold text-text-dark">Organization Management</h2>
                    <p className="text-slate-500">Manage your multi-tenant workspaces and RBAC</p>
                </div>
                <Button variant="outline" size="sm" className="font-bold text-sm border-slate-200">
                    + Invite Member
                </Button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="col-span-1 md:col-span-2 space-y-6">
                    <div className="bg-white border border-slate-100 rounded-3xl shadow-sm">
                        <div className="p-6 border-b border-slate-50 flex justify-between items-center">
                            <h3 className="text-lg font-bold text-text-dark">Active Members</h3>
                            <span className="px-3 py-1 bg-slate-50 text-slate-500 rounded-full text-xs border border-slate-100">4 / 10 Seats</span>
                        </div>
                        <div className="divide-y divide-slate-50">
                            {members.map((user, i) => (
                                <div key={i} className="p-5 flex items-center justify-between hover:bg-slate-50 transition-colors last:rounded-b-3xl relative" style={{ zIndex: 50 - i }}>
                                    <div className="flex items-center gap-4">
                                        <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center text-primary font-bold border border-primary/20">
                                            {user.name.charAt(0)}
                                        </div>
                                        <div>
                                            <div className="text-text-dark font-medium">{user.name}</div>
                                            <div className="text-xs text-slate-400">{user.email}</div>
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-4">
                                        <RoleDropdown currentRole={user.role} />
                                        <span className={`text-xs px-2 py-1 rounded-md bg-primary/10 text-primary font-bold`}>
                                            {user.status}
                                        </span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                <div className="col-span-1 space-y-6">
                    <div className="bg-white border border-slate-100 rounded-3xl p-6 shadow-sm">
                        <h3 className="text-lg font-bold text-text-dark mb-4">Roles & Permissions</h3>
                        <div className="space-y-4">
                            <div className="flex flex-col gap-1 p-3 rounded-xl bg-slate-50 border border-slate-100">
                                <div className="text-primary font-bold text-sm">Owner</div>
                                <div className="text-xs text-slate-500">Full access, billing, and org deletion.</div>
                            </div>
                            <div className="flex flex-col gap-1 p-3 rounded-xl bg-slate-50 border border-slate-100">
                                <div className="text-text-dark font-bold text-sm">Admin</div>
                                <div className="text-xs text-slate-500">Manage members, configure integrations.</div>
                            </div>
                            <div className="flex flex-col gap-1 p-3 rounded-xl bg-slate-50 border border-slate-100">
                                <div className="text-text-dark font-bold text-sm">Member</div>
                                <div className="text-xs text-slate-500">Start scans, view reports.</div>
                            </div>
                            <div className="flex flex-col gap-1 p-3 rounded-xl bg-slate-50 border border-slate-100">
                                <div className="text-text-dark font-bold text-sm">Viewer</div>
                                <div className="text-xs text-slate-500">View existing reports only.</div>
                            </div>
                        </div>
                    </div>

                    <div className="bg-white border border-slate-100 rounded-3xl p-6 shadow-sm">
                        <h3 className="text-lg font-bold text-text-dark mb-4">Audit Logs</h3>
                        <div className="space-y-3">
                            <div className="text-xs flex justify-between border-b border-slate-50 pb-2">
                                <span className="text-text-dark">Admin invited Bob</span>
                                <span className="text-slate-400">2h ago</span>
                            </div>
                            <div className="text-xs flex justify-between border-b border-slate-50 pb-2">
                                <span className="text-text-dark">Owner updated Billing</span>
                                <span className="text-slate-400">1d ago</span>
                            </div>
                            <div className="text-xs flex justify-between border-b border-slate-50 pb-2">
                                <span className="text-text-dark">API Key Rotated</span>
                                <span className="text-slate-400">2d ago</span>
                            </div>
                        </div>
                        <Button variant="custom" size="none" rounded="" display="" fontWeight="" className="w-full mt-4 text-xs text-primary font-bold hover:underline">View Full Logs →</Button>
                    </div>
                </div>
            </div>
        </div>
    );
}
