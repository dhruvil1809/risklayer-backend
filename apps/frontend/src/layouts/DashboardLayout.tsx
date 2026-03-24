import { Outlet } from 'react-router-dom';
import Header from '../components/Header';
import CookieConsent from '../components/CookieConsent';

export default function DashboardLayout() {
    return (
        <div className="min-h-screen flex flex-col bg-[#07090f] text-text-main relative font-sans">
            {/* Dashboard Header (we can pass a prop to make it dashboard-specific) */}
            <Header isDashboard={true} />

            {/* Page Content */}
            <main className="flex-1 flex flex-col relative z-10 w-full overflow-y-auto">
                <Outlet />
            </main>

            {/* No Footer here! */}
            <CookieConsent />
        </div>
    );
}
