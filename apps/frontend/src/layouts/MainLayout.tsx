import { Outlet } from 'react-router-dom';
import Header from '../components/Header';
import Footer from '../components/Footer';
import CookieConsent from '../components/CookieConsent';

export default function MainLayout() {
    return (
        <div className="min-h-screen flex flex-col bg-bg-dark text-text-main relative font-sans">
            {/* Background Layer */}
            <div className="bg-grid-effect-sides opacity-60"></div>

            {/* Navigation */}
            <Header />

            {/* Page Content */}
            <main className="flex-1 flex flex-col relative z-10 w-full">
                <Outlet />
            </main>

            {/* Footer */}
            <Footer />

            <CookieConsent />
        </div>
    );
}
