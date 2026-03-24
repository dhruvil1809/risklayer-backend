import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { Button } from './ui/Button';

interface HeaderProps {
    isDashboard?: boolean;
}

const Header = ({ isDashboard }: HeaderProps) => {
    const navigate = useNavigate();
    const location = useLocation();
    const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
    const [dropdownOpen, setDropdownOpen] = useState(false);
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [userEmail, setUserEmail] = useState('User');

    useEffect(() => {
        const token = localStorage.getItem('token') || localStorage.getItem('accessToken');
        setIsAuthenticated(!!token);
        
        if (token) {
            try {
                const payload = JSON.parse(atob(token.split('.')[1]));
                if (payload && payload.email) {
                    setUserEmail(payload.email);
                }
            } catch (e) {
                console.error('Failed to parse token in Header', e);
            }
        }
    }, [location.pathname]); // Re-check on path change to stay in sync

    const handleLogout = () => {
        localStorage.removeItem('token');
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        setIsAuthenticated(false);
        navigate('/login');
    };

    // Close the mobile menu automatically if the route changes
    useEffect(() => {
        setMobileMenuOpen(false);
    }, [location.pathname]);

    return (
        <header className="sticky top-0 z-[100] w-full transition-all duration-300 py-2 md:py-3 backdrop-blur-md bg-white/95 border-b border-slate-100 shadow-[0_2px_15px_-3px_rgba(0,0,0,0.07)]">
            <div className="max-w-[1440px] mx-auto px-6 lg:px-12 flex items-center justify-between">

                {/* Logo - Start */}
                <div className="flex-1 flex justify-start">
                    <Link
                        to="/"
                        onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
                        className="flex items-center gap-2 md:gap-2.5 text-xl md:text-2xl font-bold tracking-tight text-text-dark no-underline group"
                    >
                        <div className="w-8 h-8 md:w-9 md:h-9 flex items-center justify-center bg-primary rounded-lg md:rounded-xl text-white shadow-lg shadow-primary/20 transition-transform group-hover:scale-105">
                            <svg className="w-5 h-5 md:w-6 md:h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                            </svg>
                        </div>
                        <span className="bg-gradient-to-r from-text-dark to-slate-700 bg-clip-text">RiskLayer</span>
                    </Link>
                </div>

                {/* Desktop Nav - Center */}
                {!isDashboard && (
                    <nav className="hidden lg:flex items-center gap-8 xl:gap-10">
                        {[
                            { name: 'About', path: '/about' },
                            { name: 'Features', path: '/features' },
                            { name: 'Pricing', path: '/pricing' },
                            { name: 'Contact', path: '/contact' }
                        ].map((item) => (
                            <Link
                                key={item.name}
                                to={item.path}
                                onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
                                className="text-[15px] font-semibold text-slate-600 transition-all hover:text-primary relative group py-2"
                            >
                                {item.name}
                                <span className="absolute bottom-0 left-0 w-0 h-0.5 bg-primary transition-all duration-300 group-hover:w-full"></span>
                            </Link>
                        ))}
                    </nav>
                )}

                {/* Actions - End */}
                <div className="flex-1 flex justify-end items-center gap-5">
                    {isAuthenticated ? (
                        <div className="relative hidden lg:block">
                            <button
                                onClick={() => setDropdownOpen(!dropdownOpen)}
                                className="flex items-center gap-3.5 px-1 py-1 group transition-all duration-300"
                                onBlur={() => setTimeout(() => setDropdownOpen(false), 200)}
                            >
                                <div className="hidden sm:flex flex-col items-end text-right">
                                    <div className="text-[15px] font-bold text-text-dark leading-tight">{userEmail.split('@')[0]}</div>
                                    <div className="text-[13px] font-bold text-primary leading-tight mt-0.5">Verified Account</div>
                                </div>
                                <div className="w-10 h-10 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center text-primary font-bold uppercase shrink-0">
                                    {userEmail.charAt(0)}
                                </div>
                            </button>

                            {dropdownOpen && (
                                <div className="absolute right-0 mt-3 w-64 bg-white border border-slate-100 rounded-2xl shadow-[0_20px_50px_-12px_rgba(0,0,0,0.12)] py-2 z-50 overflow-hidden animate-in fade-in slide-in-from-top-2 duration-200">
                                    <div className="px-5 py-4 border-b border-slate-50 mb-1 font-bold">
                                        <div className="text-text-dark font-black text-sm tracking-tight">{userEmail}</div>
                                        <div className="text-slate-400 text-[10px] font-bold uppercase tracking-widest mt-0.5">Your Account</div>
                                    </div>
                                    <button
                                        onClick={() => navigate('/dashboard')}
                                        className="w-full text-left px-5 py-3 text-sm text-slate-600 hover:text-primary hover:bg-slate-50 transition-all flex items-center gap-3 font-bold"
                                    >
                                        <svg className="w-4 h-4 text-slate-400 font-bold" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                                            <rect x="3" y="3" width="7" height="7"></rect>
                                            <rect x="14" y="3" width="7" height="7"></rect>
                                            <rect x="14" y="14" width="7" height="7"></rect>
                                            <rect x="3" y="14" width="7" height="7"></rect>
                                        </svg>
                                        Dashboard
                                    </button>
                                    <button
                                        onClick={handleLogout}
                                        className="w-full text-left px-5 py-3 text-sm text-red-500 hover:bg-red-50 transition-colors flex items-center gap-3 font-semibold border-t border-slate-50 mt-1"
                                    >
                                        <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                                            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
                                            <polyline points="16 17 21 12 16 7"></polyline>
                                            <line x1="21" y1="12" x2="9" y2="12"></line>
                                        </svg>
                                        Sign Out
                                    </button>
                                </div>
                            )}
                        </div>
                    ) : (
                        <div className="hidden lg:flex items-center gap-3">
                            <Link
                                to="/login"
                                className="text-[15px] font-semibold text-slate-600 hover:text-primary px-5 py-2.5 transition-colors"
                            >
                                Log In
                            </Link>
                            <Button
                                isLink
                                url="/login"
                                variant="primary"
                                className="rounded-full px-7 py-2.5 text-[15px] font-bold shadow-lg shadow-primary/20 border-none h-auto"
                                text="Start Audit Free"
                            />
                        </div>
                    )}

                    {/* Mobile menu trigger */}
                    <div className="lg:hidden">
                        <button
                            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                            className="p-2 text-slate-600 hover:bg-slate-50 rounded-lg transition-colors"
                        >
                            {mobileMenuOpen ? (
                                <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M6 18L18 6M6 6l12 12" />
                                </svg>
                            ) : (
                                <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M4 6h16M4 12h16M4 18h16" />
                                </svg>
                            )}
                        </button>
                    </div>
                </div>
            </div>

            {/* Mobile Menu */}
            <div className={`absolute top-full left-0 w-full bg-white border-b border-slate-100 transition-all duration-300 lg:hidden flex flex-col overflow-hidden shadow-2xl ${mobileMenuOpen ? 'max-h-[60vh] opacity-100 py-6' : 'max-h-0 opacity-0 py-0'}`}>
                <div className="px-8 flex flex-col gap-1">
                    {['About', 'Features', 'Pricing', 'Contact'].map((item) => (
                        <Link
                            key={item}
                            to={`/${item.toLowerCase().replace(' ', '-')}`}
                            className="py-4 text-base font-bold text-slate-700 hover:text-primary transition-colors flex items-center justify-between group"
                            onClick={() => setMobileMenuOpen(false)}
                        >
                            {item}
                            <svg className="w-5 h-5 opacity-0 group-hover:opacity-100 transition-opacity" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M9 5l7 7-7 7" />
                            </svg>
                        </Link>
                    ))}
                    {isAuthenticated ? (
                        <div className="mt-6 flex flex-col gap-1 py-4 border-t border-slate-50">
                            <Link
                                to="/dashboard"
                                className="py-4 text-base font-bold text-slate-700 hover:text-primary transition-colors flex items-center justify-between group"
                                onClick={() => setMobileMenuOpen(false)}
                            >
                                Dashboard
                                <svg className="w-5 h-5 opacity-0 group-hover:opacity-100 transition-opacity" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M9 5l7 7-7 7" />
                                </svg>
                            </Link>
                            <button
                                onClick={() => {
                                    handleLogout();
                                    setMobileMenuOpen(false);
                                }}
                                className="py-4 text-base font-bold text-red-500 hover:text-red-600 transition-colors flex items-center justify-between group text-left w-full"
                            >
                                Sign Out
                                <svg className="w-5 h-5 opacity-0 group-hover:opacity-100 transition-opacity" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M9 5l7 7-7 7" />
                                </svg>
                            </button>
                        </div>
                    ) : (
                        <div className="mt-6 flex flex-col gap-3 py-4 border-t border-slate-50">
                            <Button isLink url="/login" variant="primary" fullWidth text="Get Started" className="py-4 rounded-xl font-bold shadow-xl shadow-primary/10" />
                            <Button isLink url="/login" variant="outline" fullWidth text="Member Login" className="py-4 rounded-xl font-bold border-slate-200 text-slate-600" />
                        </div>
                    )}
                </div>
            </div>
        </header>
    );
};

export default Header;