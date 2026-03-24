import { Link } from 'react-router-dom';
import { Linkedin, Youtube, Instagram } from 'lucide-react';

const FooterLink = ({ to, children }: { to: string; children: React.ReactNode }) => {
    return (
        <li>
            <Link
                to={to}
                className="text-slate-500 text-sm font-semibold hover:text-primary transition-all duration-300"
                onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
            >
                {children}
            </Link>
        </li>
    );
};

const Footer = () => {
    const currentYear = new Date().getFullYear();

    const scrollToTop = () => {
        window.scrollTo({ top: 0, behavior: 'smooth' });
    };

    return (
        <footer className="relative z-10 pt-20 md:pt-32 pb-12 md:pb-16 bg-white overflow-hidden border-t border-slate-100">
            {/* Links Grid */}
            <div className="max-w-[1400px] mx-auto px-6 md:px-12 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-12 md:gap-16 mb-16 md:mb-24">
                <div className="col-span-1 sm:col-span-2 lg:col-span-2">
                    <Link to="/" onClick={scrollToTop} className="text-2xl md:text-3xl font-black tracking-tighter flex items-center gap-2 text-text-dark no-underline mb-6 md:mb-8 hover:no-underline group">
                        <div className="w-8 h-8 md:w-9 md:h-9 flex items-center justify-center bg-primary rounded-lg md:rounded-xl text-white shadow-lg shadow-primary/20 transition-transform group-hover:scale-110">
                            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                            </svg>
                        </div>
                        RiskLayer
                    </Link>
                    <p className="text-slate-500 text-base md:text-lg font-medium leading-relaxed max-w-sm mb-10">
                        The world's most advanced AI-powered compliance scanner. Secure your digital assets with automated risk analysis.
                    </p>
                    <div className="flex gap-4">
                        {[
                            { icon: <Linkedin size={20} />, label: 'LinkedIn', href: '#' },
                            { icon: <Youtube size={20} />, label: 'YouTube', href: '#' },
                            { icon: <Instagram size={20} />, label: 'Instagram', href: '#' }
                        ].map((social, idx) => (
                            <a key={idx} href={social.href} className="w-11 h-11 md:w-12 md:h-12 rounded-xl md:rounded-2xl bg-slate-50 flex items-center justify-center text-slate-400 hover:bg-primary/5 hover:text-primary transition-all border border-slate-100 group">
                                <span className="sr-only">{social.label}</span>
                                <div className="transition-transform duration-300 group-hover:scale-110">
                                    {social.icon}
                                </div>
                            </a>
                        ))}
                    </div>
                </div>

                <div className="sm:col-span-1">
                    <h4 className="text-text-dark font-black uppercase tracking-widest text-[11px] md:text-xs mb-6 md:mb-8">Solution</h4>
                    <ul className="space-y-3 md:space-y-4">
                        <FooterLink to="/features">Features</FooterLink>
                        <FooterLink to="/compliance">Compliance</FooterLink>
                        <FooterLink to="/api">API Access</FooterLink>
                        <FooterLink to="/pricing">Pricing</FooterLink>
                    </ul>
                </div>

                <div className="sm:col-span-1">
                    <h4 className="text-text-dark font-black uppercase tracking-widest text-[11px] md:text-xs mb-6 md:mb-8">Company</h4>
                    <ul className="space-y-3 md:space-y-4">
                        <FooterLink to="/about">About Us</FooterLink>
                        <FooterLink to="/blog">Our Blog</FooterLink>
                        <FooterLink to="/careers">Careers</FooterLink>
                        <FooterLink to="/contact">Contact</FooterLink>
                    </ul>
                </div>

                <div className="sm:col-span-1">
                    <h4 className="text-text-dark font-black uppercase tracking-widest text-[11px] md:text-xs mb-6 md:mb-8">Support</h4>
                    <ul className="space-y-3 md:space-y-4">
                        <FooterLink to="/help">Help Center</FooterLink>
                        <FooterLink to="/docs">Documentation</FooterLink>
                        <FooterLink to="/status">System Status</FooterLink>
                        <FooterLink to="/security">Security</FooterLink>
                    </ul>
                </div>
            </div>

            {/* Bottom Bar */}
            <div className="max-w-[1400px] mx-auto px-6 md:px-12 pt-8 md:pt-12 border-t border-slate-100 flex flex-col md:flex-row items-center justify-between gap-6 md:gap-8 text-center md:text-left">
                <p className="text-slate-500 text-[13px] md:text-sm font-medium">
                    &copy; {currentYear} RiskLayer. Built with advanced AI for global compliance.
                </p>
                <div className="flex flex-wrap justify-center gap-6 md:gap-8">
                    <Link to="/terms" className="text-slate-400 text-[11px] md:text-xs font-black tracking-widest hover:text-primary transition-colors uppercase">TERMS</Link>
                    <Link to="/privacy" className="text-slate-400 text-[11px] md:text-xs font-black tracking-widest hover:text-primary transition-colors uppercase">PRIVACY</Link>
                    <Link to="/cookies" className="text-slate-400 text-[11px] md:text-xs font-black tracking-widest hover:text-primary transition-colors uppercase">COOKIES</Link>
                </div>
            </div>
        </footer>
    );
};

export default Footer;
