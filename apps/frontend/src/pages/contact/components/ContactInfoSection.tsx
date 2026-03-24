export default function ContactInfoSection() {
    return (
        <div className="flex flex-col pt-4">
            <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight mb-6 text-text-dark">
                Let's talk.
            </h1>
            <p className="text-sm md:text-xl text-slate-500 mb-16 leading-relaxed max-w-lg">
                Whether you're interested in enterprise plans, need a custom compliance audit, or just want to say hello, we're ready to listen.
            </p>

            <div className="flex flex-col gap-10">
                <div className="flex items-start gap-5 group cursor-default">
                    <div className="w-14 h-14 rounded-full bg-slate-50 border border-slate-100 flex items-center justify-center text-primary transition-all duration-300 group-hover:bg-primary group-hover:text-white group-hover:scale-110 shadow-sm">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" /><polyline points="22,6 12,13 2,6" /></svg>
                    </div>
                    <div className="flex flex-col justify-center">
                        <div className="text-sm text-slate-400 uppercase tracking-wider font-semibold mb-1">Email Us</div>
                        <a href="mailto:hello@risklayer.example.com" className="text-sm text-text-dark font-bold hover:text-primary transition-colors">hello@risklayer.example.com</a>
                    </div>
                </div>

                <div className="flex items-start gap-5 group cursor-default">
                    <div className="w-14 h-14 rounded-full bg-slate-50 border border-slate-100 flex items-center justify-center text-primary transition-all duration-300 group-hover:bg-primary group-hover:text-white group-hover:scale-110 shadow-sm">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z" /><circle cx="12" cy="10" r="3" /></svg>
                    </div>
                    <div className="flex flex-col justify-center">
                        <div className="text-sm text-slate-400 uppercase tracking-wider font-semibold mb-1">Visit Us</div>
                        <address className="text-sm text-text-dark font-bold not-italic leading-relaxed">
                            123 Tech Boulevard<br />
                            San Francisco, CA 94107
                        </address>
                    </div>
                </div>
            </div>
        </div>
    );
}
