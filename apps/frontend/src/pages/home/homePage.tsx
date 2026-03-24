import { useState } from 'react';
import ScanModal from '../../components/ScanModal';
import HeroSection from './components/HeroSection';
import FeaturesSection from './components/FeaturesSection';
import HowItWorksSection from './components/HowItWorksSection';
import ComplianceRealitySection from './components/ComplianceRealitySection';
import CtaSection from '../../components/CtaSection';

function HomePage() {
    const [url, setUrl] = useState('');
    const [isModalOpen, setIsModalOpen] = useState(false);

    const handleScanClick = () => {
        if (!url) {
            window.scrollTo({ top: 0, behavior: 'smooth' });
            setTimeout(() => {
                document.getElementById('hero-url-input')?.focus();
            }, 600);
            return;
        }
        setIsModalOpen(true);
    };

    return (
        <>
            <HeroSection url={url} setUrl={setUrl} onScan={handleScanClick} />
            <FeaturesSection />
            <HowItWorksSection />
            <ComplianceRealitySection />
            <CtaSection onScanClick={handleScanClick} />

            {/* Start Flow Modal */}
            <ScanModal
                isOpen={isModalOpen}
                onClose={() => setIsModalOpen(false)}
                url={url}
            />
        </>
    );
}

export default HomePage;
