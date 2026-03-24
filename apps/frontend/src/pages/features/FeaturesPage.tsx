import FeaturesHeroSection from './components/FeaturesHeroSection';
import LegalComplianceSection from './components/LegalComplianceSection';
import A11yStructureSection from './components/A11yStructureSection';
import ContinuousMonitoringSection from './components/ContinuousMonitoringSection';
import CtaSection from '../../components/CtaSection';

function FeaturesPage() {
    return (
        <div className="flex flex-col items-center pt-24 pb-16 px-[5%] w-full relative overflow-hidden">
            <FeaturesHeroSection />
            <LegalComplianceSection />
            <A11yStructureSection />
            <ContinuousMonitoringSection />
            <CtaSection href="/" />
        </div>
    );
}

export default FeaturesPage;
