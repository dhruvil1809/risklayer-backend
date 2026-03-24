import PricingHeroSection from './components/PricingHeroSection';
import PricingTiersSection from './components/PricingTiersSection';
import FaqSection from './components/FaqSection';

function PricingPage() {
    return (
        <div className="flex flex-col items-center pt-24 pb-16 px-[5%] w-full relative overflow-hidden">
            <PricingHeroSection />
            <PricingTiersSection />
            <FaqSection />
        </div>
    );
}

export default PricingPage;
