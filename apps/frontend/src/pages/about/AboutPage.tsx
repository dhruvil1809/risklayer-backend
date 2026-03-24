import AboutHeroSection from './components/AboutHeroSection';
import ProblemSection from './components/ProblemSection';
import SolutionSection from './components/SolutionSection';
import TechnologyProfileSection from './components/TechnologyProfileSection';
import StatsSection from './components/StatsSection';
import CtaSection from '../../components/CtaSection';

function AboutPage() {
    return (
        <div className="flex flex-col items-center w-full">
            <AboutHeroSection />
            <ProblemSection />
            <SolutionSection />
            <TechnologyProfileSection />
            <StatsSection />
            <div className="px-[5%] w-full flex justify-center">
                <CtaSection href="/" />
            </div>
        </div>
    );
}

export default AboutPage;
