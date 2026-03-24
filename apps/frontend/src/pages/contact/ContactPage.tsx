import ContactInfoSection from './components/ContactInfoSection';
import ContactFormSection from './components/ContactFormSection';

function ContactPage() {
    return (
        <div className="pt-32 pb-32 relative z-10 w-full overflow-hidden">
            <div className="max-w-[1280px] mx-auto px-[5%]">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 lg:gap-24 items-start">
                    <ContactInfoSection />
                    <ContactFormSection />
                </div>
            </div>
        </div>
    );
}

export default ContactPage;
