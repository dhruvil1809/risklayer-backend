import { useState } from 'react';
import { Button } from '../../../components/ui/Button';

export default function FaqSection() {
    const [openFaq, setOpenFaq] = useState<number | null>(0);

    const faqs = [
        {
            question: "What exactly does the FREE scan provide?",
            answer: "The free scan provides your overall score and identifies your top 5 most critical issues across accessibility and compliance. You won't see the full AI explanations or entirely deep-crawled subpages until you upgrade."
        },
        {
            question: "Are there discounts for annual agency billing?",
            answer: "Yes! If you choose to be billed annually on the Agency or Pro tiers, you receive 2 months completely free (roughly a 17% overall discount)."
        },
        {
            question: "Can I cancel my subscription at any time?",
            answer: "Yes, you can upgrade, downgrade, or cancel your subscription at any time from your billing dashboard. Cancellations take effect at the end of your current billing cycle."
        },
        {
            question: "How do 'client isolating workspaces' function?",
            answer: "Workspaces allow you to group individual reports under specific client profiles. You can generate PDF exports branded to that specific workspace without mixing client data."
        }
    ];

    const toggleFaq = (index: number) => {
        setOpenFaq(openFaq === index ? null : index);
    };

    return (
        <div className="max-w-[800px] w-full mb-16 relative z-10 text-left">
            <h2 className="text-3xl font-extrabold mb-10 pb-4 border-b border-slate-100 text-center text-text-dark">Frequently Asked Questions</h2>

            <div className="flex flex-col gap-4">
                {faqs.map((faq, index) => (
                    <div
                        key={index}
                        className={`bg-white border rounded-2xl overflow-hidden transition-all duration-300 ${openFaq === index ? 'border-primary/50 shadow-lg' : 'border-slate-100 hover:border-slate-200 cursor-pointer shadow-sm'}`}
                    >
                        <Button
                            variant="custom" size="none" display="" rounded="" fontWeight=""
                            className="w-full text-left p-6 flex justify-between items-center focus:outline-none"
                            onClick={() => toggleFaq(index)}
                        >
                            <span className={`font-bold text-sm transition-colors ${openFaq === index ? 'text-primary' : 'text-text-dark'}`}>
                                {faq.question}
                            </span>
                            <div className={`w-8 h-8 rounded-full flex items-center justify-center border transition-all duration-300 ${openFaq === index ? 'bg-primary/10 border-primary/30 text-primary rotate-45' : 'bg-slate-50 border-slate-100 text-slate-400 hover:bg-slate-100 hover:text-text-dark'}`}>
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                                    <line x1="12" y1="5" x2="12" y2="19"></line>
                                    <line x1="5" y1="12" x2="19" y2="12"></line>
                                </svg>
                            </div>
                        </Button>

                        <div
                            className={`transition-all duration-300 ease-in-out ${openFaq === index ? 'max-h-[200px] opacity-100' : 'max-h-0 opacity-0 overflow-hidden'}`}
                        >
                            <div className="p-6 pt-0 text-slate-500 text-sm leading-relaxed border-t border-slate-50 mt-2">
                                {faq.answer}
                            </div>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}
