import { useState } from 'react';
import { Button } from '../../../components/ui/Button';

export default function ContactFormSection() {
    const [formData, setFormData] = useState({
        name: '',
        email: '',
        subject: '',
        message: ''
    });
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [submitSuccess, setSubmitSuccess] = useState(false);
    const [isDropdownOpen, setIsDropdownOpen] = useState(false);

    const subjectOptions = [
        { value: 'enterprise', label: 'Enterprise Sales' },
        { value: 'support', label: 'Technical Support' },
        { value: 'billing', label: 'Billing Inquiry' },
        { value: 'other', label: 'Other' }
    ];

    const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        setIsSubmitting(true);
        // Simulate API call
        setTimeout(() => {
            setIsSubmitting(false);
            setSubmitSuccess(true);
            setFormData({ name: '', email: '', subject: '', message: '' });
            setTimeout(() => setSubmitSuccess(false), 5000);
        }, 1500);
    };

    return (
        <div className="relative w-full max-w-xl mx-auto lg:mx-0 lg:ml-auto">
            <div className="relative bg-white border border-slate-100 rounded-[2rem] p-8 md:p-10 shadow-2xl">
                <h3 className="text-2xl font-bold text-text-dark mb-8">Send a Message</h3>
                <form onSubmit={handleSubmit} className="flex flex-col gap-6">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                        <div className="relative group">
                            <input
                                type="text"
                                id="name"
                                name="name"
                                required
                                value={formData.name}
                                onChange={handleChange}
                                className="block w-full px-0 py-3 text-text-dark bg-transparent border-0 border-b-2 border-slate-200 appearance-none focus:outline-none focus:ring-0 focus:border-primary peer relative z-10 [&:-webkit-autofill]:bg-white [&:-webkit-autofill]:[-webkit-text-fill-color:black] [&:-webkit-autofill]:transition-[background-color_5000s_ease-in-out_0s]"
                                placeholder=" "
                            />
                            <label htmlFor="name" className="absolute text-slate-400 duration-300 transform -translate-y-6 scale-90 top-3 z-0 origin-[0] peer-focus:left-0 peer-focus:text-primary peer-placeholder-shown:scale-100 peer-placeholder-shown:translate-y-0 peer-focus:scale-90 peer-focus:-translate-y-6">Full Name</label>
                        </div>
                        <div className="relative group">
                            <input
                                type="email"
                                id="email"
                                name="email"
                                required
                                value={formData.email}
                                onChange={handleChange}
                                className="block w-full px-0 py-3 text-text-dark bg-transparent border-0 border-b-2 border-slate-200 appearance-none focus:outline-none focus:ring-0 focus:border-primary peer relative z-10 [&:-webkit-autofill]:bg-white [&:-webkit-autofill]:[-webkit-text-fill-color:black] [&:-webkit-autofill]:transition-[background-color_5000s_ease-in-out_0s]"
                                placeholder=" "
                            />
                            <label htmlFor="email" className="absolute text-slate-400 duration-300 transform -translate-y-6 scale-90 top-3 z-0 origin-[0] peer-focus:left-0 peer-focus:text-primary peer-placeholder-shown:scale-100 peer-placeholder-shown:translate-y-0 peer-focus:scale-90 peer-focus:-translate-y-6">Email Address</label>
                        </div>
                    </div>

                    <div className="relative group mt-2 z-20">
                        <div
                            className="block w-full px-0 py-3 text-text-dark bg-transparent border-0 border-b-2 border-slate-200 cursor-pointer relative z-10"
                            onClick={() => setIsDropdownOpen(!isDropdownOpen)}
                        >
                            {formData.subject ? (
                                <span className="text-text-dark">{subjectOptions.find(o => o.value === formData.subject)?.label}</span>
                            ) : (
                                <span className="text-transparent select-none">.</span>
                            )}
                        </div>
                        <label
                            className={`absolute duration-300 transform origin-[0] pointer-events-none z-0 ${formData.subject || isDropdownOpen ? '-translate-y-6 scale-90 text-primary' : 'translate-y-3 scale-100 text-slate-400'} top-0`}
                        >
                            What can we help you with?
                        </label>
                        <div className="absolute right-0 top-4 pointer-events-none text-slate-300 z-10 transition-transform duration-300" style={{ transform: isDropdownOpen ? 'rotate(180deg)' : 'rotate(0)' }}>
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M6 9l6 6 6-6" /></svg>
                        </div>

                        {/* Dropdown Menu */}
                        {isDropdownOpen && (
                            <>
                                <div className="fixed inset-0 z-10" onClick={() => setIsDropdownOpen(false)}></div>
                                <div className="absolute left-0 right-0 top-full mt-2 bg-white border border-slate-100 rounded-xl shadow-2xl z-20 overflow-hidden animate-fadeIn">
                                    {subjectOptions.map((option) => (
                                        <div
                                            key={option.value}
                                            className="px-4 py-3 text-text-dark hover:bg-primary/10 hover:text-primary cursor-pointer transition-colors"
                                            onClick={() => {
                                                setFormData({ ...formData, subject: option.value });
                                                setIsDropdownOpen(false);
                                            }}
                                        >
                                            {option.label}
                                        </div>
                                    ))}
                                </div>
                            </>
                        )}
                    </div>

                    <div className="relative group mt-4 z-0">
                        <textarea
                            id="message"
                            name="message"
                            required
                            value={formData.message}
                            onChange={handleChange}
                            rows={4}
                            className="block w-full px-0 py-3 text-text-dark bg-transparent border-0 border-b-2 border-slate-200 appearance-none focus:outline-none focus:ring-0 focus:border-primary peer relative z-10 resize-none font-sans"
                            placeholder=" "
                        ></textarea>
                        <label htmlFor="message" className="absolute text-slate-400 duration-300 transform -translate-y-6 scale-90 top-3 z-0 origin-[0] peer-focus:left-0 peer-focus:text-primary peer-placeholder-shown:scale-100 peer-placeholder-shown:translate-y-0 peer-focus:scale-90 peer-focus:-translate-y-6">Write your message here...</label>
                    </div>

                    <Button
                        type="submit"
                        variant="custom"
                        fullWidth
                        disabled={isSubmitting}
                        className={`mt-6 py-4 justify-center tracking-wide bg-primary text-white border-none rounded-2xl transition-all duration-300 flex items-center gap-2 shadow-md hover:shadow-lg active:scale-95 ${isSubmitting ? 'opacity-70 cursor-not-allowed' : 'hover:-translate-y-1'}`}
                        text={isSubmitting ? "Sending..." : "Send Message"}
                        startIcon={
                            isSubmitting ? (
                                <svg className="animate-spin h-5 w-5 mr-3" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                </svg>
                            ) : undefined
                        }
                    />

                    {submitSuccess && (
                        <div className="mt-4 p-4 rounded-xl bg-primary/10 border border-primary/20 text-primary text-center font-bold animate-fadeIn">
                            Message sent successfully. We'll be in touch soon.
                        </div>
                    )}
                </form>
            </div>
        </div>
    );
}
