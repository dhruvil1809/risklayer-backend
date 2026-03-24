import React, { forwardRef } from 'react';
import { useNavigate } from 'react-router-dom';

export type ButtonVariant = 'primary' | 'secondary' | 'outline' | 'glass' | 'custom' | string;
export type ButtonSize = 'sm' | 'md' | 'lg' | string;

const getControl = (control: ButtonVariant) => {
    switch (control) {
        case 'primary':
            return 'bg-primary text-white border-none shadow-lg shadow-primary/20 hover:bg-primary-hover hover:scale-95 active:scale-95';
        case 'secondary':
            return 'bg-secondary text-white border-none shadow-lg shadow-secondary/20 hover:bg-secondary-hover hover:scale-95 active:scale-95';
        case 'outline':
            return 'text-primary border border-primary/20 bg-primary/10 hover:bg-primary/10 hover:border-primary/40 backdrop-blur-sm';
        case 'glass':
            return 'bg-glass-bg border border-glass-border text-white hover:bg-white/10 hover:border-white/20';
        case 'highlight':
            return 'bg-highlight text-text-dark border-none shadow-lg shadow-highlight/20 hover:brightness-110 hover:-translate-y-0.5';
        case 'custom':
            return '';
        default:
            return 'text-primary bg-primary/10 hover:bg-primary/20 border border-primary/20';
    }
};

const getSize = (size: ButtonSize) => {
    switch (size) {
        case 'sm':
            return 'py-2 px-4 text-sm';
        case 'md':
            return 'py-3.5 px-6 text-sm';
        case 'lg':
            return 'py-4 px-8 text-sm md:text-base';
        default:
            return '';
    }
};

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
    control?: ButtonVariant;
    variant?: ButtonVariant;
    size?: ButtonSize;
    isLink?: boolean;
    url?: string;
    text?: string | React.ReactNode;
    startIcon?: React.ReactNode;
    endIcon?: React.ReactNode;
    fontSize?: string;
    fontWeight?: string;
    display?: string;
    rounded?: string;
    fullWidth?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>((props, ref) => {
    // Merge props with default values
    const {
        control,
        variant = 'primary',
        size = 'md',
        isLink = false,
        type = 'button',
        text,
        children,
        url = '/',
        startIcon,
        endIcon,
        fontSize = '',
        fontWeight = 'font-bold',
        display = 'inline-flex items-center justify-center',
        rounded = 'rounded-xl',
        className = '',
        fullWidth = false,
        onClick,
        disabled = false,
        ...rest
    } = props;

    const navigate = useNavigate();

    // Support either standard 'variant' prop or 'control' prop (from reference)
    const activeControl = control || variant;
    const designButton = getControl(activeControl);
    const sizeButton = getSize(size);
    const widthStyle = fullWidth ? 'w-full' : '';

    const baseStyles = 'transition-all duration-300 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed active:scale-[0.97] gap-2';

    // Combine all structural and decorative classes
    const finalClassName = `${display} ${fontWeight} ${baseStyles} ${designButton} ${sizeButton} ${rounded} ${fontSize} ${widthStyle} ${className}`.replace(/\s+/g, ' ').trim();

    // Setup action handler for both normal clicks and routing links
    const handleAction = (e: React.MouseEvent<HTMLButtonElement, MouseEvent>) => {
        if (onClick) onClick(e);
        if (isLink && !disabled) {
            navigate(url);
        }
    };

    // Construct button payload securely handling icons alongside text/children
    const content = (
        <>
            {startIcon && <span className="flex items-center shrink-0">{startIcon}</span>}
            {text || children}
            {endIcon && <span className="flex items-center shrink-0">{endIcon}</span>}
        </>
    );

    return (
        <button
            ref={ref}
            disabled={disabled}
            type={type}
            className={finalClassName}
            onClick={handleAction}
            {...rest}
        >
            {content}
        </button>
    );
});

Button.displayName = 'Button';
export default Button;
