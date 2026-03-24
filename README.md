# RiskLayer — AI-Powered Website Compliance & Risk Scanner

**RiskLayer** is a professional-grade SaaS platform that performs deep security, compliance, and structural audits of websites. It combines **deterministic crawling** (Playwright) with **generative AI analysis** (Claude 3.5 Sonnet) to provide actionable risk reports.

---

## 🚀 Key Features

-   **Deep Crawling Engine**: Uses Playwright to audit up to 20 pages per domain with a depth of 2.
-   **AI-Driven Risk Reports**: Leverages Anthropic's Claude 3.5 Sonnet to interpret technical signals into human-readable executive summaries and priority checklists.
-   **SSRF Protection**: Hardened security layer to prevent Server-Side Request Forgery using DNS-level IP filtering.
-   **6-Point Analysis**:
    -   🔒 **Security**: Header analysis (CSP, HSTS, etc.) and form safety.
    -   ⚖️ **Compliance**: GDPR/CCPA privacy and terms detection.
    -   🤝 **Trust**: SSL/HTTPS and structural professionalisms.
    -   🔎 **SEO**: Meta data, title hierarchy, and crawlability.
    -   ⚡ **Performance**: Page weight and render-blocking resources.
    -   ♿ **Accessibility**: ARIA labels, image alt text, and form accessibility.
-   **Professional Dashboard**: Stunning visualization of risk scores, findings, and technical discovery logs.
-   **OTP Authentication**: Secure login flow using magic codes sent via email.

---

## 🛠️ Tech Stack

-   **Monorepo**: npm workspaces
-   **Backend**: Node.js, Express, TypeScript, Prisma (PostgreSQL), Winston (Logging)
-   **Frontend**: React 18+ (Vite), Tailwind CSS, Lucide Icons, Axios
-   **Intelligence**: Anthropic Claude 3.5 Sonnet API
-   **Crawling**: Playwright (Headless Chromium)

---

## 📦 Getting Started

### Prerequisites

-   **Node.js**: v18 or higher
-   **Database**: PostgreSQL instance
-   **AI Key**: Anthropic API Key (Claude)

### Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/risklayer.git
    cd risklayer
    ```

2.  **Install dependencies** (from the root):
    ```bash
    npm install
    npx playwright install chromium
    ```

3.  **Environment Setup**:
    Create a `.env` file in the **root** directory and copy the contents from `.env.example` (or use the following):
    ```env
    # Database
    DATABASE_URL="postgresql://user:password@localhost:5432/risklayer"

    # AI (Anthropic)
    ANTHROPIC_API_KEY="sk-ant-..."

    # Email (Nodemailer for OTPs)
    EMAIL_USER="your-email@gmail.com"
    EMAIL_PASS="your-app-password"

    # ReCaptcha
    VITE_RECAPTCHA_SITE_KEY="..."
    RECAPTCHA_SECRET_KEY="..."

    # App Config
    PORT=5000
    NODE_ENV="development"
    ```

4.  **Database Migration**:
    ```bash
    cd apps/backend
    npx prisma migrate dev
    ```

---

## 🏃 Running the App

### Development Mode
Runs both frontend and backend concurrently:
```bash
npm run dev
```

### Individual Workspaces
```bash
# Backend only
npm run dev:backend

# Frontend only
npm run dev:frontend
```

---

## 📂 Project Structure

-   `apps/backend/`: Express API, Prisma schemas, and core Scanning services.
-   `apps/frontend/`: React application and Tailwind UI.
-   `configuration/`: Global project configs (ESLint, Prettier).

---

## 🛡️ Security & Hard Limits

To maintain cost control and performance, the following rules are enforced:
-   **Max Pages**: 20 per scan.
-   **Max Depth**: 2 (Home -> Link -> Link).
-   **Timeouts**: 8s per page / 90s total crawl limit.
-   **SSRF**: Blocks all private/internal IP ranges (loopback, link-local, private LAN).

---

## 📄 License

Copyright © 2026 RiskLayer. All rights reserved.
