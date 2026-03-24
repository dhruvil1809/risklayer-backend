import db from "../config/db";
import { logger } from "../utils/logger";
import { randomUUID } from "node:crypto";
import { generateExecutiveSummary as getAiSummary } from "./aiService";


/**
 * Deterministic Rule Engine
 * ─────────────────────────────────────────────────────────────────
 * Implemented as a pure rule-based system for high-speed, accurate,
 * and evidence-backed risk reporting (Sprint 2 & 3).
 */

const MASTER_RULES = [
    // Accessibility
    { rule_id: "ACC-MISSING-ALT", category: "accessibility", title: "missing alt attributes" },
    { rule_id: "ACC-EMPTY-ALT", category: "accessibility", title: "image alt empty" },
    { rule_id: "ACC-MISSING-LABEL-TAGS", category: "accessibility", title: "missing label tags" },
    { rule_id: "ACC-HTML-LANG-MISSING", category: "accessibility", title: "missing html lang" },
    { rule_id: "ACC-HEADING-ORDER", category: "accessibility", title: "heading order issues" },
    { rule_id: "ACC-FORM-LABELS-MISSING", category: "accessibility", title: "missing form labels" },
    { rule_id: "ACC-TITLE-MISSING", category: "accessibility", title: "missing title tag" },
    { rule_id: "ACC-EMPTY-ANCHORS", category: "accessibility", title: "Links have empty anchor text" },
    { rule_id: "ACC-ARIA-MISSING", category: "accessibility", title: "ARIA attributes missing" },
    { rule_id: "ACC-SKIP-LINK-MISSING", category: "accessibility", title: "Skip link missing" },
    
    // Compliance
    { rule_id: "COM-PRIVACY-MISSING", category: "compliance", title: "Missing Privacy Policy" },
    { rule_id: "COM-TOS-MISSING", category: "compliance", title: "Missing Terms of Service" },
    { rule_id: "COM-CONTACT-MISSING", category: "compliance", title: "Missing Contact Page" },
    { rule_id: "COM-IDENTITY-MISSING", category: "compliance", title: "Business Identity Missing" },
    
    // Trust
    { rule_id: "TRU-SSL-MISSING", category: "trust", title: "SSL Security Missing" },
    { rule_id: "TRU-META-DESC-MISSING", category: "trust", title: "Meta Description Missing" },
    { rule_id: "TRU-MIXED-CONTENT", category: "trust", title: "Mixed Content" },
    { rule_id: "TRU-SCRIPT-OVERLOAD", category: "trust", title: "Script Overload" },
    { rule_id: "TRU-META-DESC-LENGTH", category: "trust", title: "Meta description length" },
    { rule_id: "TRU-MULTIPLE-DESCRIPTIONS", category: "trust", title: "Multiple meta descriptions" },
    { rule_id: "TRU-NO-SOCIAL-LINKS", category: "trust", title: "No social media links" },
    
    // Structure
    { rule_id: "STR-H1-DUPLICATE", category: "structure", title: "Multiple H1 tags" },
    { rule_id: "STR-H1-MISSING", category: "structure", title: "Missing H1 tag" },
    { rule_id: "STR-TITLE-LENGTH", category: "structure", title: "Title length" },
    { rule_id: "STR-IMG-DIMS-MISSING", category: "structure", title: "Missing image dimensions" },
    { rule_id: "STR-IMG-NEXTGEN", category: "structure", title: "Next-gen image formats" },
    { rule_id: "STR-H1-TAGS-INSIDE", category: "structure", title: "H1 has other tags inside" },
    { rule_id: "STR-H2-TAGS-INSIDE", category: "structure", title: "H2 has other tags inside" },
    { rule_id: "STR-CANONICAL-MISMATCH", category: "structure", title: "Canonical mismatch" },
    { rule_id: "STR-INLINE-STYLES", category: "structure", title: "Inline styles used" },
    { rule_id: "STR-GTM-MISSING", category: "structure", title: "Missing GTM" },
    { rule_id: "STR-H2-MISSING", category: "structure", title: "Missing H2 tags" },
    { rule_id: "STR-IDENTICAL-HEADINGS", category: "structure", title: "Identical headings" },
    { rule_id: "STR-IDENTICAL-ALT-TAGS", category: "structure", title: "Identical alt tags" },
    { rule_id: "STR-NO-STRONG-ELEMENTS", category: "structure", title: "No strong importance elements" },
    { rule_id: "STR-TITLE-DUPLICATE", category: "structure", title: "Duplicate Titles" },
    { rule_id: "STR-ROBOTS-MISSING", category: "structure", title: "Missing robots.txt" },
    { rule_id: "STR-BROKEN-LINKS", category: "structure", title: "Broken Links" },

    // Security Headers (Hybrid Agent)
    { rule_id: "SEC-CSP-MISSING", category: "trust", title: "Content Security Policy Missing" },
    { rule_id: "SEC-HSTS-MISSING", category: "trust", title: "HSTS Missing" },
    { rule_id: "SEC-FRAME-MISSING", category: "trust", title: "X-Frame-Options Missing" },
    { rule_id: "SEC-XSS-MISSING", category: "trust", title: "X-Content-Type Missing" },
    { rule_id: "SEC-REFERRER-MISSING", category: "trust", title: "Referrer Policy Missing" },
    { rule_id: "SEC-PERMISSIONS-MISSING", category: "trust", title: "Permissions Policy Missing" },
    
    // Cookie Compliance
    { rule_id: "COM-COOKIE-BANNER-MISSING", category: "compliance", title: "Cookie Consent Missing" }
];

interface FindingInput {
    rule_id: string;
    category: 'accessibility' | 'compliance' | 'trust' | 'structure';
    severity: 'critical' | 'high' | 'medium' | 'low';
    message: string;
    how_to_fix: string;
    difficulty: 'easy' | 'medium' | 'hard';
    evidence?: any;
}

export async function evaluateRules(scanId: string) {
    try {
        logger.info(`[SCAN:${scanId}] ⚖️ RULE ENGINE: Starting deterministic analysis...`);

        // 1. Gather all pages and site-wide metadata
        const pages = await db.scanPage.findMany({
            where: { scan_id: scanId },
            orderBy: { depth: 'asc' }
        });

        if (pages.length === 0) {
            logger.warn(`[SCAN:${scanId}] ⚠️ Rule Engine: No pages found. Ending early.`);
            await db.scan.update({
                where: { id: scanId },
                data: {
                    status: "complete", // Or failed, but complete with 0 score is safer for UI
                    score: 0,
                    executive_summary: "Our crawler was unable to access any pages on this website. Please check if the URL is accessible and try again."
                }
            });
            return;
        }

        logger.info(`[SCAN:${scanId}] ⚖️ Analyzing ${pages.length} crawled pages...`);
        const findings: FindingInput[] = [];

        // 2. Execute Rules Groups
        logger.info(`[SCAN:${scanId}] ⚖️ Running Accessibility Rules...`);
        runAccessibilityRules(pages, findings);
        logger.info(`[SCAN:${scanId}] ⚖️ Running Compliance Rules...`);
        runComplianceRules(pages, findings);
        logger.info(`[SCAN:${scanId}] ⚖️ Running Trust Rules...`);
        runTrustRules(pages, findings);
        logger.info(`[SCAN:${scanId}] ⚖️ Running Structure Rules...`);
        runStructureRules(pages, findings);

        logger.info(`[SCAN:${scanId}] 📊 Analysis complete. Found ${findings.length} issues.`);

        // 3. Calculate Weighted Scores (0-100)
        const scores = calculateCategorizedScores(findings);
        const finalScore = Math.max(0, Math.min(100, Math.round(
            scores.accessibility.score * 0.3 +
            scores.compliance.score * 0.3 +
            scores.trust.score * 0.2 +
            scores.structure.score * 0.2
        )));

        // Transform scores object into the array format expected by the UI
        const categories = [
            {
                id: 'accessibility',
                name: 'Accessibility (WCAG)',
                score: scores.accessibility.score,
                description: 'Evaluation of screen reader compatibility, heading hierarchy, and alt text coverage.'
            },
            {
                id: 'compliance',
                name: 'Legal Compliance',
                score: scores.compliance.score,
                description: 'Presence of mandatory legal pages like Privacy Policy and Terms of Service.'
            },
            {
                id: 'trust',
                name: 'Trust & Reputation',
                score: scores.trust.score,
                description: 'Analysis of SSL certificates, meta descriptions, and mixed content risks.'
            },
            {
                id: 'structure',
                name: 'System Structure',
                score: scores.structure.score,
                description: 'Assessment of sitemap integrity, robots.txt, and link health.'
            }
        ];
        logger.info(`[SCAN:${scanId}] 📈 Calculated Score: ${finalScore}/100`);

        // 4. Save Findings to DB
        logger.info(`[SCAN:${scanId}] 💾 Saving findings to database...`);
        // --- AI Enhanced Summary (Sprint 3) ---
        const homePage = pages.find(p => p.depth === 0);
        const homePageSignals = homePage?.extracted_json;
        const homePageHtml = (homePageSignals as any)?.cleaned_html;
        const aiSummary = await getAiSummary(finalScore, findings, homePage?.url || "", homePageSignals, homePageHtml);

        // 4. Save Findings to DB (Sorted by severity)
        logger.info(`[SCAN:${scanId}] 💾 Saving findings to database...`);
        await db.finding.deleteMany({ where: { scan_id: scanId } });
        if (findings.length > 0) {
            const sortedFindings = [...findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
            await db.finding.createMany({
                data: sortedFindings.map(f => ({
                    id: randomUUID(),
                    scan_id: scanId,
                    ...f
                }))
            });
        }
 
        const passedChecks = getPassedChecks(findings);
        await db.scan.update({
            where: { id: scanId },
            data: {
                score: finalScore,
                executive_summary: aiSummary,
                categories: categories as any,
                passed_checks: passedChecks as any,
                findings_summary: {
                    accessibility: findings.filter(f => f.category === 'accessibility').length,
                    compliance: findings.filter(f => f.category === 'compliance').length,
                    trust: findings.filter(f => f.category === 'trust').length,
                    structure: findings.filter(f => f.category === 'structure').length,
                },
                status: "complete"
            }
        });

        logger.info(`[SCAN:${scanId}] ✅ RULE ENGINE COMPLETE. Final Score: ${finalScore}`);

    } catch (error) {
        logger.error(`[SCAN:${scanId}] ❌ Rule Evaluation crashed:`, error);
        await db.scan.update({
            where: { id: scanId },
            data: { status: "failed" }
        });
    }
}

// ─────────────────────────────────────────────────────────────────
// RULE GROUPS
// ─────────────────────────────────────────────────────────────────

function runAccessibilityRules(pages: any[], findings: FindingInput[]) {
    pages.filter(p => (p.content_type || "").includes("html")).forEach(page => {
        const data = page.extracted_json as any;
        if (!data) return;

        // ACC-001A: Missing Image Alts
        const missingAlts = (data.images || []).filter((img: any) => img.has_alt_attr === false);
        if (missingAlts.length > 0) {
            findings.push({
                rule_id: "ACC-MISSING-ALT",
                category: "accessibility",
                severity: "high",
                message: `${missingAlts.length} images completely lack the 'alt' attribute.`,
                how_to_fix: "Add descriptive 'alt' attributes to all <img> tags to support screen readers.",
                difficulty: "easy",
                evidence: {
                    url: page.url,
                    count: missingAlts.length,
                    examples: missingAlts.slice(0, 5) // Send as examples for inspector
                }
            });
        }

        // ACC-001B: Empty Image Alts
        const emptyAlts = (data.images || []).filter((img: any) => img.has_alt_attr === true && (!img.alt || img.alt.trim() === ""));
        if (emptyAlts.length > 0) {
            findings.push({
                rule_id: "ACC-EMPTY-ALT",
                category: "accessibility",
                severity: "medium",
                message: `${emptyAlts.length} images have empty 'alt' attributes (alt="").`,
                how_to_fix: "If the image is decorative, this is fine; otherwise, add meaningful descriptive text to the alt attribute.",
                difficulty: "easy",
                evidence: {
                    url: page.url,
                    count: emptyAlts.length,
                    examples: emptyAlts.slice(0, 5) // Send as examples for inspector
                }
            });
        }

        // ACC-002: Missing Page Title
        if (!page.title || page.title.trim() === "") {
            findings.push({
                rule_id: "ACC-TITLE-MISSING",
                category: "accessibility",
                severity: "critical",
                message: "This page is missing a <title> tag.",
                how_to_fix: "Add a unique and descriptive <title> tag to the <head> section.",
                difficulty: "easy",
                evidence: { url: page.url }
            });
        }

        // ACC-003: HTML Lang Missing
        if (!data.html_lang) {
            findings.push({
                rule_id: "ACC-HTML-LANG-MISSING",
                category: "accessibility",
                severity: "medium",
                message: "Missing 'lang' attribute on the <html> tag.",
                how_to_fix: "Add a lang attribute (e.g., lang=\"en\") to help screen readers identify the language.",
                difficulty: "easy",
                evidence: { url: page.url, snippet: "<html lang=\"?\">" }
            });
        }

        // ACC-004: Heading Order Issues
        const heads = data.headings || [];
        let prevLevel = 0;
        let hasOrderIssue = false;
        for (const h of heads) {
            if (h.level > prevLevel + 1 && prevLevel !== 0) {
                hasOrderIssue = true;
                break;
            }
            prevLevel = h.level;
        }
        if (hasOrderIssue) {
            findings.push({
                rule_id: "ACC-HEADING-ORDER",
                category: "accessibility",
                severity: "low",
                message: "Heading levels are skipped (e.g., H1 to H3).",
                how_to_fix: "Ensure headings follow a logical nested order (H1 -> H2 -> H3).",
                difficulty: "medium",
                evidence: { url: page.url, sequence: heads.map((h: any) => `H${h.level}`).join(' -> ') }
            });
        }

        // ACC-005A: Missing Form Labels (Forms with orphan inputs)
        const formsWithIssues = data.forms?.filter((f: any) => f.orphan_inputs_count > 0) || [];
        if (formsWithIssues.length > 0) {
            findings.push({
                rule_id: "ACC-FORM-LABELS-MISSING",
                category: "accessibility",
                severity: "high",
                message: `${formsWithIssues.length} forms have inputs without associated <label> tags.`,
                how_to_fix: "Ensure all form inputs have a corresponding <label> with a matching 'for' attribute.",
                difficulty: "easy",
                evidence: { url: page.url, count: formsWithIssues.length, examples: formsWithIssues }
            });
        }

        // ACC-005B: Missing Label Tags (Inputs unconditionally missing labels)
        const missingLabelTags = data.orphan_inputs || [];
        if (missingLabelTags.length > 0) {
            findings.push({
                rule_id: "ACC-MISSING-LABEL-TAGS",
                category: "accessibility",
                severity: "high",
                message: `${missingLabelTags.length} inputs are missing label tags or ARIA labels.`,
                how_to_fix: "Wrap the input in a <label> or link it with a 'for' attribute.",
                difficulty: "easy",
                evidence: { url: page.url, count: missingLabelTags.length, examples: missingLabelTags.slice(0, 5) }
            });
        }

        // ACC-006: Empty Anchor Text (Enhanced for Accessibility Accuracy)
        const emptyLinks = [...(data.links_internal || []), ...(data.links_external || [])].filter(l => {
            const hasText = l.text && l.text.trim().length > 0;
            const hasAria = l.aria_label && l.aria_label.trim().length > 0;
            const hasTitle = l.title && l.title.trim().length > 0;
            const hasImgAlt = l.image_alts && l.image_alts.length > 0;
            return !(hasText || hasAria || hasTitle || hasImgAlt);
        });

        if (emptyLinks.length > 0) {
            findings.push({
                rule_id: "ACC-EMPTY-ANCHORS",
                category: "accessibility",
                severity: "medium",
                message: `${emptyLinks.length} links have empty anchor text.`,
                how_to_fix: "Add descriptive text or aria-labels to all links for screen readers and SEO.",
                difficulty: "easy",
                evidence: { url: page.url, count: emptyLinks.length, examples: emptyLinks.slice(0, 5) }
            });
        }

        // ACC-007: ARIA/Roles (Agent Signal)
        if (data.accessibility) {
            if (!data.accessibility.has_aria_labels) {
                findings.push({ rule_id: "ACC-ARIA-MISSING", category: "accessibility", severity: "low", message: "No ARIA attributes found.", how_to_fix: "Use ARIA labels (aria-label) to provide context for interactive elements.", difficulty: "medium", evidence: { url: page.url } });
            }
            if (!data.accessibility.has_skip_link) {
                findings.push({ rule_id: "ACC-SKIP-LINK-MISSING", category: "accessibility", severity: "low", message: "Missing 'Skip to Content' link.", how_to_fix: "Add a skip link to allow keyboard users to bypass navigation.", difficulty: "easy", evidence: { url: page.url } });
            }
        }
    });
}

function runComplianceRules(pages: any[], findings: FindingInput[]) {
    const allInternalLinks = pages.flatMap(p => p.extracted_json?.links_internal || []);
    const homePage = pages.find(p => p.depth === 0);
    const bodyContent = homePage?.extracted_json?.body_text_sample || "";

    // Helper: Check if link list contains specific keywords in URL or Text
    const findLegalPage = (keywords: string[]) => {
        return allInternalLinks.some((l: any) =>
            keywords.some(k => l.href.toLowerCase().includes(k) || l.text.toLowerCase().includes(k))
        );
    };

    // COM-001: Privacy Policy
    if (!findLegalPage(['privacy'])) {
        findings.push({
            rule_id: "COM-PRIVACY-MISSING",
            category: "compliance",
            severity: "critical",
            message: "No Privacy Policy page detected.",
            how_to_fix: "Create and link a Privacy Policy page to comply with GDPR/CCPA regulations.",
            difficulty: "medium"
        });
    }

    // COM-002: Terms of Service
    if (!findLegalPage(['terms', 'condition', 'tos', 'legal'])) {
        findings.push({
            rule_id: "COM-TERMS-MISSING",
            category: "compliance",
            severity: "high",
            message: "No Terms of Service page detected.",
            how_to_fix: "Add a Terms of Service page to protect your business and inform users.",
            difficulty: "medium"
        });
    }

    // COM-003: Business Identity (Address/Phone)
    const addressRegex = /\d+\s+[A-Za-z0-9\s,]{10,}/; // Rough address pattern
    const phoneRegex = /\+?(\d{1,3})?[-.\s]?(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}/;

    if (!addressRegex.test(bodyContent) && !phoneRegex.test(bodyContent)) {
        findings.push({
            rule_id: "COM-IDENTITY-MISSING",
            category: "compliance",
            severity: "medium",
            message: "No clear business address or phone identity found on the homepage.",
            how_to_fix: "Display your business address and contact information clearly to establish legal presence.",
            difficulty: "easy",
            evidence: { excerpt: bodyContent.slice(0, 300) }
        });
    }

    // COM-004: Cookie Banner (Agent Signal)
    const hasAnyCookieBanner = pages.some(p => p.extracted_json?.compliance?.has_cookie_banner);
    if (!hasAnyCookieBanner) {
        findings.push({
            rule_id: "COM-COOKIE-BANNER-MISSING",
            category: "compliance",
            severity: "high",
            message: "No cookie consent banner detected.",
            how_to_fix: "Implement a Cookie Consent Management Platform (CMP) to comply with ePrivacy directives.",
            difficulty: "easy"
        });
    }
}

function runTrustRules(pages: any[], findings: FindingInput[]) {
    // TRU-001: SSL Validity
    const homePage = pages.find(p => p.depth === 0);
    if (homePage && !homePage.url.startsWith('https')) {
        findings.push({
            rule_id: "TRU-SSL-MISSING",
            category: "trust",
            severity: "critical",
            message: "Your website is not using an SSL certificate (HTTPS).",
            how_to_fix: "Install an SSL certificate to encrypt user data and build trust.",
            difficulty: "medium",
            evidence: { protocol: "http" }
        });
    }

    // TRU-002: Meta Description
    pages.filter(p => (p.content_type || "").includes("html")).forEach(p => {
        if (!p.meta?.description) {
            findings.push({
                rule_id: "TRU-META-DESC-MISSING",
                category: "trust",
                severity: "medium",
                message: "Missing meta description tag.",
                how_to_fix: "Add a <meta name=\"description\"> tag to improve CTR in search results.",
                difficulty: "easy",
                evidence: { url: p.url }
            });
        }

        // TRU-003: Mixed Content
        const data = p.extracted_json as any;
        if (data?.has_ssl && data.scripts) {
            const httpLinks = [
                ...(data.scripts || []),
                ...(data.images?.map((i: any) => i.src) || [])
            ].filter(src => src.startsWith('http:'));

            if (httpLinks.length > 0) {
                findings.push({
                    rule_id: "TRU-MIXED-CONTENT",
                    category: "trust",
                    severity: "high",
                    message: "Mixed content detected (HTTP resources on HTTPS page).",
                    how_to_fix: "Ensure all resources (scripts, images) are loaded via HTTPS.",
                    difficulty: "medium",
                    evidence: { url: p.url, count: httpLinks.length, examples: httpLinks.slice(0, 3) }
                });
            }
        }

        // TRU-004: Script Overload
        if (data?.total_scripts > 25) {
            findings.push({
                rule_id: "TRU-SCRIPT-OVERLOAD",
                category: "trust",
                severity: "low",
                message: "High number of external scripts may affect performance and trust.",
                how_to_fix: "Consolidate scripts and remove unnecessary third-party trackers.",
                difficulty: "hard",
                evidence: { url: p.url, count: data.total_scripts }
            });
        }

        // TRU-005: Meta Description Length
        if (p.meta?.description) {
            const len = p.meta.description.length;
            if (len < 70 || len > 160) {
                findings.push({
                    rule_id: "TRU-META-DESC-LENGTH",
                    category: "trust",
                    severity: "low",
                    message: `Meta description is ${len} characters (ideal: 70-160).`,
                    how_to_fix: "Adjust your meta description to be between 70 and 160 characters for optimal display in search results.",
                    difficulty: "easy",
                    evidence: { url: p.url, length: len }
                });
            }
        }

        // TRU-006: Multiple Meta Descriptions
        if (data.descriptions && data.descriptions.length > 1) {
            findings.push({
                rule_id: "TRU-MULTIPLE-DESCRIPTIONS",
                category: "trust",
                severity: "low",
                message: `Page has ${data.descriptions.length} meta description tags.`,
                how_to_fix: "Ensure each page has only one meta description tag to prevent search engines from choosing the wrong one.",
                difficulty: "easy",
                evidence: { url: p.url, count: data.descriptions.length, snippets: data.descriptions }
            });
        }
    });

    // TRU-007: Social Media Links
    if (homePage && homePage.extracted_json?.social_links && homePage.extracted_json.social_links.length === 0) {
        findings.push({
            rule_id: "TRU-NO-SOCIAL-LINKS",
            category: "trust",
            severity: "low",
            message: "Home page has no links to social media pages.",
            how_to_fix: "Add links to your social media profiles on the homepage to increase brand trust and engagement.",
            difficulty: "easy",
            evidence: { url: homePage.url }
        });
    }

    // TRU-008: Security Headers (Agent Signal)
    if (homePage?.extracted_json?.security_headers) {
        const h = homePage.extracted_json.security_headers;
        if (!h.csp) findings.push({ rule_id: "SEC-CSP-MISSING", category: "trust", severity: "high", message: "Content Security Policy (CSP) not set.", how_to_fix: "Define a CSP header to prevent XSS and data injection attacks.", difficulty: "medium" });
        if (!h.hsts) findings.push({ rule_id: "SEC-HSTS-MISSING", category: "trust", severity: "medium", message: "HSTS Header missing.", how_to_fix: "Enable HTTP Strict Transport Security (HSTS) on your server.", difficulty: "easy" });
        if (!h.x_frame_options) findings.push({ rule_id: "SEC-FRAME-MISSING", category: "trust", severity: "medium", message: "X-Frame-Options not set.", how_to_fix: "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking.", difficulty: "easy" });
        if (!h.x_content_type) findings.push({ rule_id: "SEC-XSS-MISSING", category: "trust", severity: "low", message: "X-Content-Type-Options missing.", how_to_fix: "Set X-Content-Type-Options to 'nosniff' to prevent MIME sniffing.", difficulty: "easy" });
        if (!h.referrer_policy) findings.push({ rule_id: "SEC-REFERRER-MISSING", category: "trust", severity: "low", message: "Referrer-Policy header missing.", how_to_fix: "Set a Referrer-Policy to control how much information is shared when navigating away from your site.", difficulty: "easy" });
        if (!h.permissions_policy) findings.push({ rule_id: "SEC-PERMISSIONS-MISSING", category: "trust", severity: "low", message: "Permissions-Policy header missing.", how_to_fix: "Use Permissions-Policy to restrict which browser features (like camera/mic) can be used.", difficulty: "medium" });
    }
}

function runStructureRules(pages: any[], findings: FindingInput[]) {
    pages.filter(p => (p.content_type || "").includes("html")).forEach(page => {
        const data = page.extracted_json as any;
        if (!data) return;

        // STR-001: Duplicate H1
        const h1s = data.headings?.filter((h: any) => h.level === 1) || [];
        if (h1s.length > 1) {
            findings.push({
                rule_id: "STR-H1-DUPLICATE",
                category: "structure",
                severity: "medium",
                message: "Multiple H1 tags detected on a single page.",
                how_to_fix: "Ensure each page has only one primary H1 tag for optimal SEO.",
                difficulty: "easy",
                evidence: {
                    url: page.url,
                    count: h1s.length,
                    items: h1s
                }
            });
        }

        // STR-002: Missing H1
        if (h1s.length === 0) {
            findings.push({
                rule_id: "STR-H1-MISSING",
                category: "structure",
                severity: "high",
                message: "Page is missing an H1 tag.",
                how_to_fix: "Add one H1 tag per page to help search engines understand your main topic.",
                difficulty: "easy",
                evidence: { url: page.url }
            });
        }

        // STR-006: Title Length
        if (page.title) {
            const tLen = page.title.length;
            if (tLen < 30 || tLen > 60) {
                findings.push({
                    rule_id: "STR-TITLE-LENGTH",
                    category: "structure",
                    severity: "low",
                    message: `Title length is ${tLen} characters (ideal: 30-60).`,
                    how_to_fix: "Adjust page title to be between 30 and 60 characters so it doesn't get cut off in search results.",
                    difficulty: "easy",
                    evidence: { url: page.url, title: page.title, length: tLen }
                });
            }
        }

        // STR-007: Image Dimensions Missing
        const imagesNoDims = (data.images || []).filter((img: any) => !img.width || !img.height);
        if (imagesNoDims.length > 0) {
            findings.push({
                rule_id: "STR-IMG-DIMS-MISSING",
                category: "structure",
                severity: "low",
                message: `${imagesNoDims.length} images are missing width/height attributes.`,
                how_to_fix: "Add width and height attributes to images to prevent Cumulative Layout Shift (CLS).",
                difficulty: "easy",
                evidence: { url: page.url, count: imagesNoDims.length, examples: imagesNoDims.slice(0, 5) }
            });
        }

        // STR-008: Next Gen Formats
        const legacyImages = (data.images || []).filter((img: any) => img.src && (img.src.toLowerCase().endsWith('.jpg') || img.src.toLowerCase().endsWith('.jpeg') || img.src.toLowerCase().endsWith('.png')));
        if (legacyImages.length > 0) {
            findings.push({
                rule_id: "STR-IMG-NEXTGEN",
                category: "structure",
                severity: "low",
                message: `${legacyImages.length} images are not served in next-gen formats (WebP/AVIF).`,
                how_to_fix: "Convert legacy image formats (JPEG/PNG) to WebP or AVIF to improve load times.",
                difficulty: "medium",
                evidence: { url: page.url, count: legacyImages.length, examples: legacyImages.slice(0, 5) }
            });
        }

        // STR-009: H1 / H2 has other tags inside
        const checkTagsInside = (tags: any[], ruleBase: string) => {
            const hasTags = tags.filter(t => t.innerHTML && /<[a-zA-Z]+[^>]*>/.test(t.innerHTML));
            if (hasTags.length > 0) {
                findings.push({
                    rule_id: `STR-${ruleBase}-TAGS-INSIDE`,
                    category: "structure",
                    severity: "low",
                    message: `Found ${hasTags.length} ${ruleBase} tags with inner HTML tags.`,
                    how_to_fix: `Remove redundant tags from ${ruleBase} to keep heading structure clean for search engines.`,
                    difficulty: "easy",
                    evidence: { url: page.url, count: hasTags.length, examples: hasTags.slice(0, 5) }
                });
            }
        };
        checkTagsInside(h1s, "H1");
        const h2s = data.headings?.filter((h: any) => h.level === 2) || [];
        checkTagsInside(h2s, "H2");

        // STR-010: Canonical Mismatch
        if (data.canonical && data.canonical !== page.url && normalizeUrl(data.canonical) !== normalizeUrl(page.url)) {
            findings.push({
                rule_id: "STR-CANONICAL-MISMATCH",
                category: "structure",
                severity: "medium",
                message: "Canonical URL does not match actual URL.",
                how_to_fix: "Ensure the canonical tag points to the desired indexable version of the URL to avoid indexing issues.",
                difficulty: "medium",
                evidence: { url: page.url, canonical: data.canonical }
            });
        }

        // STR-011: Inline Styles
        if (data.inline_styles && data.inline_styles.length > 0) {
            findings.push({
                rule_id: "STR-INLINE-STYLES",
                category: "structure",
                severity: "low",
                message: `Page has ${data.inline_styles.length} elements with inline style attributes.`,
                how_to_fix: "Move inline styles to external CSS files for better caching and maintainability (W3C standard).",
                difficulty: "medium",
                evidence: { url: page.url, count: data.inline_styles.length, examples: data.inline_styles.slice(0, 5) }
            });
        }

        // STR-012: Missing GTM
        if (data.gtm_present === false) {
            findings.push({
                rule_id: "STR-GTM-MISSING",
                category: "structure",
                severity: "low",
                message: "URL contains no Google Tag Manager code.",
                how_to_fix: "Add Google Tag Manager snippet to track analytics and marketing tags centrally.",
                difficulty: "easy",
                evidence: { url: page.url }
            });
        }

        // STR-013: Missing H2
        if (h2s.length === 0) {
            findings.push({
                rule_id: "STR-H2-MISSING",
                category: "structure",
                severity: "low",
                message: "Page is missing H2 tags.",
                how_to_fix: "Use H2 tags to structure your content into sub-topics, making it easier for users and search engines to read.",
                difficulty: "easy",
                evidence: { url: page.url }
            });
        }

        // STR-014: Identical Headings
        const headingTexts = data.headings?.map((h: any) => h.text.trim().toLowerCase()) || [];
        const identicalHeadings = headingTexts.filter((t: string, i: number) => headingTexts.indexOf(t) !== i && t !== "");
        if (identicalHeadings.length > 0) {
            findings.push({
                rule_id: "STR-IDENTICAL-HEADINGS",
                category: "structure",
                severity: "low",
                message: `Page has ${identicalHeadings.length} identical headings.`,
                how_to_fix: "Ensure headings are unique and descriptive to provide better context to readers and search engines.",
                difficulty: "easy",
                evidence: { url: page.url, count: identicalHeadings.length, examples: [...new Set(identicalHeadings)].slice(0, 5) }
            });
        }

        // STR-015: Identical Alt Tags
        const altTexts = (data.images || []).map((img: any) => (img.alt || "").trim().toLowerCase()).filter(Boolean);
        const identicalAlts = altTexts.filter((t: string, i: number) => altTexts.indexOf(t) !== i);
        if (identicalAlts.length > 0) {
            findings.push({
                rule_id: "STR-IDENTICAL-ALT-TAGS",
                category: "structure",
                severity: "low",
                message: `Page has ${identicalAlts.length} identical alt tags.`,
                how_to_fix: "Provide unique, descriptive alt text for each image to improve accessibility and image search SEO.",
                difficulty: "easy",
                evidence: { url: page.url, count: identicalAlts.length, examples: [...new Set(identicalAlts)].slice(0, 5) }
            });
        }

        // STR-016: No strong importance elements
        if (data.strong_tags_count === 0) {
            findings.push({
                rule_id: "STR-NO-STRONG-ELEMENTS",
                category: "structure",
                severity: "low",
                message: "Page has no strong importance elements (e.g., <strong>, <b>).",
                how_to_fix: "Use <strong> or <b> tags to highlight important keywords or phrases within your content.",
                difficulty: "easy",
                evidence: { url: page.url }
            });
        }
    });

    // STR-003: Duplicate Titles
    const titleMap = new Map<string, string[]>();
    pages.filter(p => (p.content_type || "").includes("html")).forEach(p => {
        if (p.title) {
            const list = titleMap.get(p.title) || [];
            list.push(p.url);
            titleMap.set(p.title, list);
        }
    });

    titleMap.forEach((urls, title) => {
        if (urls.length > 1) {
            findings.push({
                rule_id: "STR-TITLE-DUPLICATE",
                category: "structure",
                severity: "medium",
                message: `Duplicate page title: "${title}"`,
                how_to_fix: "Give each page a unique and descriptive title to avoid SEO cannibalization.",
                difficulty: "easy",
                evidence: { title, count: urls.length, urls }
            });
        }
    });

    // STR-004: Robots.txt existence
    const robotsPage = pages.find(p => p.url.endsWith('/robots.txt'));
    if (!robotsPage || robotsPage.status_code !== 200) {
        findings.push({
            rule_id: "STR-ROBOTS-MISSING",
            category: "structure",
            severity: "medium",
            message: "Missing or inaccessible robots.txt file.",
            how_to_fix: "Create a robots.txt file at the root to guide search engine crawlers.",
            difficulty: "easy",
            evidence: { url: `${pages.find(p => p.depth === 0)?.url || ''}robots.txt` }
        });
    }

        // STR-005: Broken Links (404/500)
    const brokenPages = pages.filter(p => p.status_code >= 400 && !p.url.endsWith('/robots.txt'));
    if (brokenPages.length > 0) {
        findings.push({
            rule_id: "STR-BROKEN-LINKS",
            category: "structure",
            severity: "high",
            message: `${brokenPages.length} broken links (404 or 500 errors) detected.`,
            how_to_fix: "Check for broken links or server errors and redirect or fix the URLs.",
            difficulty: "medium",
            evidence: { count: brokenPages.length, urls: brokenPages.map(p => ({ url: p.url, status: p.status_code })) }
        });
    }
}

function normalizeUrl(urlStr: string): string {
    try {
        const u = new URL(urlStr);
        u.hash = '';
        let path = u.pathname.replace(/\/+$/, '') || '/';
        return `${u.protocol}//${u.host.toLowerCase()}${path}${u.search}`;
    } catch {
        return urlStr;
    }
}

// ─────────────────────────────────────────────────────────────────
// SCORING LOGIC
// ─────────────────────────────────────────────────────────────────

function calculateCategorizedScores(findings: FindingInput[]) {
    const scores = {
        accessibility: { score: 100, count: 0 },
        compliance: { score: 100, count: 0 },
        trust: { score: 100, count: 0 },
        structure: { score: 100, count: 0 }
    };

    findings.forEach(f => {
        const penalty = getPenalty(f.severity);
        scores[f.category].score -= penalty;
        scores[f.category].count++;
    });

    // Clamp scores
    Object.keys(scores).forEach(key => {
        const k = key as keyof typeof scores;
        scores[k].score = Math.max(0, scores[k].score);
    });

    return scores;
}

function getPenalty(severity: string) {
    switch (severity) {
        case 'critical': return 25;
        case 'high': return 15;
        case 'medium': return 10;
        case 'low': return 5;
        default: return 0;
    }
}

function severityRank(severity: string) {
    const ranks = { critical: 4, high: 3, medium: 2, low: 1 };
    return ranks[severity as keyof typeof ranks] || 0;
}

function getPassedChecks(findings: FindingInput[]) {
    const failedIds = new Set(findings.map(f => f.rule_id));
    return MASTER_RULES.filter(r => !failedIds.has(r.rule_id));
}


