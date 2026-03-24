import React from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import MainLayout from "../layouts/MainLayout";
import HomePage from "../pages/home/homePage";
import AboutPage from "../pages/about/AboutPage";
import PricingPage from "../pages/pricing/PricingPage";
import FeaturesPage from "../pages/features/FeaturesPage";
import LoginPage from "../pages/auth/LoginPage";
import ScanProcessingPage from "../pages/scan/ScanProcessingPage";
import ReportPreviewPage from "../pages/report/ReportPreviewPage";
import PrivacyPolicyPage from "../pages/legal/PrivacyPolicyPage";
import TermsOfServicePage from "../pages/legal/TermsOfServicePage";
import CookiePolicyPage from "../pages/legal/CookiePolicyPage";
import ContactPage from "../pages/contact/ContactPage";
import MasterDashboard from "../pages/dashboard/MasterDashboard";
import DashboardOverview from "../pages/dashboard/DashboardOverview";
import DashboardOrg from "../pages/dashboard/DashboardOrg";
import DashboardConfig from "../pages/dashboard/DashboardConfig";
import DashboardMonitoring from "../pages/dashboard/DashboardMonitoring";
import DashboardBilling from "../pages/dashboard/DashboardBilling";
import ProjectScanView from "../pages/dashboard/ProjectScanView";

const AuthGuard = ({ children }: { children: React.ReactNode }) => {
    const isAuthenticated = !!localStorage.getItem('token') || !!localStorage.getItem('accessToken');
    return isAuthenticated ? <Navigate to="/" replace /> : <>{children}</>;
};

const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
    const isAuthenticated = !!localStorage.getItem('token') || !!localStorage.getItem('accessToken');
    return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />;
};

const AppRoutes = () => {
    return (
        <Routes>
            {/* Routes wrapped with MainLayout (includes Header & Footer) */}
            <Route element={<MainLayout />}>
                <Route path="/" element={<HomePage />} />
                <Route path="/about" element={<AboutPage />} />
                <Route path="/pricing" element={<PricingPage />} />
                <Route path="/features" element={<FeaturesPage />} />
                <Route path="/privacy" element={<PrivacyPolicyPage />} />
                <Route path="/terms" element={<TermsOfServicePage />} />
                <Route path="/cookies" element={<CookiePolicyPage />} />
                <Route path="/contact" element={<ContactPage />} />
                <Route path="/login" element={
                    <AuthGuard>
                        <LoginPage />
                    </AuthGuard>
                } />
            </Route>

            {/* Application Dashboard Route - Full Screen */}
            <Route path="/dashboard" element={
                <ProtectedRoute>
                    <MasterDashboard />
                </ProtectedRoute>
            }>
                <Route index element={<DashboardOverview />} />
                <Route path="team" element={<DashboardOrg />} />
                <Route path="settings" element={<DashboardConfig />} />
                <Route path="monitoring" element={<DashboardMonitoring />} />
                <Route path="billing" element={<DashboardBilling />} />
                <Route path=":id" element={<ProjectScanView />} />
            </Route>

            <Route path="/scan/processing" element={<ScanProcessingPage />} />
            <Route path="/report/preview" element={<ReportPreviewPage />} />

            <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
    );
};

export default AppRoutes;
