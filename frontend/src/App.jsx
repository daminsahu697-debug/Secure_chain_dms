import React, { useState, useEffect, useRef } from 'react';
import TopMicroStrip from './components/TopMicroStrip';
import MainHeader from './components/MainHeader';
import FlagBanner from './components/FlagBanner';
import Navbar from './components/Navbar';
import Footer from './components/Footer';

import UploadModal from './components/UploadModal';
import QuorumModal from './components/QuorumModal';
import ShortcutsModal from './components/ShortcutsModal';
import BackToTop from './components/BackToTop';
import LandingPage from './views/LandingPage';
import LoginPage from './views/LoginPage';
import DashboardView from './views/DashboardView';
import ApprovalsView from './views/ApprovalsView';
import CitizenPortalView from './views/CitizenPortalView';
import DocumentDetailView from './views/DocumentDetailView';
import VersionChainView from './views/VersionChainView';
import AuditLogView from './views/AuditLogView';
import ContactView from './views/ContactView';
import AboutView from './views/public/AboutView';
import SitemapView from './views/public/SitemapView';
import TermsView from './views/public/TermsView';
import PrivacyView from './views/public/PrivacyView';
import AccessibilityView from './views/public/AccessibilityView';
import CopyrightView from './views/public/CopyrightView';
import DisclaimerView from './views/public/DisclaimerView';
import { ToastProvider, useToast } from './context/ToastContext';
import { translations } from './i18n/translations';
import { apiClient, getToken, setStoredAuth, clearStoredAuth, getStoredUser } from './services/apiClient';

function AppContent() {
  const toast = useToast();

  // Global Bilingual Internationalization State (English / हिन्दी)
  const [lang, setLang] = useState('en');
  const [fontSizeLevel, setFontSizeLevel] = useState(0); // -1, 0, 1
  const [highContrast, setHighContrast] = useState(false);

  // Dark Mode State
  const [darkMode, setDarkMode] = useState(() => {
    return localStorage.getItem('theme') === 'dark';
  });

  // Shortcuts Modal State
  const [shortcutsOpen, setShortcutsOpen] = useState(false);

  // App Navigation & Active View State
  const [currentTab, setCurrentTab] = useState('home'); // home | dashboard | cases | approvals | audit | contact | citizen | login
  const [loginRoleIntent, setLoginRoleIntent] = useState('POLICE');
  const [selectedDoc, setSelectedDoc] = useState(null);
  const [isViewingChain, setIsViewingChain] = useState(false);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);

  // Modals
  const [uploadModalOpen, setUploadModalOpen] = useState(false);
  const [uploadFile, setUploadFile] = useState(null);
  const [quorumModalOpen, setQuorumModalOpen] = useState(false);
  const [activeQuorumDoc, setActiveQuorumDoc] = useState(null);

  // Data & Authentication
  const [personas, setPersonas] = useState([]);
  const [activeUser, setActiveUser] = useState(null);
  const [documents, setDocuments] = useState([]);
  const [metrics, setMetrics] = useState({
    totalDocuments: 3,
    lockedCount: 2,
    pendingQuorumCount: 1,
    rejectedCount: 0,
    totalBlocks: 4
  });
  const [loading, setLoading] = useState(true);

  // Keyboard shortcut state sequence tracking
  const lastKeyRef = useRef(null);
  const lastKeyTimerRef = useRef(null);

  // Apply dark mode class to <html> element
  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark');
      localStorage.setItem('theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('theme', 'light');
    }
  }, [darkMode]);

  // URL Hash Routing Setup (Enables direct linking and footer links)
  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.replace('#', '');
      if (hash && ['home', 'dashboard', 'cases', 'approvals', 'audit', 'contact', 'citizen', 'login', 'about', 'sitemap', 'terms', 'privacy', 'accessibility', 'copyright', 'disclaimer'].includes(hash)) {
        setCurrentTab(hash);
      } else if (!hash) {
        setCurrentTab('home');
      }
    };

    // Run on initial load
    handleHashChange();

    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  // Section 14 Global Keyboard Shortcuts
  useEffect(() => {
    const handleKeyDown = (e) => {
      const isInput = ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName);

      // Escape closes any open modal
      if (e.key === 'Escape') {
        setShortcutsOpen(false);
        setUploadModalOpen(false);
        setQuorumModalOpen(false);
        return;
      }

      // Alt + D: Toggle Dark Mode
      if (e.altKey && (e.key === 'd' || e.key === 'D')) {
        e.preventDefault();
        setDarkMode(prev => !prev);
        return;
      }

      // If user is inside an input, don't trigger navigation shortcuts
      if (isInput) return;

      // '/': Focus search bar
      if (e.key === '/') {
        e.preventDefault();
        const searchInput = document.querySelector('input[type="text"], input[type="search"]');
        if (searchInput) {
          searchInput.focus();
        }
        return;
      }

      // '?': Open shortcuts help modal
      if (e.key === '?') {
        e.preventDefault();
        setShortcutsOpen(true);
        return;
      }

      // 'g' then 'd': Go to dashboard home
      // 'g' then 'a': Go to approvals
      if (e.key === 'g' || e.key === 'G') {
        lastKeyRef.current = 'g';
        clearTimeout(lastKeyTimerRef.current);
        lastKeyTimerRef.current = setTimeout(() => {
          lastKeyRef.current = null;
        }, 1000);
        return;
      }

      if (lastKeyRef.current === 'g') {
        if (e.key === 'd' || e.key === 'D') {
          e.preventDefault();
          lastKeyRef.current = null;
          if (activeUser?.portalRole === 'CITIZEN') {
            setCurrentTab('citizen');
          } else if (activeUser) {
            setCurrentTab('dashboard');
          } else {
            setCurrentTab('home');
          }
          setSelectedDoc(null);
          return;
        }

        if (e.key === 'a' || e.key === 'A') {
          e.preventDefault();
          lastKeyRef.current = null;
          if (activeUser?.portalRole === 'POLICE' || activeUser?.portalRole === 'JUDICIAL' || activeUser?.portalRole === 'FORENSIC') {
            setCurrentTab('approvals');
            setSelectedDoc(null);
          } else {
            toast.info("Approvals queue is restricted to supervisory review cadres.");
          }
          return;
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [activeUser]);

  // Strict Route Guard per Master Spec Section 23
  useEffect(() => {
    if (activeUser) {
      // If logged in, they cannot visit home or login pages.
      if (currentTab === 'home' || currentTab === 'login') {
        setCurrentTab(activeUser.portalRole === 'CITIZEN' ? 'citizen' : 'dashboard');
      }
    } else {
      // If not logged in, they can only visit public pages.
      if (['dashboard', 'cases', 'approvals', 'audit', 'citizen'].includes(currentTab)) {
        setLoginRoleIntent('POLICE');
        setCurrentTab('login');
      }
    }
  }, [activeUser, currentTab]);

  // Fetch initial data from backend
  const fetchAllData = async () => {
    try {
      // Fetch personas
      try {
        const pRes = await fetch('/api/v1/personas');
        if (pRes.ok) {
          const pData = await pRes.json();
          setPersonas(pData.personas || []);
        }
      } catch (_) {
        // Fallback for personas
      }

      // Fetch documents & metrics from real backend API if authenticated
      if (getToken()) {
        try {
          const res = await apiClient.get('/documents');
          const rawItems = res?.items || (Array.isArray(res) ? res : []);

          const formattedItems = rawItems.map(d => {
            let cached = {};
            try {
              const str = localStorage.getItem(`securechain_doc_meta_${d.id}`);
              if (str) cached = JSON.parse(str);
            } catch (_) {}

            const realFirNo = cached.firNo || cached.fir_number || d.fir_number ||
              (d.title?.startsWith('FIR No.') ? d.title.split(' ')[2]?.split('-')[0]?.trim() : null) ||
              (d.case_id ? `CASE-${String(d.case_id).substring(0, 8).toUpperCase()}` : `DOC-${String(d.id).substring(0, 8).toUpperCase()}`);

            return {
              ...d,
              ...cached,
              id: d.id,
              title: d.title || cached.title,
              caseTitle: d.title || cached.caseTitle || cached.title,
              firNo: realFirNo,
              fir_number: realFirNo,
              district: cached.district || d.district || 'Patna',
              policeStation: cached.policeStation || d.policeStation || 'Central PS',
              year: cached.year || d.year || new Date().getFullYear().toString(),
              sha256: d.sha256_hash || d.sha256 || d.hash || cached.sha256 || '',
              status: d.status || (d.is_sealed ? 'LOCKED' : 'PENDING'),
              version: d.version || '1.0',
              created_at: d.created_at || d.createdAt,
              dateReported: cached.dateReported || d.created_at || d.createdAt,
              requesterId: d.requester_id || d.uploaded_by || d.created_by || d.authorId,
            };
          });

          setDocuments(formattedItems);

          // Calculate metrics dynamically from real backend documents
          const totalDocs = formattedItems.length;
          const locked = formattedItems.filter(d => d.status === 'LOCKED' || d.status === 'APPROVED' || d.is_sealed || d.is_locked).length;
          const pending = formattedItems.filter(d => d.status === 'PENDING_AMENDMENT' || d.status === 'PENDING_QUORUM' || d.status === 'PENDING').length;
          const rejected = formattedItems.filter(d => d.status === 'REJECTED' || d.status === 'TAMPER_DETECTED').length;
          const totalVerBlocks = formattedItems.reduce((acc, d) => acc + (d.version_count || d.version_number || 1), 0);

          setMetrics({
            totalDocuments: totalDocs,
            lockedCount: locked,
            pendingQuorumCount: pending,
            rejectedCount: rejected,
            totalBlocks: totalVerBlocks
          });

          if (selectedDoc) {
            const fresh = formattedItems.find(d => d.id === selectedDoc.id);
            if (fresh) setSelectedDoc(fresh);
          }
        } catch (docErr) {
          console.error("Failed to load real documents from API:", docErr);
        }
      }
    } catch (err) {
      console.error("Failed to load initial data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const initAuthAndData = async () => {
      const token = getToken();
      if (token) {
        try {
          const userRes = await apiClient.get('/auth/me');
          if (userRes) {
            const storedUser = getStoredUser() || {};
            const empId = userRes.employee_id || storedUser.employee_id || '';
            const prefix = empId.slice(0, 3).toUpperCase();
            const prefixRoleMap = { POL: 'POLICE', JUD: 'JUDICIAL', FOR: 'FORENSIC', FSL: 'FORENSIC', AUD: 'AUDITOR' };
            const portalRole = storedUser.portalRole || prefixRoleMap[prefix] || (userRes.role === 'ADMIN' ? 'AUDITOR' : 'POLICE');

            const restoredUser = {
              ...storedUser,
              id: userRes.id || empId,
              employee_id: empId,
              employeeId: empId,
              name: userRes.name || storedUser.name || 'Official User',
              email: userRes.email || storedUser.email,
              role: userRes.role || storedUser.role || portalRole,
              portalRole: portalRole,
            };
            setActiveUser(restoredUser);
            setStoredAuth(token, restoredUser);
          }
        } catch (err) {
          console.warn("Stored JWT session invalid or expired:", err.message);
          clearStoredAuth();
          setActiveUser(null);
        }
      }
      await fetchAllData();
    };

    initAuthAndData();
  }, []);

  // Handlers
  const handleToggleLang = () => {
    setLang(prev => prev === 'en' ? 'hi' : 'en');
  };

  const handleToggleDarkMode = () => {
    setDarkMode(prev => {
      const next = !prev;
      if (next) {
        document.documentElement.classList.add('dark');
        localStorage.setItem('theme', 'dark');
      } else {
        document.documentElement.classList.remove('dark');
        localStorage.setItem('theme', 'light');
      }
      return next;
    });
  };

  const handleChangeFontSize = (delta) => {
    setFontSizeLevel(delta);
  };

  const handleToggleHighContrast = () => {
    setHighContrast(prev => !prev);
  };

  // Route Guard per Master Spec Section 4 & 5
  const handleSelectTab = (tabId) => {
    // Audit Log access control: JUDICIAL only (Sections 8 & 10)
    if (tabId === 'audit') {
      if (activeUser?.portalRole !== 'JUDICIAL') {
        toast.warning("Access Restricted: The WORM Cryptographic Ledger is restricted to Judicial Authorities.");
        return;
      }
    }

    // Citizen isolation: Citizen can only view citizen portal
    if (activeUser?.portalRole === 'CITIZEN' && tabId === 'dashboard') {
      setCurrentTab('citizen');
      return;
    }

    // Dashboard access control: if not logged in, prompt login
    if (tabId === 'dashboard' && !activeUser) {
      setLoginRoleIntent('POLICE');
      setCurrentTab('login');
      return;
    }

    // Allow navigating to public pages even if not logged in
    const publicTabs = ['home', 'login', 'contact', 'citizen', 'about', 'sitemap', 'terms', 'privacy', 'accessibility', 'copyright', 'disclaimer'];
    if (!activeUser && !publicTabs.includes(tabId)) {
      toast.warning("Authentication Required: Please login with your official MHA credentials to access this secure zone.");
      return;
    }

    // Sync hash to URL
    if (tabId === 'home') {
      window.history.pushState(null, null, ' '); // remove hash cleanly
    } else {
      window.location.hash = tabId;
    }

    setCurrentTab(tabId);
    setSelectedDoc(null);
    setIsViewingChain(false);
    setMobileSidebarOpen(false);
  };

  const handleSelectDocument = (doc) => {
    setSelectedDoc(doc);
    setIsViewingChain(false);
  };

  const handleGoToChain = (doc) => {
    setSelectedDoc(doc);
    setIsViewingChain(true);
  };

  const handleOpenQuorum = (doc) => {
    setActiveQuorumDoc(doc);
    setQuorumModalOpen(true);
  };

  const handleOpenRoleLogin = (roleKey) => {
    setLoginRoleIntent(roleKey || 'POLICE');
    setCurrentTab('login');
  };

  const handleSwitchPersona = (persona) => {
    setActiveUser(persona);
    toast.info(`Switched active cadre to ${persona.name} (${persona.role})`);
  };

  const handleDemoApproverLogin = async (employeeId) => {
    try {
      toast.info(`Switching user to ${employeeId}...`);
      const data = await apiClient.post('/auth/login', {
        employee_id: employeeId,
        password: '123456'
      });
      const backendUser = data.user || {};
      
      const enrichedUser = {
        ...backendUser,
        id: backendUser.id || backendUser.employee_id,
        name: backendUser.name || 'Approver',
        portalRole: 'JUDICIAL'
      };
      
      setActiveUser(enrichedUser);
      toast.success(`Switched active cadre to ${enrichedUser.name}`);
      setQuorumModalOpen(false); // Close modal so they can reopen it as the new user
      setTimeout(() => setQuorumModalOpen(true), 100);
    } catch (err) {
      toast.error(`Demo login failed for ${employeeId}.`);
    }
  };

  const handleLoginSuccess = (user) => {
    setActiveUser(user);
    fetchAllData();
    toast.success(`Authenticated successfully as ${user.name}`);
    if (user.portalRole === 'CITIZEN') {
      setCurrentTab('citizen');
    } else {
      setCurrentTab('dashboard');
    }
  };

  const handleLogout = async () => {
    try {
      if (getToken()) {
        await apiClient.post('/auth/logout');
      }
    } catch (_) {
      // Ignore API errors during logout cleanup
    } finally {
      clearStoredAuth();
      setActiveUser(null);
      setCurrentTab('home');
      setSelectedDoc(null);
      toast.info("Logged out of official session.");
    }
  };

  const handleRequestEdit = async (docId, editData) => {
    try {
      const { reason, proposalFile } = editData || {};
      if (!proposalFile) {
        toast.error("Please select a proposed amendment PDF file.");
        return;
      }

      const formData = new FormData();
      formData.append("reason", reason || "Supplementary document amendment request");
      formData.append("file", proposalFile);

      const res = await apiClient.postFormData(`/documents/${docId}/edit-requests`, formData);

      // On successful creation:
      toast.success("Amendment request submitted for quorum approval.");

      // Refresh documents and update active selection state
      if (selectedDoc && selectedDoc.id === docId) {
        setSelectedDoc(prev => ({
          ...prev,
          status: 'PENDING_QUORUM',
          editRequestId: res.id,
          activeEditRequest: res
        }));
      }

      await fetchAllData();
    } catch (err) {
      console.error("Failed to submit edit request:", err);
      let errorMsg = err.message || 'Failed to submit edit request';
      if (err.status === 403) {
        errorMsg = "Permission Denied: Requester or role is not authorized to request an edit on this case.";
      } else if (err.status === 413) {
        errorMsg = "File Size Error: Proposed PDF exceeds maximum file upload limit.";
      } else if (err.status === 404) {
        errorMsg = "Not Found: Document or source version record was not found.";
      }
      toast.error(errorMsg);
    }
  };

  const handleVoteSuccess = (updatedDoc, updatedSession) => {
    setSelectedDoc(updatedDoc);
    if (activeQuorumDoc?.id === updatedDoc.id) {
      setActiveQuorumDoc(updatedDoc);
    }
    fetchAllData();
    toast.success("Consensus vote recorded on immutable ledger.");
  };

  const handleFinalizeSuccess = async (docId, newVersion) => {
    const verStr = newVersion?.version || (newVersion?.version_number ? `1.${newVersion.version_number - 1}` : '1.1');
    toast.success(`Amendment finalized successfully! Version v${verStr} sealed into repository.`);

    await fetchAllData();

    if (selectedDoc && selectedDoc.id === docId) {
      try {
        const freshDoc = await apiClient.get(`/documents/${docId}`);
        if (freshDoc) {
          setSelectedDoc(prev => ({
            ...prev,
            ...freshDoc,
            status: 'LOCKED',
            currentVersion: freshDoc.version_number ? `1.${freshDoc.version_number - 1}` : verStr
          }));
        }
      } catch (_) {}
    }
  };

  const handleUploadSuccess = (newDoc) => {
    setDocuments(prev => [newDoc, ...prev.filter(d => d.id !== newDoc.id)]);
    setSelectedDoc(newDoc);
    setCurrentTab('dashboard');
    fetchAllData();
    toast.success(`FIR ${newDoc.firNo || newDoc.id} sealed into tamper-evident repository!`);
  };

  const handleVerdictSuccess = (updatedDoc, verdict) => {
    fetchAllData();
    setDocuments(prev => prev.map(d => d.id === updatedDoc.id ? { ...d, ...updatedDoc, verdict } : d));
    if (selectedDoc && selectedDoc.id === updatedDoc.id) {
      setSelectedDoc(prev => ({ ...prev, ...updatedDoc, verdict }));
    }
    toast.success(`Judicial Verdict sealed & locked on Case ${updatedDoc.firNo}!`);
  };

  // Dynamic font scaling
  const fontScaleClass = 
    fontSizeLevel === 1 ? 'text-[115%]' : 
    fontSizeLevel === -1 ? 'text-[90%]' : '';

  const t = translations[lang] || translations.en;

  return (
    <div className={`min-h-screen w-full flex flex-col bg-[#FFF9F2] dark:bg-slate-950 text-slate-900 dark:text-slate-100 overflow-x-hidden ${highContrast ? 'contrast-125' : ''} ${fontScaleClass}`}>
      
      {/* 1. Top Micro-Strip with Dark Mode Toggle & Accessibility */}
      <TopMicroStrip
        lang={lang}
        onToggleLang={handleToggleLang}
        fontSizeLevel={fontSizeLevel}
        onChangeFontSize={handleChangeFontSize}
        highContrast={highContrast}
        onToggleHighContrast={handleToggleHighContrast}
        darkMode={darkMode}
        onToggleDarkMode={handleToggleDarkMode}
        onOpenShortcuts={() => setShortcutsOpen(true)}
      />

      {/* 2. Main Header with Official Ashoka Stambh Emblem */}
      <MainHeader lang={lang} />

      {/* 3. Primary Navbar with Single Login and Single Sign Out Button */}
      <Navbar
        currentTab={selectedDoc || isViewingChain ? 'cases' : currentTab}
        onSelectTab={handleSelectTab}
        activeUser={activeUser}
        onOpenLogin={handleOpenRoleLogin}
        onLogout={handleLogout}
        personas={personas}
        onSwitchPersona={handleSwitchPersona}
        onOpenUpload={() => setUploadModalOpen(true)}
        lang={lang}
        onToggleMobileSidebar={() => setMobileSidebarOpen(prev => !prev)}
        isDashboardActive={currentTab === 'dashboard' || currentTab === 'cases'}
      />

      {/* 4. Real Indian Flag Banner (Full-Width Saffron/White/Green with Navy Ashoka Chakra) */}
      <FlagBanner />

      {/* 5. Main Content Area */}
      <main className="flex-1 flex flex-col w-full min-w-0">
        
        {/* Dedicated Single Unified Login View (/login) */}
        {currentTab === 'login' ? (
          <LoginPage
            onLoginSuccess={handleLoginSuccess}
            onCancel={() => setCurrentTab('home')}
            initialRole={loginRoleIntent}
            personas={personas}
          />
        ) : selectedDoc && !isViewingChain ? (
          /* Dedicated Real Indian FIR Document Viewer (CrPC 154) */
          <DocumentDetailView
            document={selectedDoc}
            onRequestEdit={handleRequestEdit}
            onOpenQuorum={handleOpenQuorum}
            activeUser={activeUser}
            onBackToDashboard={() => setSelectedDoc(null)}
            lang={lang}
          />
        ) : isViewingChain ? (
          /* Version Chain & Lineage Comparison View */
          <VersionChainView
            document={selectedDoc || documents[1] || documents[0]}
            onBack={() => setIsViewingChain(false)}
            allDocuments={documents}
            onSelectDocument={handleSelectDocument}
            lang={lang}
          />
        ) : currentTab === 'home' ? (
          /* Purely Informational Public Landing Page */
          <LandingPage
            onOpenRoleLogin={handleOpenRoleLogin}
            onGoToDashboard={() => {
              if (!activeUser) {
                handleOpenRoleLogin('POLICE');
              } else {
                handleSelectTab('dashboard');
              }
            }}
            onGoToCitizen={() => handleSelectTab('citizen')}
            activeUser={activeUser}
            metrics={metrics}
            lang={lang}
          />
        ) : currentTab === 'citizen' ? (
          /* Citizen Record Portal */
          <CitizenPortalView
            lang={lang}
            activeUser={activeUser}
            onBackToHome={() => handleSelectTab('home')}
          />
        ) : currentTab === 'dashboard' || currentTab === 'cases' ? (
          /* Role-Based Dedicated Dashboard View */
          <DashboardView
            documents={documents}
            metrics={metrics}
            onSelectDocument={handleSelectDocument}
            onOpenUpload={(file) => {
              setUploadFile(file);
              setUploadModalOpen(true);
            }}
            onOpenQuorum={handleOpenQuorum}
            onGoToAudit={() => handleSelectTab('audit')}
            onGoToChain={handleGoToChain}
            onNavigateToApprovals={() => setCurrentTab('approvals')}
            activeUser={activeUser}
            onSelectTab={handleSelectTab}
            lang={lang}
            mobileSidebarOpen={mobileSidebarOpen}
            onCloseMobileSidebar={() => setMobileSidebarOpen(false)}
            onOpenMobileSidebar={() => setMobileSidebarOpen(true)}
            darkMode={darkMode}
            onToggleDark={handleToggleDarkMode}
            onToggleLang={handleToggleLang}
            onVerdictSuccess={handleVerdictSuccess}
          />
        ) : currentTab === 'approvals' ? (
          /* Dedicated Quorum Approvals Page (/approvals per Section 12) */
          <ApprovalsView
            documents={documents}
            onVoteSuccess={handleVoteSuccess}
            onBack={() => setCurrentTab('dashboard')}
            onBackToDashboard={() => setCurrentTab('dashboard')}
            activeUser={activeUser}
            lang={lang}
          />
        ) : currentTab === 'audit' ? (
          /* WORM Audit Log View — Judicial only */
          activeUser?.portalRole === 'JUDICIAL' ? (
            <div className="flex-1 bg-[#FFF9F2] dark:bg-slate-950 p-4 sm:p-8">
              <div className="max-w-6xl mx-auto space-y-4">
                <div className="bg-sky-50 dark:bg-sky-950/40 border border-sky-200 dark:border-sky-800 p-4 rounded-2xl flex items-center justify-between text-xs text-sky-800 dark:text-sky-300">
                  <span className="font-semibold">
                    Judicial Oversight: Read-only access to Ministry of Home Affairs WORM cryptographic audit ledger.
                  </span>
                  <span className="font-mono text-[10px] bg-sky-100 dark:bg-sky-900 px-2 py-0.5 rounded font-bold">
                    Immutable Insert-Only
                  </span>
                </div>
                <AuditLogView onBack={() => setCurrentTab('dashboard')} lang={lang} />
              </div>
            </div>
          ) : (
            <div className="flex-1 flex items-center justify-center p-8">
              <div className="text-center space-y-3 bg-white dark:bg-slate-900 p-8 rounded-3xl border border-rose-300 dark:border-rose-900 max-w-md">
                <h3 className="font-bold text-rose-600">Access Restricted</h3>
                <p className="text-xs text-slate-500">The WORM cryptographic audit trail is restricted to Judicial Authorities only.</p>
                <button
                  onClick={() => setCurrentTab('home')}
                  className="px-4 py-2 bg-[#FF6A1A] text-white text-xs font-bold rounded-xl cursor-pointer"
                >
                  Return to Home
                </button>
              </div>
            </div>
          )
        ) : currentTab === 'contact' ? (
          <ContactView lang={lang} onBack={() => handleSelectTab('home')} />
        ) : currentTab === 'about' ? (
          <AboutView lang={lang} />
        ) : currentTab === 'sitemap' ? (
          <SitemapView lang={lang} />
        ) : currentTab === 'terms' ? (
          <TermsView lang={lang} />
        ) : currentTab === 'privacy' ? (
          <PrivacyView lang={lang} />
        ) : currentTab === 'accessibility' ? (
          <AccessibilityView lang={lang} />
        ) : currentTab === 'copyright' ? (
          <CopyrightView lang={lang} />
        ) : currentTab === 'disclaimer' ? (
          <DisclaimerView lang={lang} />
        ) : (
          <LandingPage
            onOpenRoleLogin={handleOpenRoleLogin}
            onGoToDashboard={() => handleSelectTab('dashboard')}
            onGoToCitizen={() => handleSelectTab('citizen')}
            activeUser={activeUser}
            metrics={metrics}
            lang={lang}
          />
        )}

      </main>
      {/* Modals & Dialogs */}
      {uploadModalOpen && (
        <UploadModal
          isOpen={uploadModalOpen}
          onClose={() => {
            setUploadModalOpen(false);
            setUploadFile(null);
          }}
          initialFile={uploadFile}
          onUploadSuccess={handleUploadSuccess}
          activeUser={activeUser}
        />
      )}

      {quorumModalOpen && activeQuorumDoc && (
        <QuorumModal
          isOpen={quorumModalOpen}
          onClose={() => setQuorumModalOpen(false)}
          document={activeQuorumDoc}
          activeUser={activeUser}
          onVoteSuccess={handleVoteSuccess}
          onFinalizeSuccess={handleFinalizeSuccess}
          onSwitchUser={handleDemoApproverLogin}
        />
      )}

      {shortcutsOpen && (
        <ShortcutsModal
          isOpen={shortcutsOpen}
          onClose={() => setShortcutsOpen(false)}
          onToggleDarkMode={() => setDarkMode(prev => !prev)}
          onNavigateHome={() => {
            setCurrentTab('home');
            setSelectedDoc(null);
            setShortcutsOpen(false);
          }}
          onNavigateLogin={() => {
            setCurrentTab('login');
            setSelectedDoc(null);
            setShortcutsOpen(false);
          }}
          onOpenSearch={() => {
            setShortcutsOpen(false);
            const searchInput = document.querySelector('input[type="text"], input[type="search"]');
            if (searchInput) searchInput.focus();
          }}
        />
      )}

      {/* Floating Back to Top Button (Section 14) */}
      <BackToTop />

    </div>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <AppContent />
    </ToastProvider>
  );
}
