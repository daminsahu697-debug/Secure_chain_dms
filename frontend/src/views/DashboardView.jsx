import React, { useState } from 'react';
import { 
  Home, 
  FolderArchive, 
  FileCheck2, 
  ScrollText, 
  FileText, 
  Settings, 
  HelpCircle, 
  Plus, 
  Menu, 
  Bell,
  Shield,
  Scale,
  Microscope,
  ChevronDown,
  ChevronRight,
  Search,
  Filter,
  MoreVertical,
  Calendar,
  Building2,
  Lock,
  Clock,
  Database,
  UploadCloud,
  CheckCircle2,
  Hash,
  Activity,
  Award,
  PackageCheck,
  Layers,
  X,
  FileCheck,
  ShieldAlert,
  Gavel,
  KeyRound,
  Eye,
  ArrowRight
} from 'lucide-react';
import PoliceDashboard from './dashboards/PoliceDashboard';
import JudicialDashboard from './dashboards/JudicialDashboard';
import ForensicDashboard from './dashboards/ForensicDashboard';
import EmptyState from '../components/EmptyState';
import { translations } from '../i18n/translations';

/**
 * Cadre Dashboard View per Master Spec Section 5, 7, 8, 9, 10:
 * - Dedicated role-scoped sidebar links per cadre (nothing extra)
 * - Police: Home, My Cases, Upload New FIR, My Edit Requests, Chain of Custody, Notifications, Settings (Saffron accent)
 * - Judicial: Home, Cases Pending Verification, Upload Verdict, Quorum Approval, WORM Audit Log (read-only), Settings (Chakra-blue accent)
 * - Forensic: Home, Reports Awaiting Upload, Upload New Report, OCR/Analysis Queue, Evidence Chain of Custody, My Pending Reviews, Settings (Sage-green accent)
 * - Auditor: Home, WORM Audit Log, De-anonymize Requests, Emergency Override Review, Verify Integrity, Settings (Purple accent)
 * - Fully responsive with mobile drawer
 */
export default function DashboardView({ 
  documents = [], 
  metrics, 
  onSelectDocument, 
  onOpenUpload, 
  onOpenQuorum, 
  onGoToAudit,
  onGoToChain,
  onNavigateToApprovals,
  activeUser,
  onSelectTab,
  lang = 'en',
  mobileSidebarOpen = false,
  onCloseMobileSidebar,
  onOpenMobileSidebar,
  darkMode = false,
  onToggleDark,
  onToggleLang,
  onVerdictSuccess
}) {
  const t = translations[lang] || translations.en;
  const role = activeUser?.portalRole || 'POLICE';

  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [localMobileOpen, setLocalMobileOpen] = useState(false);
  const isMobileDrawerOpen = mobileSidebarOpen || localMobileOpen;

  const handleCloseMobileDrawer = () => {
    setLocalMobileOpen(false);
    if (onCloseMobileSidebar) onCloseMobileSidebar();
  };

  const handleOpenMobileDrawer = () => {
    setLocalMobileOpen(true);
    if (onOpenMobileSidebar) onOpenMobileSidebar();
  };

  const [activeSidebarTab, setActiveSidebarTab] = useState('overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');

  // Define cadre sidebar tabs strictly scoped to each role (Sections 6, 7, 8, 9, 10, 23)
  const getSidebarTabs = () => {
    const myCasesCount = documents.filter(d => (d.requesterId || d.uploaded_by || d.created_by) === activeUser?.id).length;
    const pendingCount = documents.filter(d => {
      const activeReq = d.activeEditRequest || d.active_edit_request || {};
      const status = activeReq.status || d.status;
      if (status === 'APPROVED' || status === 'REJECTED' || status === 'LOCKED') return false;
      return status === 'PENDING' || status === 'PENDING_QUORUM' || status === 'PENDING_AMENDMENT';
    }).length;

    switch (role) {
      case 'POLICE':
        return [
          { id: 'overview', label: 'Home', icon: Home, badge: null },
          { id: 'cases', label: 'My Cases', icon: FolderArchive, badge: myCasesCount || null },
          { id: 'upload', label: 'Upload New FIR', icon: UploadCloud, badge: null },
          { id: 'my_requests', label: 'My Requests (Quorum Status)', icon: FileCheck, badge: pendingCount || null },
          { id: 'settings', label: 'Settings', icon: Settings, badge: null }
        ];
      case 'JUDICIAL':
        return [
          { id: 'overview', label: 'Home', icon: Home, badge: null },
          { id: 'pending', label: 'Cases Pending Verification', icon: FolderArchive, badge: documents.length },
          { id: 'upload_verdict', label: 'Upload Verdict', icon: Gavel, badge: null },
          { id: 'approvals', label: 'Quorum Approval', icon: FileCheck2, badge: pendingCount || null },
          { id: 'audit', label: 'WORM Audit Log (read-only)', icon: ScrollText, badge: null },
          { id: 'settings', label: 'Settings', icon: Settings, badge: null }
        ];
      case 'FORENSIC':
        return [
          { id: 'overview', label: 'Home', icon: Home, badge: null },
          { id: 'awaiting', label: 'Reports Awaiting Upload', icon: FolderArchive, badge: 3 },
          { id: 'upload', label: 'Upload New Report', icon: UploadCloud, badge: null },
          { id: 'ocr', label: 'OCR/Analysis Queue', icon: Layers, badge: 3 },
          { id: 'custody', label: 'Evidence Chain of Custody', icon: PackageCheck, badge: '2 Sealed' },
          { id: 'my_requests', label: 'My Requests (Quorum Status)', icon: FileCheck, badge: pendingCount || null },
          { id: 'approvals', label: 'Quorum Approval', icon: FileCheck2, badge: pendingCount || null },
          { id: 'settings', label: 'Settings', icon: Settings, badge: null }
        ];
      case 'APPROVAL_OFFICER':
        return [
          { id: 'overview', label: 'Home', icon: Home, badge: null },
          { id: 'cases', label: 'My Cases', icon: FolderArchive, badge: myCasesCount || null },
          { id: 'upload', label: 'Upload New FIR', icon: UploadCloud, badge: null },
          { id: 'approvals', label: 'Quorum Approval', icon: FileCheck2, badge: pendingCount || null },
          { id: 'my_requests', label: 'My Requests (Quorum Status)', icon: FileCheck, badge: pendingCount || null },
          { id: 'settings', label: 'Settings', icon: Settings, badge: null }
        ];
      default:
        return [
          { id: 'overview', label: 'Home', icon: Home, badge: null },
          { id: 'cases', label: 'Case Records', icon: FolderArchive, badge: documents.length }
        ];
    };
  };

  const getRoleTheme = () => {
    switch (role) {
      case 'POLICE':
        return {
          title: "Police / IO Terminal",
          titleHindi: "पुलिस / जांच अधिकारी डैशबोर्ड",
          icon: Shield,
          activeBg: "bg-[#FF6A1A] text-white",
          activeTabBg: "bg-orange-50 dark:bg-orange-950/60 text-[#FF6A1A] border-l-4 border-[#FF6A1A]",
          textAccent: "text-[#FF6A1A]",
          borderAccent: "border-orange-200 dark:border-orange-800",
          tagBg: "bg-orange-100 dark:bg-orange-950 text-[#FF6A1A]"
        };
      case 'JUDICIAL':
        return {
          title: "Judicial Authority Terminal",
          titleHindi: "न्यायिक प्राधिकरण डैशबोर्ड",
          icon: Scale,
          activeBg: "bg-[#4FA8E0] text-white",
          activeTabBg: "bg-sky-50 dark:bg-sky-950/60 text-[#4FA8E0] border-l-4 border-[#4FA8E0]",
          textAccent: "text-[#4FA8E0]",
          borderAccent: "border-sky-200 dark:border-sky-800",
          tagBg: "bg-sky-100 dark:bg-sky-950 text-[#4FA8E0]"
        };
      case 'FORENSIC':
        return {
          title: "Forensic Lab Terminal",
          titleHindi: "फॉरेंसिक प्रयोगशाला डैशबोर्ड",
          icon: Microscope,
          activeBg: "bg-[#5FA777] text-white",
          activeTabBg: "bg-emerald-50 dark:bg-emerald-950/60 text-[#5FA777] border-l-4 border-[#5FA777]",
          textAccent: "text-[#5FA777]",
          borderAccent: "border-emerald-200 dark:border-emerald-800",
          tagBg: "bg-emerald-100 dark:bg-emerald-950 text-[#5FA777]"
        };
      default:
        return {
          title: "Case Dashboard",
          titleHindi: "प्रकरण डैशबोर्ड",
          icon: Shield,
          activeBg: "bg-[#FF6A1A] text-white",
          activeTabBg: "bg-orange-50 dark:bg-orange-950/60 text-[#FF6A1A] border-l-4 border-[#FF6A1A]",
          textAccent: "text-[#FF6A1A]",
          borderAccent: "border-orange-200 dark:border-orange-800",
          tagBg: "bg-orange-100 dark:bg-orange-950 text-[#FF6A1A]"
        };
    }
  };

  const theme = getRoleTheme();
  const HeaderIcon = theme.icon;
  const sidebarTabs = getSidebarTabs();

  const handleTabClick = (tabId) => {
    if (tabId === 'approvals' && onNavigateToApprovals) {
      onNavigateToApprovals();
    } else if (tabId === 'audit' && onGoToAudit) {
      onGoToAudit();
    } else {
      setActiveSidebarTab(tabId);
    }
    handleCloseMobileDrawer();
  };

  return (
    <div className="flex-1 flex bg-[#FFF9F2] dark:bg-slate-950 select-none min-h-[calc(100vh-140px)] w-full transition-colors relative">
      
      {/* MOBILE DRAWER OVERLAY (Below md breakpoint) */}
      {isMobileDrawerOpen && (
        <div 
          onClick={handleCloseMobileDrawer}
          className="fixed inset-0 z-40 bg-slate-900/60 backdrop-blur-xs md:hidden"
        />
      )}

      {/* MOBILE SLIDE-IN DRAWER (Below md breakpoint) */}
      <aside 
        className={`fixed top-0 left-0 bottom-0 z-50 w-72 bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 shadow-2xl flex flex-col justify-between p-4 transition-transform duration-300 ease-in-out md:hidden ${
          isMobileDrawerOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
            <div className="flex items-center space-x-2">
              <div className={`w-8 h-8 rounded-xl ${theme.tagBg} flex items-center justify-center`}>
                <HeaderIcon className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-xs font-bold text-slate-900 dark:text-slate-100">{lang === 'hi' ? theme.titleHindi : theme.title}</h3>
                <span className="text-[10px] text-slate-400 font-mono">{activeUser?.badgeId || activeUser?.id || role}</span>
              </div>
            </div>
            <button
              onClick={handleCloseMobileDrawer}
              className="p-1 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-slate-200"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Navigation Links */}
          <nav className="space-y-1">
            {sidebarTabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeSidebarTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => handleTabClick(tab.id)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                    isActive ? theme.activeTabBg : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
                  }`}
                >
                  <div className="flex items-center space-x-2.5">
                    <Icon className="w-4 h-4 flex-shrink-0" />
                    <span>{tab.label}</span>
                  </div>
                  {tab.badge && (
                    <span className="text-[10px] px-2 py-0.5 rounded-full font-mono font-bold bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-200">
                      {tab.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        <div className="text-[10px] text-slate-400 border-t border-slate-100 dark:border-slate-800 pt-3">
          Ministry of Home Affairs • GOI
        </div>
      </aside>

      {/* DESKTOP SIDEBAR (Visible on md and above) */}
      <aside 
        className={`${
          sidebarOpen ? 'w-64' : 'w-20'
        } bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 flex flex-col justify-between transition-all duration-300 hidden md:flex flex-shrink-0`}
      >
        <div className="p-4 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
            {sidebarOpen ? (
              <div className="flex items-center space-x-2.5">
                <div className={`w-8 h-8 rounded-xl ${theme.tagBg} flex items-center justify-center`}>
                  <HeaderIcon className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-xs font-bold text-slate-900 dark:text-slate-100">
                    {lang === 'hi' ? theme.titleHindi : theme.title}
                  </h3>
                  <span className="text-[10px] text-slate-400 font-mono">
                    {activeUser?.badgeId || activeUser?.id || role}
                  </span>
                </div>
              </div>
            ) : (
              <div className={`w-8 h-8 rounded-xl ${theme.tagBg} flex items-center justify-center mx-auto`}>
                <HeaderIcon className="w-4 h-4" />
              </div>
            )}

            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="p-1 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-slate-200"
              title={sidebarOpen ? "Collapse sidebar" : "Expand sidebar"}
            >
              <Menu className="w-4 h-4" />
            </button>
          </div>

          {/* Nav tabs */}
          <nav className="space-y-1">
            {sidebarTabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeSidebarTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => handleTabClick(tab.id)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                    isActive ? theme.activeTabBg : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
                  }`}
                  title={!sidebarOpen ? tab.label : undefined}
                >
                  <div className="flex items-center space-x-2.5 min-w-0">
                    <Icon className="w-4 h-4 flex-shrink-0" />
                    {sidebarOpen && <span className="truncate">{tab.label}</span>}
                  </div>
                  {sidebarOpen && tab.badge && (
                    <span className="text-[10px] px-2 py-0.5 rounded-full font-mono font-bold bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-200">
                      {tab.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Sidebar Footer */}
        {sidebarOpen && (
          <div className="p-4 border-t border-slate-100 dark:border-slate-800 text-[10px] text-slate-400">
            Govt. of India Legal DMS • v2.0
          </div>
        )}
      </aside>

      {/* MAIN CONTENT AREA */}
      <div className="flex-1 flex flex-col min-w-0 w-full">
        
        {/* Top Mobile Bar with Hamburger Button */}
        <div className="md:hidden bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 px-4 py-2.5 flex items-center justify-between">
          <button
            onClick={handleOpenMobileDrawer}
            className="flex items-center gap-2 text-xs font-bold text-slate-700 dark:text-slate-200 p-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
          >
            <Menu className="w-4 h-4 text-[#FF6A1A]" />
            <span>Cadre Menu</span>
          </button>

          <span className="text-xs font-bold text-slate-800 dark:text-slate-200">
            {sidebarTabs.find(t => t.id === activeSidebarTab)?.label || 'Overview'}
          </span>
        </div>

        {/* Dynamic Cadre Content Renderer */}
        <div className="p-4 sm:p-8 flex-1 w-full">
          {role === 'POLICE' ? (
            <PoliceDashboard
              documents={documents}
              metrics={metrics}
              onSelectDocument={onSelectDocument}
              onOpenUpload={onOpenUpload}
              onOpenQuorum={onOpenQuorum}
              onGoToChain={onGoToChain}
              activeUser={activeUser}
              activeTab={activeSidebarTab}
              onSelectTab={setActiveSidebarTab}
              lang={lang}
              darkMode={darkMode}
              onToggleDark={onToggleDark}
              onToggleLang={onToggleLang}
            />
          ) : role === 'JUDICIAL' ? (
            <JudicialDashboard
              documents={documents}
              metrics={metrics}
              onSelectDocument={onSelectDocument}
              onOpenQuorum={onOpenQuorum}
              onGoToApprovals={onNavigateToApprovals}
              activeUser={activeUser}
              activeTab={activeSidebarTab}
              onSelectTab={setActiveSidebarTab}
              lang={lang}
              darkMode={darkMode}
              onToggleDark={onToggleDark}
              onToggleLang={onToggleLang}
              onVerdictSuccess={onVerdictSuccess}
            />
          ) : role === 'FORENSIC' ? (
            <ForensicDashboard
              documents={documents}
              metrics={metrics}
              onSelectDocument={onSelectDocument}
              onOpenUpload={onOpenUpload}
              onOpenQuorum={onOpenQuorum}
              onNavigateToApprovals={onNavigateToApprovals}
              activeUser={activeUser}
              activeTab={activeSidebarTab}
              onSelectTab={setActiveSidebarTab}
              lang={lang}
              darkMode={darkMode}
              onToggleDark={onToggleDark}
              onToggleLang={onToggleLang}
            />
          ) : (
            <PoliceDashboard
              documents={documents}
              metrics={metrics}
              onSelectDocument={onSelectDocument}
              onOpenUpload={onOpenUpload}
              onOpenQuorum={onOpenQuorum}
              onGoToChain={onGoToChain}
              activeUser={activeUser}
              activeTab={activeSidebarTab}
              onSelectTab={setActiveSidebarTab}
              lang={lang}
              darkMode={darkMode}
              onToggleDark={onToggleDark}
              onToggleLang={onToggleLang}
            />
          )}
        </div>

      </div>

    </div>
  );
}
