import React, { useState, useRef, useEffect } from 'react';
import { 
  Home, 
  LayoutDashboard, 
  FolderArchive, 
  UploadCloud, 
  FileCheck2, 
  ScrollText, 
  HelpCircle, 
  ChevronDown, 
  LogOut, 
  User, 
  ShieldCheck, 
  Search, 
  ExternalLink, 
  BookOpen, 
  FileText,
  Lock,
  Layers,
  Scale,
  Microscope,
  FileCheck,
  Menu,
  X,
  Shield,
  Bell,
  Check
} from 'lucide-react';
import { translations } from '../i18n/translations';

export default function Navbar({ 
  currentTab, 
  onSelectTab, 
  activeUser, 
  onOpenLogin, 
  onLogout, 
  personas = [], 
  onSwitchPersona, 
  onOpenUpload,
  lang = 'en',
  onToggleMobileSidebar,
  isDashboardActive = false
}) {
  const t = translations[lang] || translations.en;
  
  const [casesMenuOpen, setCasesMenuOpen] = useState(false);
  const [helpMenuOpen, setHelpMenuOpen] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);

  const casesRef = useRef(null);
  const helpRef = useRef(null);
  const notifRef = useRef(null);

  // Mock notifications based on role
  const [notifications, setNotifications] = useState(activeUser ? [
    ...(activeUser.portalRole === 'POLICE' ? [
      { id: 1, text: 'Your edit on FIR-2026-089 is pending quorum.', unread: true },
      { id: 2, text: 'Quorum approved your edit on FIR-2026-091.', unread: true }
    ] : []),
    ...(activeUser.portalRole === 'JUDICIAL' ? [
      { id: 3, text: 'Pending approval for FIR-2026-089 (2 of 3 received).', unread: true },
      { id: 4, text: 'New verdict uploaded successfully.', unread: false }
    ] : []),
    ...(activeUser.portalRole === 'FORENSIC' ? [
      { id: 5, text: 'Your uploaded report was approved.', unread: true },
      { id: 6, text: 'Pending approval for FIR-2026-089.', unread: true }
    ] : [])
  ] : []);

  const unreadCount = notifications.filter(n => n.unread).length;

  const markAllRead = () => {
    setNotifications(notifications.map(n => ({ ...n, unread: false })));
  };

  // Close dropdowns on outside click
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (casesRef.current && !casesRef.current.contains(event.target)) setCasesMenuOpen(false);
      if (helpRef.current && !helpRef.current.contains(event.target)) setHelpMenuOpen(false);
      if (notifRef.current && !notifRef.current.contains(event.target)) setNotificationsOpen(false);
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const getRoleDotColor = (role) => {
    switch (role) {
      case 'POLICE': return 'bg-[#FF6A1A]';
      case 'JUDICIAL': return 'bg-[#4FA8E0]';
      case 'FORENSIC': return 'bg-[#5FA777]';
      case 'CITIZEN': return 'bg-slate-500';
      default: return 'bg-slate-400';
    }
  };

  return (
    <nav className="bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 sticky top-0 z-40 shadow-xs select-none transition-colors">
      <div className="w-full px-3 sm:px-6 flex items-center justify-between h-[54px]">
        
        {/* ================= DESKTOP NAVIGATION TABS (Hidden on Mobile) ================= */}
        <div className="hidden md:flex items-center space-x-1 sm:space-x-1.5">
          {!activeUser && (
            <>
              {/* 1. Home */}
              <button
                onClick={() => onSelectTab('home')}
                className={`px-3 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                  currentTab === 'home'
                    ? 'bg-[#FF6A1A] text-white shadow-sm'
                    : 'text-slate-700 dark:text-slate-300 hover:text-[#FF6A1A] dark:hover:text-[#FF6A1A] hover:bg-orange-50/70 dark:hover:bg-slate-800'
                }`}
              >
                <Home className="w-3.5 h-3.5" />
                <span>{t.navHome}</span>
              </button>

              {/* 2. Track My Records */}
              <button
                onClick={() => onSelectTab('citizen')}
                className={`px-3 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                  currentTab === 'citizen'
                    ? 'bg-[#7B93AD] text-white shadow-sm'
                    : 'text-[#57728E] dark:text-slate-300 hover:text-[#38536E] hover:bg-slate-100 dark:hover:bg-slate-800'
                }`}
              >
                <User className="w-3.5 h-3.5" />
                <span>{t.navTrackRecords}</span>
              </button>

              {/* 3. Legal & Guidelines Dropdown */}
              <div className="relative" ref={helpRef}>
                <button
                  onClick={() => setHelpMenuOpen(!helpMenuOpen)}
                  onMouseEnter={() => setHelpMenuOpen(true)}
                  className={`px-3 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-1 cursor-pointer ${
                    currentTab === 'contact' || helpMenuOpen
                      ? 'text-[#FF6A1A] bg-orange-50 dark:bg-slate-800'
                      : 'text-slate-700 dark:text-slate-300 hover:text-[#FF6A1A] hover:bg-orange-50/70 dark:hover:bg-slate-800'
                  }`}
                >
                  <HelpCircle className="w-3.5 h-3.5" />
                  <span className="hidden sm:inline">{t.navHelpAndLegal}</span>
                  <ChevronDown className="w-3 h-3 ml-0.5" />
                </button>

                {helpMenuOpen && (
                  <div 
                    onMouseLeave={() => setHelpMenuOpen(false)}
                    className="absolute top-full left-0 mt-1 w-64 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-xl p-2 z-50 animate-in fade-in slide-in-from-top-1"
                  >
                    <div className="text-[10px] font-bold text-slate-400 uppercase px-3 py-1 tracking-wider border-b border-slate-100 dark:border-slate-800">
                      {t.navHelpAndLegal}
                    </div>
                    <div className="space-y-1 mt-1">
                      <button
                        onClick={() => { onSelectTab('home'); setHelpMenuOpen(false); }}
                        className="w-full text-left px-3 py-2 text-xs font-semibold text-slate-800 dark:text-slate-200 hover:bg-orange-50 dark:hover:bg-slate-800 hover:text-[#FF6A1A] rounded-xl transition-colors flex items-center gap-2"
                      >
                        <BookOpen className="w-3.5 h-3.5 text-slate-400" />
                        <span>{t.navAbout}</span>
                      </button>
                      <button
                        onClick={() => { onSelectTab('contact'); setHelpMenuOpen(false); }}
                        className="w-full text-left px-3 py-2 text-xs font-semibold text-slate-800 dark:text-slate-200 hover:bg-orange-50 dark:hover:bg-slate-800 hover:text-[#FF6A1A] rounded-xl transition-colors flex items-center gap-2"
                      >
                        <FileText className="w-3.5 h-3.5 text-slate-400" />
                        <span>{t.navLegalActs}</span>
                      </button>
                      <button
                        onClick={() => { onSelectTab('contact'); setHelpMenuOpen(false); }}
                        className="w-full text-left px-3 py-2 text-xs font-semibold text-slate-800 dark:text-slate-200 hover:bg-orange-50 dark:hover:bg-slate-800 hover:text-[#FF6A1A] rounded-xl transition-colors flex items-center gap-2"
                      >
                        <ExternalLink className="w-3.5 h-3.5 text-slate-400" />
                        <span>{t.navContact}</span>
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* ================= MOBILE NAVIGATION BAR (< 768px) ================= */}
        <div className="flex md:hidden items-center justify-between w-full">
          {/* Mobile Hamburger Menu Button */}
          <button
            onClick={() => {
              if (isDashboardActive && onToggleMobileSidebar) {
                onToggleMobileSidebar();
              } else {
                setMobileNavOpen(true);
              }
            }}
            className="px-2.5 py-1.5 rounded-xl bg-orange-50 dark:bg-slate-800 border border-orange-200 dark:border-slate-700 text-[#FF6A1A] hover:bg-orange-100 dark:hover:bg-slate-700 transition-colors cursor-pointer flex items-center gap-1.5 shadow-2xs"
            aria-label="Open Navigation Menu"
            title="Open Menu"
          >
            <Menu className="w-4 h-4" />
            <span className="text-xs font-bold text-slate-800 dark:text-slate-200">
              {isDashboardActive ? (lang === 'hi' ? 'कैडर मेन्यू' : 'Cadre Menu') : (lang === 'hi' ? 'मेन्यू' : 'Menu')}
            </span>
          </button>

          {/* Quick Right Side Identifier on Mobile */}
          <div className="flex items-center space-x-2">
            {activeUser ? (
              <div className="flex items-center gap-1.5">
                {/* Mobile Notification Bell */}
                <div className="relative" ref={notifRef}>
                  <button
                    onClick={() => { setNotificationsOpen(!notificationsOpen); setHelpMenuOpen(false); }}
                    className="p-1.5 rounded-lg text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors relative"
                  >
                    <Bell className="w-4 h-4" />
                    {unreadCount > 0 && (
                      <span className="absolute top-1 right-1 w-2 h-2 bg-rose-500 rounded-full border border-white dark:border-slate-900"></span>
                    )}
                  </button>
                  {notificationsOpen && (
                    <div className="absolute top-full right-0 mt-1 w-72 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-xl z-50 overflow-hidden">
                      <div className="p-3 border-b border-slate-100 dark:border-slate-800 flex justify-between items-center">
                        <span className="text-xs font-bold text-slate-900 dark:text-white">Notifications</span>
                        {unreadCount > 0 && (
                          <button onClick={markAllRead} className="text-[10px] text-[#FF6A1A] hover:underline font-semibold flex items-center gap-1">
                            <Check className="w-3 h-3" /> Mark all read
                          </button>
                        )}
                      </div>
                      <div className="max-h-64 overflow-y-auto">
                        {notifications.length > 0 ? (
                          notifications.map(n => (
                            <div key={n.id} className={`p-3 text-xs border-b border-slate-50 dark:border-slate-800/50 ${n.unread ? 'bg-orange-50/50 dark:bg-slate-800/50' : ''}`}>
                              <p className={`text-slate-700 dark:text-slate-300 ${n.unread ? 'font-semibold' : ''}`}>{n.text}</p>
                            </div>
                          ))
                        ) : (
                          <div className="p-4 text-center text-xs text-slate-500">No notifications</div>
                        )}
                      </div>
                    </div>
                  )}
                </div>

                <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800">
                  <div className={`w-2 h-2 rounded-full ${getRoleDotColor(activeUser.portalRole)}`}></div>
                  <span className="text-xs font-bold text-slate-800 dark:text-slate-200 truncate max-w-[110px]">
                    {activeUser.name.split(' ')[0]}
                  </span>
                </div>
                <button
                  onClick={onLogout}
                  className="p-1.5 rounded-lg text-slate-500 hover:text-rose-600 dark:text-slate-400 dark:hover:text-rose-400 cursor-pointer"
                  title="Sign Out"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            ) : (
              <button
                onClick={() => onSelectTab('login')}
                className="px-3 py-1.5 rounded-xl bg-[#FF6A1A] text-white text-xs font-bold shadow-xs flex items-center gap-1 cursor-pointer"
              >
                <Lock className="w-3 h-3" />
                <span>Login</span>
              </button>
            )}
          </div>
        </div>

        {/* ================= DESKTOP USER DISPLAY (Hidden on Mobile) ================= */}
        <div className="hidden md:flex items-center space-x-2.5">
          
          {activeUser ? (
            <div className="flex items-center gap-2">
              {/* Desktop Notification Bell */}
              <div className="relative mr-1" ref={notifRef}>
                <button
                  onClick={() => { setNotificationsOpen(!notificationsOpen); setHelpMenuOpen(false); }}
                  className="p-1.5 rounded-lg text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors relative"
                >
                  <Bell className="w-4 h-4" />
                  {unreadCount > 0 && (
                    <span className="absolute top-1 right-1 w-2 h-2 bg-rose-500 rounded-full border border-white dark:border-slate-900"></span>
                  )}
                </button>
                {notificationsOpen && (
                  <div className="absolute top-full right-0 mt-1 w-80 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-xl z-50 overflow-hidden animate-in fade-in slide-in-from-top-1">
                    <div className="p-3 border-b border-slate-100 dark:border-slate-800 flex justify-between items-center bg-slate-50 dark:bg-slate-800/50">
                      <span className="text-xs font-bold text-slate-900 dark:text-white">Notifications</span>
                      {unreadCount > 0 && (
                        <button onClick={markAllRead} className="text-[10px] text-[#FF6A1A] hover:underline font-semibold flex items-center gap-1 cursor-pointer">
                          <Check className="w-3 h-3" /> Mark all read
                        </button>
                      )}
                    </div>
                    <div className="max-h-80 overflow-y-auto">
                      {notifications.length > 0 ? (
                        notifications.map(n => (
                          <div key={n.id} className={`p-3 text-xs border-b border-slate-50 dark:border-slate-800/50 ${n.unread ? 'bg-orange-50/50 dark:bg-slate-800/50 border-l-2 border-l-[#FF6A1A]' : 'border-l-2 border-l-transparent'}`}>
                            <p className={`text-slate-700 dark:text-slate-300 ${n.unread ? 'font-semibold' : ''}`}>{n.text}</p>
                          </div>
                        ))
                      ) : (
                        <div className="p-6 text-center text-xs text-slate-500">No recent notifications</div>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* Authenticated Officer Identifier (Locked to detected role) */}
              <div className="flex items-center space-x-2 px-3 py-1.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800">
                <div className={`w-2.5 h-2.5 rounded-full ${getRoleDotColor(activeUser.portalRole)}`}></div>
                <div className="text-left hidden sm:block">
                  <div className="text-xs font-bold text-slate-900 dark:text-slate-100 leading-tight">
                    {activeUser.name}
                  </div>
                  <div className="text-[10px] text-slate-500 dark:text-slate-400 font-medium font-mono">
                    {activeUser.badge || activeUser.role}
                  </div>
                </div>
              </div>

              {/* Subtle Sign Out Button */}
              <button
                onClick={onLogout}
                className="px-2.5 py-1.5 rounded-xl text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 text-xs font-medium transition-colors flex items-center gap-1.5 cursor-pointer border border-transparent hover:border-slate-200 dark:hover:border-slate-700"
                title="Sign Out"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Sign Out</span>
              </button>
            </div>
          ) : (
            <button
              onClick={() => onSelectTab('login')}
              className="px-4 py-1.5 rounded-xl bg-[#FF6A1A] hover:bg-[#e85b0e] text-white text-xs font-bold shadow-sm transition-all flex items-center gap-1.5 cursor-pointer"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>Login</span>
            </button>
          )}

        </div>

      </div>

      {/* ================= MOBILE SLIDE-IN NAVIGATION DRAWER ================= */}
      {mobileNavOpen && (
        <div className="fixed inset-0 z-50 md:hidden animate-in fade-in duration-200">
          {/* Backdrop Overlay */}
          <div 
            className="fixed inset-0 bg-slate-950/60 backdrop-blur-xs transition-opacity" 
            onClick={() => setMobileNavOpen(false)}
          />

          {/* Slide-in Drawer Container */}
          <aside className="fixed top-0 bottom-0 left-0 w-72 max-w-[85vw] bg-white dark:bg-slate-900 shadow-2xl flex flex-col z-50 border-r border-slate-200 dark:border-slate-800 animate-in slide-in-from-left duration-200">
            
            {/* Drawer Header with Close Button */}
            <div className="p-4 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-orange-100 dark:bg-orange-950 flex items-center justify-center text-[#FF6A1A]">
                  <Shield className="w-4 h-4" />
                </div>
                <span className="font-bold text-sm text-slate-900 dark:text-slate-100">SecureChain DMS</span>
              </div>
              <button
                onClick={() => setMobileNavOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
                title="Close Navigation"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Navigation Tabs List */}
            <div className="p-3 space-y-1 overflow-y-auto flex-1 text-xs font-semibold">
              <button
                onClick={() => { onSelectTab('home'); setMobileNavOpen(false); }}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl transition-colors ${
                  currentTab === 'home' ? 'bg-[#FF6A1A] text-white' : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                }`}
              >
                <Home className="w-4 h-4" />
                <span>{t.navHome}</span>
              </button>

              {activeUser && (
                <button
                  onClick={() => { onSelectTab('dashboard'); setMobileNavOpen(false); }}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl transition-colors ${
                    currentTab === 'dashboard' ? 'bg-[#FF6A1A] text-white' : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                  }`}
                >
                  <LayoutDashboard className="w-4 h-4" />
                  <span>{t.navDashboard}</span>
                </button>
              )}

              {activeUser && activeUser.portalRole !== 'CITIZEN' && (
                <button
                  onClick={() => { onSelectTab('cases'); setMobileNavOpen(false); }}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl transition-colors ${
                    currentTab === 'cases' ? 'bg-[#FF6A1A] text-white' : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                  }`}
                >
                  <FolderArchive className="w-4 h-4" />
                  <span>{t.navCases}</span>
                </button>
              )}

              {activeUser && activeUser.portalRole !== 'CITIZEN' && (
                <button
                  onClick={() => { onSelectTab('approvals'); setMobileNavOpen(false); }}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl transition-colors ${
                    currentTab === 'approvals' ? 'bg-[#FF6A1A] text-white' : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                  }`}
                >
                  <FileCheck2 className="w-4 h-4" />
                  <span>
                    {lang === 'hi' ? 'कोरम अनुमोदन' : 'Quorum Approval'}
                  </span>
                </button>
              )}


              {(!activeUser || activeUser.portalRole === 'CITIZEN') && (
                <button
                  onClick={() => { onSelectTab('citizen'); setMobileNavOpen(false); }}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl transition-colors ${
                    currentTab === 'citizen' ? 'bg-[#7B93AD] text-white' : 'text-[#57728E] dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                  }`}
                >
                  <User className="w-4 h-4" />
                  <span>{t.navTrackRecords}</span>
                </button>
              )}

              <button
                onClick={() => { onSelectTab('contact'); setMobileNavOpen(false); }}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl transition-colors ${
                  currentTab === 'contact' ? 'bg-[#FF6A1A] text-white' : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                }`}
              >
                <HelpCircle className="w-4 h-4" />
                <span>{t.navHelpAndLegal}</span>
              </button>
            </div>

            {/* Officer Profile Badge & Sign Out in Drawer */}
            {activeUser ? (
              <div className="p-4 border-t border-slate-200 dark:border-slate-800 bg-[#FFF9F2] dark:bg-slate-800/60 space-y-3">
                <div>
                  <div className="font-bold text-xs text-slate-900 dark:text-slate-100 truncate">{activeUser.name}</div>
                  <div className="text-[10px] text-slate-500 dark:text-slate-400 truncate">{activeUser.role}</div>
                  <div className="text-[10px] font-mono text-[#FF6A1A] font-bold mt-0.5">ID: {activeUser.badge}</div>
                </div>
                <button
                  onClick={() => { onLogout(); setMobileNavOpen(false); }}
                  className="w-full py-2 bg-slate-200 dark:bg-slate-700 hover:bg-rose-100 dark:hover:bg-rose-950 text-slate-700 dark:text-slate-200 hover:text-rose-700 text-xs font-bold rounded-xl transition-colors flex items-center justify-center gap-2 cursor-pointer"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  <span>Sign Out</span>
                </button>
              </div>
            ) : (
              <div className="p-4 border-t border-slate-200 dark:border-slate-800">
                <button
                  onClick={() => { onOpenLogin('POLICE'); setMobileNavOpen(false); }}
                  className="w-full py-2.5 bg-[#FF6A1A] hover:bg-[#e85b0e] text-white text-xs font-bold rounded-xl shadow-xs transition-all flex items-center justify-center gap-2 cursor-pointer"
                >
                  <Lock className="w-3.5 h-3.5" />
                  <span>Official Sign In</span>
                </button>
              </div>
            )}

          </aside>
        </div>
      )}
    </nav>
  );
}
