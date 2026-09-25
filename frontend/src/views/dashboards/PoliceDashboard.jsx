import React, { useState } from 'react';
import { 
  Shield, 
  FolderArchive, 
  FileEdit, 
  Clock, 
  CheckCircle2, 
  UploadCloud, 
  GitBranch, 
  Bell, 
  ArrowRight, 
  Sparkles, 
  MapPin, 
  Calendar, 
  AlertCircle, 
  FileText, 
  FileCheck, 
  Hash, 
  Layers, 
  Activity,
  User,
  Settings as SettingsIcon,
  Eye,
  AlertTriangle,
  Lock,
  Gavel
} from 'lucide-react';
import { translations } from '../../i18n/translations';
import DragDropUploader from '../../components/DragDropUploader';
import { useToast } from '../../context/ToastContext';
import RoleSettingsPanel from '../../components/RoleSettingsPanel';
import ProfileCard from '../../components/ProfileCard';


/**
 * Police Dashboard per Master Spec Section 7 & 20.4:
 * - Dedicated saffron accent sidebar: Home, My Cases, Upload New FIR, My Edit Requests, Chain of Custody, Notifications, Settings
 * - Scoped strictly to FIRs only (Section 20.4)
 * - Drag-and-drop upload zone leading into OCR Review step
 * - My Edit Requests with status chips (Pending Quorum / Approved / Rejected)
 * - Chain of Custody mini timeline (plain language, no raw hashes)
 * - NO audit log link anywhere
 */
export default function PoliceDashboard({ 
  documents = [], 
  metrics, 
  onSelectDocument, 
  onOpenUpload, 
  onOpenQuorum, 
  onGoToChain,
  activeUser,
  activeTab = 'overview',
  lang = 'en',
  darkMode = false,
  onToggleDark,
  onToggleLang
}) {
  const t = translations[lang] || translations.en;
  const toast = useToast();
  const [droppedFile, setDroppedFile] = useState(null);

  // Filter strictly to this officer's own cases by requesterId
  const myCases = documents.filter(d => (d.requesterId || d.uploaded_by || d.created_by) === activeUser?.id);
  const pendingRequests = myCases.filter(d => {
    const activeReq = d.activeEditRequest || d.active_edit_request || {};
    const status = activeReq.status || d.status;
    if (status === 'APPROVED' || status === 'REJECTED' || status === 'LOCKED') return false;
    return status === 'PENDING' || status === 'PENDING_QUORUM' || status === 'PENDING_AMENDMENT';
  });

  const custodyEvents = [
    { step: "Seizure Memo Form No. 24 Issued", time: "14/08/2024 10:45 IST", actor: "Police Official (Investigating Officer)", status: "Completed" },
    { step: "Initial Formal FIR Sealing", time: "14/08/2024 11:00 IST", actor: "Special Investigation Division PS", status: "Sealed (v1.0)" },
    { step: "Physical Exhibits Transferred to Lab", time: "15/08/2024 14:20 IST", actor: "Forensic Officer (Scientific Examiner)", status: "Exhibits Received" },
    { step: "Supplementary Draft Update Submitted", time: "21/08/2024 09:15 IST", actor: "Police Official (Investigating Officer)", status: "Under Review" }
  ];

  const handleProceedToOcr = () => {
    if (!droppedFile) return;
    if (onOpenUpload) {
      onOpenUpload(droppedFile.file || droppedFile);
    } else {
      toast.info(`Proceeding to OCR text verification for ${droppedFile.name}...`);
    }
  };

  return (
    <div className="space-y-6 w-full">
      
      {/* Top Banner Card */}
      <div className="bg-white dark:bg-slate-900 border border-orange-200 dark:border-slate-800 rounded-3xl p-4 sm:p-8 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-colors w-full">
        <div className="flex items-center space-x-3 sm:space-x-4">
          <div className="w-12 h-12 sm:w-14 sm:h-14 rounded-2xl bg-orange-100 dark:bg-orange-950/60 border border-orange-300 dark:border-orange-800 flex items-center justify-center text-[#FF6A1A] shadow-xs flex-shrink-0">
            <Shield className="w-6 h-6 sm:w-7 sm:h-7" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-lg sm:text-xl font-bold text-slate-900 dark:text-slate-100 tracking-tight font-serif">
                Police / Investigating Officer Terminal
              </h2>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase bg-orange-100 dark:bg-orange-950 text-[#FF6A1A] border border-orange-200 dark:border-orange-800">
                Law Enforcement Cadre
              </span>
            </div>
            <p className="text-[11px] sm:text-xs text-slate-500 dark:text-slate-400 mt-1 font-sans">
              Investigating Officer: <strong className="text-slate-800 dark:text-slate-200">{activeUser?.name}</strong> • Station: <span className="text-[#FF6A1A] font-semibold">{activeUser?.policeStation || "Special Investigation Division PS, Mandir Marg"}</span>
            </p>
          </div>
        </div>

        <button
          onClick={() => onOpenUpload(null)}
          className="px-4 sm:px-5 py-2.5 bg-[#FF6A1A] hover:bg-[#E85B0E] text-white font-bold rounded-xl text-xs shadow-md hover:shadow-lg transition-all flex items-center justify-center gap-2 cursor-pointer w-full sm:w-auto"
        >
          <FileText className="w-4 h-4" />
          <span>+ Register New FIR</span>
        </button>
      </div>

      {/* VIEW 1: UPLOAD NEW FIR (Section 7 & 20.4) */}
      {activeTab === 'upload' && (
        <div className="bg-white dark:bg-slate-900 border border-orange-300 dark:border-orange-700/60 rounded-3xl p-4 sm:p-8 shadow-sm space-y-5 animate-in fade-in w-full">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800 pb-4">
            <div>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase bg-orange-100 dark:bg-orange-950 text-[#FF6A1A] border border-orange-200 dark:border-orange-800">
                FIR Ingestion Gateway
              </span>
              <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 mt-1 font-serif">
                Upload New FIR (CrPC Section 154 / BNSS Section 173)
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 font-sans">
                Drag and drop scanned FIR dockets. Leads directly into human-in-the-loop OCR review before cryptographic sealing.
              </p>
            </div>
          </div>

          <DragDropUploader
            onFileSelect={setDroppedFile}
            label="Drag & Drop Scanned FIR Document or Case Diary"
            hint="Supports PDF, TIFF, PNG up to 50MB (AES-256 encrypted at rest)"
            roleColor="#FF6A1A"
          />

          {droppedFile && (
            <div className="p-4 bg-orange-50 dark:bg-orange-950/40 border border-orange-200 dark:border-orange-800/80 rounded-2xl flex flex-col sm:flex-row items-center justify-between gap-3">
              <div className="space-y-0.5 text-xs text-slate-700 dark:text-slate-300">
                <div className="font-bold text-slate-900 dark:text-slate-100">Ready for OCR Text Extraction:</div>
                <div className="font-mono text-[11px] text-slate-500">{droppedFile.name} ({(droppedFile.size / 1024 / 1024).toFixed(2)} MB)</div>
              </div>

              <button
                onClick={handleProceedToOcr}
                className="px-5 py-2.5 bg-[#FF6A1A] hover:bg-[#e05910] text-white text-xs font-bold rounded-xl shadow-xs transition-all flex items-center gap-2 cursor-pointer w-full sm:w-auto justify-center"
              >
                <span>Proceed to OCR Review Step</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>
      )}

      {/* VIEW 2: MY CASES */}
      {activeTab === 'cases' && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-6 sm:p-8 shadow-xs space-y-5 animate-in fade-in">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-4">
            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 font-serif">
                Assigned Case Records & Active Investigations
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-sans">
                List of FIRs registered under your investigating jurisdiction
              </p>
            </div>
            <span className="text-xs font-mono font-bold text-slate-500">{myCases.length} Records</span>
          </div>

          <div className="space-y-3">
            {myCases.map(doc => (
              <div 
                key={doc.id}
                className="p-4 rounded-2xl border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-850 hover:border-orange-300 dark:hover:border-orange-700 transition-all space-y-3"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs font-bold text-slate-900 dark:text-slate-100 bg-white dark:bg-slate-800 px-2 py-0.5 rounded border border-slate-200 dark:border-slate-700">
                        {doc.firNo}
                      </span>
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300">
                        v{doc.currentVersion} Locked
                      </span>
                      {doc.verdict && (
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-sky-100 dark:bg-sky-950 text-sky-800 dark:text-sky-300 border border-sky-200 dark:border-sky-800 flex items-center gap-1">
                          <Gavel className="w-3 h-3 text-[#4FA8E0]" />
                          <span>Verdict Delivered</span>
                        </span>
                      )}
                      {doc.status === 'PENDING_QUORUM' && (
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300">
                          Draft Pending Review
                        </span>
                      )}
                    </div>
                    <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100 font-serif">
                      {doc.caseTitle}
                    </h4>
                    <p className="text-xs text-slate-500 dark:text-slate-400 font-sans">
                      Acts: <strong>{doc.actsAndSections}</strong>
                    </p>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => onSelectDocument && onSelectDocument(doc)}
                      className="px-3.5 py-1.5 bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-bold rounded-xl border border-slate-200 dark:border-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      <span>View FIR</span>
                    </button>
                    {!doc.verdict && (
                      <button
                        onClick={() => onSelectDocument && onSelectDocument(doc)}
                        className="px-3.5 py-1.5 bg-orange-50 dark:bg-orange-950 text-[#FF6A1A] hover:bg-orange-100 text-xs font-bold rounded-xl border border-orange-200 dark:border-orange-800 transition-colors flex items-center gap-1.5 cursor-pointer"
                      >
                        <FileEdit className="w-3.5 h-3.5" />
                        <span>Request Edit</span>
                      </button>
                    )}
                  </div>
                </div>

                {/* Read-Only Verdict Card for Police Officer */}
                {doc.verdict && (
                  <div className="p-3.5 rounded-xl bg-sky-50/80 dark:bg-sky-950/40 border border-sky-200 dark:border-sky-800 space-y-2 text-xs">
                    <div className="flex items-center justify-between font-bold text-sky-950 dark:text-sky-200">
                      <span className="flex items-center gap-1.5">
                        <Gavel className="w-3.5 h-3.5 text-[#4FA8E0]" />
                        <span>Judicial Ruling & Final Judgment (Read-Only)</span>
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-sky-100 dark:bg-sky-900 text-[#4FA8E0]">
                        {doc.verdict.disposition}
                      </span>
                    </div>
                    <div className="text-slate-800 dark:text-slate-200 font-serif">
                      {doc.verdict.verdictTitle} — {doc.verdict.bench || doc.verdict.presidingCourt}
                    </div>
                    {doc.verdict.summary && (
                      <p className="text-[11px] text-slate-600 dark:text-slate-400 italic line-clamp-2">
                        "{doc.verdict.summary}"
                      </p>
                    )}
                    <div className="flex flex-wrap items-center gap-2 sm:gap-3 text-[10px] text-slate-500 dark:text-slate-400 font-mono pt-1 border-t border-sky-100 dark:border-sky-900/60">
                      <span>Presiding: {doc.verdict.judgeName} ({doc.verdict.judgeBadge})</span>
                      <span>•</span>
                      <span>Pronounced: {new Date(doc.verdict.deliveredAt).toLocaleDateString()}</span>
                      <span>•</span>
                      <span>Digest: {doc.verdict.fileSha256?.substring(0, 16)}...</span>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* VIEW 3: MY REQUESTS (QUORUM STATUS) — Master Spec Section 7 & 12 */}
      {(activeTab === 'my_requests' || activeTab === 'edits') && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-6 sm:p-8 shadow-xs space-y-6 animate-in fade-in">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 dark:border-slate-800 pb-4">
            <div>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-800">
                Requester Scrutiny View
              </span>
              <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 mt-1 font-serif">
                My Requests (Quorum Status)
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-sans">
                Read-only tracking of your submitted amendment dockets. Requesters cannot vote on their own requests (Rule 4B lock).
              </p>
            </div>
            <span className="px-3 py-1 bg-amber-50 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-800 rounded-xl text-xs font-bold font-mono self-start sm:self-auto">
              {pendingRequests.length} Active Requests
            </span>
          </div>

          {pendingRequests.length === 0 ? (
            <div className="text-center py-10 space-y-2">
              <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto" />
              <div className="text-xs font-bold text-slate-800 dark:text-slate-200">No Pending Quorum Requests</div>
              <p className="text-[11px] text-slate-500 max-w-sm mx-auto">
                All supplementary reports submitted by your station have been verified and sealed into the permanent ledger.
              </p>
            </div>
          ) : (
            <div className="space-y-5">
              {myCases.filter(d => !!(d.editRequestId || d.activeEditRequest || d.active_edit_request)).map(doc => {
                const activeReq = doc.activeEditRequest || doc.active_edit_request || doc.quorum_data?.request || doc.quorum_data || {};
                const threshold = activeReq.threshold_m || activeReq.threshold || doc.quorumSession?.threshold || 2;
                const totalEligible = activeReq.pool_size_n || activeReq.totalEligible || doc.quorumSession?.totalEligible || 3;
                const votes = activeReq.votes || activeReq.quorum_data?.votes || doc.quorumSession?.votes || [];
                const voteCounts = activeReq.vote_counts || activeReq.quorum_data?.vote_counts;

                const approvalCount = voteCounts?.approve !== undefined 
                  ? voteCounts.approve 
                  : (doc.quorumSession?.approvalCount !== undefined 
                      ? doc.quorumSession.approvalCount 
                      : votes.filter(v => (v.vote_choice || v.vote) === 'APPROVE').length);

                const poolMembers = activeReq.approval_pool || [];

                const approverSlots = (doc.quorumSession?.approverSlots && doc.quorumSession.approverSlots.length > 0)
                  ? doc.quorumSession.approverSlots
                  : Array.from({ length: totalEligible }, (_, i) => {
                      const member = poolMembers[i];
                      const voteObj = votes[i];
                      const hasVoted = !!voteObj;
                      const voteChoice = voteObj?.vote_choice || voteObj?.vote || null;
                      const title = member?.pseudonym || voteObj?.pseudonym || `Approver ${i + 1}`;
                      return {
                        slotIndex: i + 1,
                        title,
                        hasVoted,
                        vote: voteChoice
                      };
                    });

                const session = {
                  threshold,
                  totalEligible,
                  approvalCount,
                  poolLabel: doc.jurisdictionalPool || "District Police Review Pool",
                  approverSlots
                };
                const progressPct = Math.min(100, Math.round((approvalCount / threshold) * 100));
                const isReqApproved = activeReq.status === 'APPROVED' || doc.status === 'APPROVED' || doc.currentVersion === '1.1';

                return (
                  <div 
                    key={doc.id}
                    className={`p-6 rounded-3xl border space-y-4 shadow-xs ${
                      isReqApproved 
                        ? 'border-emerald-200 dark:border-emerald-900/60 bg-emerald-50/30 dark:bg-emerald-950/20' 
                        : 'border-amber-200 dark:border-amber-900/60 bg-amber-50/30 dark:bg-amber-950/20'
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-amber-200/50 dark:border-amber-900/40 pb-3">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-slate-900 dark:text-slate-100 bg-white dark:bg-slate-800 px-2.5 py-0.5 rounded border border-slate-200 dark:border-slate-700">
                          {doc.firNo}
                        </span>
                        <span className="text-xs font-bold text-amber-700 dark:text-amber-300">
                          Draft v{doc.draftVersion || doc.currentVersion || '1.1'}
                        </span>
                      </div>

                      <div className="flex flex-wrap items-center gap-2">
                        {isReqApproved ? (
                          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800">
                            🟢 Consensus Approved & Sealed
                          </span>
                        ) : (
                          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800">
                            🔴 Pending Quorum
                          </span>
                        )}
                        <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700 flex items-center gap-1">
                          <Lock className="w-3 h-3 text-amber-600" />
                          <span>Rule 4B Self-Approval Locked</span>
                        </span>
                      </div>
                    </div>

                    <div className="space-y-1">
                      <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100 font-serif">
                        {doc.caseTitle}
                      </h4>
                      <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed font-sans">
                        {doc.draftData?.editSummary || doc.versions?.find(v => v.version === doc.draftVersion)?.summaryDiff || "Supplementary findings and charge details submitted for peer review."}
                      </p>
                    </div>

                    {/* Progress Indicator & Peer Approvers Status */}
                    <div className="space-y-2 bg-white dark:bg-slate-900 p-4 rounded-2xl border border-amber-200/60 dark:border-amber-900/30">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-bold text-slate-800 dark:text-slate-200">
                          Consensus Progress:
                        </span>
                        <span className="font-mono text-xs font-semibold text-slate-600 dark:text-slate-400">
                          {approvalCount} of {threshold} approvals received ({session.totalEligible || 3} eligible slots)
                        </span>
                      </div>

                      <div className="w-full h-2 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden border border-slate-200 dark:border-slate-700">
                        <div 
                          className="h-full bg-[#5FA777] transition-all duration-500 rounded-full"
                          style={{ width: `${progressPct}%` }}
                        />
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-2">
                        {(session.approverSlots || []).map((slot, idx) => (
                          <div 
                            key={idx}
                            className={`p-2 rounded-xl border text-xs flex items-center justify-between ${
                              slot.hasVoted 
                                ? 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300' 
                                : 'bg-slate-50 dark:bg-slate-850 border-slate-200 dark:border-slate-700 text-slate-500'
                            }`}
                          >
                            <span className="font-medium">{slot.title || `Approver ${idx + 1}`}</span>
                            <span className="text-[10px] font-bold font-mono">
                              {slot.hasVoted ? 'Approved' : 'Pending'}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="text-[11px] text-slate-500 dark:text-slate-400 flex flex-col sm:flex-row sm:items-center justify-between gap-1 pt-1">
                      <span>Routing: <strong className="text-slate-800 dark:text-slate-200">{session.poolLabel || doc.jurisdictionalPool || "District Police Review Pool"}</strong></span>
                      <span className="text-amber-700 dark:text-amber-300 font-medium">Read-Only View: Police cannot vote on own submitted requests</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* VIEW 5: OVERVIEW (Default) */}
      {activeTab === 'overview' && (
        <div className="space-y-6 animate-in fade-in">

          {/* Profile Card — identity + My Work snapshot */}
          <ProfileCard
            activeUser={activeUser}
            role="POLICE"
            documents={documents}
            lang={lang}
            onGoToSettings={() => {}}
          />

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 sm:gap-6">
            
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-6 shadow-xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  Active Cases Assigned
                </span>
                <div className="w-8 h-8 rounded-xl bg-orange-50 dark:bg-orange-950 text-[#FF6A1A] flex items-center justify-center">
                  <FolderArchive className="w-4 h-4" />
                </div>
              </div>
              <div className="text-3xl font-extrabold text-slate-900 dark:text-slate-100">
                {myCases.length}
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Active investigation dockets under CrPC Section 154
              </p>
            </div>

            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-6 shadow-xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  Pending Edit Requests
                </span>
                <div className="w-8 h-8 rounded-xl bg-amber-50 dark:bg-amber-950 text-amber-500 flex items-center justify-center">
                  <Clock className="w-4 h-4" />
                </div>
              </div>
              <div className="text-3xl font-extrabold text-amber-600">
                {pendingRequests.length}
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Supplementary reports awaiting independent peer review
              </p>
            </div>

            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-6 shadow-xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  Cryptographic Ledger Health
                </span>
                <div className="w-8 h-8 rounded-xl bg-emerald-50 dark:bg-emerald-950 text-[#5FA777] flex items-center justify-center">
                  <CheckCircle2 className="w-4 h-4" />
                </div>
              </div>
              <div className="text-3xl font-extrabold text-slate-900 dark:text-slate-100">
                100% Sealed
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                AES-256 encrypted at rest with automated tamper detection
              </p>
            </div>

          </div>

          {/* Quorum Status Widget: Your Requests */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-6 shadow-xs space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm font-bold text-slate-800 dark:text-slate-200">
                <FileCheck className="w-5 h-5 text-[#FF6A1A]" />
                <span>Quorum Status: Your Requests</span>
              </div>
              <button 
                onClick={() => onGoToChain && onGoToChain('my_requests')}
                className="text-xs text-[#FF6A1A] hover:underline font-bold"
              >
                View All
              </button>
            </div>
            
            {pendingRequests.length > 0 ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {pendingRequests.slice(0, 4).map(doc => {
                  const required = doc.quorum?.required || 3;
                  const current = doc.quorum?.current || 0;
                  return (
                    <div key={doc.id} className="p-3 rounded-xl border border-slate-100 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 flex flex-col justify-between">
                      <div className="flex justify-between items-start mb-2">
                        <span className="text-xs font-bold font-mono text-slate-900 dark:text-white">{doc.firNo}</span>
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300">
                          Pending Quorum
                        </span>
                      </div>
                      <div className="text-xs text-slate-500 dark:text-slate-400 mb-2 truncate">
                        {doc.caseTitle}
                      </div>
                      <div className="w-full bg-slate-200 dark:bg-slate-700 rounded-full h-1.5 mb-1">
                        <div 
                          className="bg-[#FF6A1A] h-1.5 rounded-full transition-all" 
                          style={{ width: `${(current / required) * 100}%` }}
                        ></div>
                      </div>
                      <div className="text-[10px] text-slate-500 dark:text-slate-400 font-medium">
                        {current} of {required} approved
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="p-6 text-center border border-dashed border-slate-200 dark:border-slate-700 rounded-2xl bg-slate-50/50 dark:bg-slate-800/30">
                <p className="text-sm font-semibold text-slate-600 dark:text-slate-400">You have no active requests.</p>
                <p className="text-xs text-slate-500 mt-1">When you request edits, their quorum approval progress will appear here.</p>
              </div>
            )}
          </div>

          <div className="p-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl space-y-3">
            <div className="flex items-center gap-2 text-sm font-bold text-slate-800 dark:text-slate-200">
              <Activity className="w-4 h-4 text-[#FF6A1A]" />
              <span>Recent Investigation Activity Feed</span>
            </div>
            <div className="divide-y divide-slate-100 dark:divide-slate-800 text-xs">
              <div className="py-2.5 flex items-center justify-between">
                <div>
                  <strong>FIR 0842/2024:</strong> Physical MicroSD evidence exhibits verified and locked.
                </div>
                <span className="text-[10px] text-slate-400 font-mono">14 Aug 2024</span>
              </div>
              <div className="py-2.5 flex items-center justify-between">
                <div>
                  <strong>FIR 1920/2024:</strong> Supplementary charge amendment submitted to State Review Pool.
                </div>
                <span className="text-[10px] text-slate-400 font-mono">21 Aug 2024</span>
              </div>
            </div>
          </div>
        </div>
      )}
      {/* VIEW: SETTINGS */}
      {activeTab === 'settings' && (
        <RoleSettingsPanel
          activeUser={activeUser}
          role="POLICE"
          lang={lang}
          darkMode={darkMode}
          onToggleDark={onToggleDark}
          onToggleLang={onToggleLang}
        />
      )}

    </div>
  );
}
