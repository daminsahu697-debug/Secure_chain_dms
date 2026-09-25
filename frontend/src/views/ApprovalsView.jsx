import React, { useState } from 'react';
import { 
  FileCheck2, 
  CheckCircle2, 
  Circle, 
  AlertTriangle, 
  ArrowLeft, 
  Clock, 
  ShieldAlert, 
  FolderArchive,
  Info,
  ChevronDown,
  ChevronUp,
  Award,
  Lock,
  Building
} from 'lucide-react';
import { translations } from '../i18n/translations';
import { useToast } from '../context/ToastContext';
import { apiClient } from '../services/apiClient';
import EmptyState from '../components/EmptyState';

/**
 * Dedicated Quorum Approval Page (/approvals) per Master Spec Section 12 & 20.2
 * - Dedicated page, not a modal inside the document viewer
 * - Reachable from Judicial "Approval Queue" and Forensic "My Pending Reviews"
 * - Card per pending request; expanding shows:
 *    - Light-background card with heading "Approval Status"
 *    - Plain numbered list: "Approver 1", "Approver 2", "Approver 3" with empty circle or green checkmark
 *    - "X of Y approvals received" with clean horizontal progress bar
 *    - Jurisdictional pool label: "Routed to: State Police Review Pool" or "Routed to: District Police Review Pool"
 *    - Self-approval blocked: requester's row is disabled with tooltip explaining conflict of interest (enforced 403 server-side)
 *    - No dark sci-fi graphics; clean, calm government UI
 */
export default function ApprovalsView({
  documents = [],
  activeUser,
  onVoteSuccess,
  onBack,
  onBackToDashboard,
  initialTab = 'approvals', // 'approvals' | 'my_requests'
  lang = 'en'
}) {
  const handleBack = onBack || onBackToDashboard;
  const t = translations[lang] || translations.en;
  const toast = useToast();

  const userRole = activeUser?.portalRole || 'POLICE';
  const defaultTab = userRole === 'POLICE' ? 'my_requests' : (initialTab || 'approvals');
  const [activeViewTab, setActiveViewTab] = useState(defaultTab);

  const pendingDocs = documents.filter(d => {
    // Check doc status directly
    const docPending = d.status === 'PENDING_QUORUM' || d.status === 'PENDING_AMENDMENT' || d.status === 'PENDING';
    // Also check if there's an active edit request with PENDING status
    const reqPending = d.activeEditRequest?.status === 'PENDING' || d.active_edit_request?.status === 'PENDING';
    const hasEditReqId = !!(d.editRequestId || d.activeEditRequest?.id || d.active_edit_request?.id);
    return docPending || (reqPending && hasEditReqId);
  });

  // Split into own requests vs peer review requests
  // Use the edit request's requester_id for accurate self-check
  const myRequests = pendingDocs.filter(d => {
    const activeReq = d.activeEditRequest || d.active_edit_request || {};
    const rId = activeReq.requester_id || d.requester_id || d.requesterId || d.uploaded_by || d.authorId || d.created_by;
    return rId === activeUser?.id || rId === activeUser?.employee_id || (userRole === 'POLICE');
  });
  const actionablePeerReviews = pendingDocs.filter(d => {
    const activeReq = d.activeEditRequest || d.active_edit_request || {};
    const rId = activeReq.requester_id || d.requester_id || d.requesterId || d.uploaded_by || d.authorId || d.created_by;
    return rId !== activeUser?.id && rId !== activeUser?.employee_id;
  });

  const displayDocs = activeViewTab === 'my_requests' ? myRequests : (userRole === 'JUDICIAL' ? pendingDocs : actionablePeerReviews);


  const [expandedDocId, setExpandedDocId] = useState(displayDocs[0]?.id || null);
  const [votingId, setVotingId] = useState(null);
  const [voteComment, setVoteComment] = useState('');

  const handleCastVote = async (doc, voteType) => {
    // Self-vote check: use the edit request's requester_id, NOT the doc uploader
    const activeReq = doc.activeEditRequest || doc.active_edit_request || {};
    const requesterId = activeReq.requester_id || doc.requester_id || doc.requesterId;
    if (activeUser && requesterId && (
      String(activeUser.id) === String(requesterId) ||
      String(activeUser.employee_id) === String(requesterId)
    )) {
      toast.error("Rule 4B Enforcement: You cannot approve your own edit request.");
      return;
    }

    const requestId = doc.editRequestId || activeReq.id || doc.activeEditRequest?.id || doc.id;
    setVotingId(doc.id);


    try {
      const res = await apiClient.post(`/documents/${doc.id}/edit-requests/${requestId}/vote`, {
        vote_choice: voteType
      });

      toast.success(voteType === 'APPROVE' ? 'Consensus approval recorded on ledger!' : 'Rejection registered.');
      if (onVoteSuccess) {
        const qData = res.quorum_data || res;
        const qReq = qData?.request || qData;
        const votes = qReq?.votes || [];
        const voteCounts = qReq?.vote_counts || {};
        const poolMembers = qReq?.approval_pool || [];
        const totalEligible = qReq?.pool_size_n || 3;

        const updatedSlots = Array.from({ length: totalEligible }, (_, idx) => {
          const m = poolMembers[idx];
          const v = votes[idx];
          return {
            slotIndex: idx + 1,
            title: m?.pseudonym || v?.pseudonym || `Approver ${idx + 1}`,
            hasVoted: !!v,
            vote: v?.vote_choice || null
          };
        });

        onVoteSuccess({
          ...doc,
          status: res.status || qReq?.status || 'APPROVED',
          editRequestId: requestId,
          activeEditRequest: qReq,
          quorumSession: {
            threshold: qReq?.threshold_m || 2,
            totalEligible,
            approvalCount: voteCounts.approve !== undefined ? voteCounts.approve : votes.filter(v => v.vote_choice === 'APPROVE').length,
            approverSlots: updatedSlots
          }
        }, qData);
      }
    } catch (err) {
      console.error("Vote error in ApprovalsView:", err);
      let msg = err.message || 'Failed to record vote';
      if (err.status === 409) {
        msg = "Duplicate Vote: You have already voted on this amendment request.";
      }
      toast.error(msg);
    } finally {
      setVotingId(null);
      setVoteComment('');
    }
  };

  return (
    <div className="flex-1 bg-[#FFF9F2] dark:bg-slate-950 p-4 sm:p-8 flex flex-col items-center select-none min-h-[calc(100vh-140px)] transition-colors w-full">
      <div className="max-w-4xl w-full space-y-6">
        
        {/* Navigation Breadcrumb */}
        {handleBack && (
          <button
            onClick={handleBack}
            className="text-xs font-bold text-slate-600 dark:text-slate-400 hover:text-[#FF6A1A] flex items-center gap-1.5 cursor-pointer"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Return to Dashboard</span>
          </button>
        )}

        {/* Page Header */}
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-6 sm:p-8 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase bg-orange-100 dark:bg-orange-950 text-[#FF6A1A] border border-orange-200 dark:border-orange-800">
              M-of-N Multi-Officer Governance
            </span>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-slate-100 tracking-tight mt-1 font-serif">
              {activeViewTab === 'my_requests' 
                ? (lang === 'hi' ? 'मेरे अनुरोध (कोरम स्थिति)' : 'My Requests (Quorum Status)')
                : (lang === 'hi' ? 'कोरम अनुमोदन बोर्ड' : 'Quorum Approval Queue')}
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-sans">
              {activeViewTab === 'my_requests'
                ? "Requester-side read-only tracking of your submitted amendment dockets. Peer officer consensus is required."
                : "Actionable consensus board. Review peer amendment dockets and cast supervisory approval votes."}
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="px-3.5 py-1.5 bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300 font-bold text-xs rounded-xl border border-amber-300 dark:border-amber-800 flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5" />
              <span>{displayDocs.length} Active Sessions</span>
            </span>
          </div>
        </div>

        {/* Cadre-Scoped Tab Switcher (Master Spec Section 12) */}
        {['FORENSIC', 'APPROVAL_OFFICER'].includes(userRole) && (
          <div className="flex items-center gap-2 p-1.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl w-fit">
            <button
              onClick={() => setActiveViewTab('approvals')}
              className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer ${
                activeViewTab === 'approvals'
                  ? 'bg-[#FF6A1A] text-white shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              <FileCheck2 className="w-3.5 h-3.5" />
              <span>Quorum Approval ({actionablePeerReviews.length})</span>
            </button>
            <button
              onClick={() => setActiveViewTab('my_requests')}
              className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer ${
                activeViewTab === 'my_requests'
                  ? 'bg-[#FF6A1A] text-white shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              <Clock className="w-3.5 h-3.5" />
              <span>My Requests ({myRequests.length})</span>
            </button>
          </div>
        )}

        {/* List of Approval / Request Cards */}
        {displayDocs.length === 0 ? (
          <EmptyState
            icon={FileCheck2}
            title={activeViewTab === 'my_requests' ? "No Pending Edit Requests" : "No Pending Approvals"}
            description={
              activeViewTab === 'my_requests'
                ? "You currently have no amendment dockets awaiting peer review."
                : "All case dockets and supplementary amendments have achieved full consensus or are locked."
            }
          />
        ) : (
          <div className="space-y-4">
            {displayDocs.map((doc) => {
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

              const session = doc.quorumSession || {
                threshold,
                totalEligible,
                approvalCount,
                poolLabel: doc.jurisdictionalPool || "District Police Review Pool",
                approverSlots
              };

              const isExpanded = expandedDocId === doc.id;
              const isRequester = activeUser && (activeUser.id === doc.requesterId || activeUser.id === doc.authorId);
              const approvalCount = session.approvalCount || 0;
              const threshold = session.threshold || 2;
              const totalEligible = session.totalEligible || 3;
              const progressPct = Math.min(100, Math.round((approvalCount / threshold) * 100));

              return (
                <div
                  key={doc.id}
                  className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-6 shadow-xs hover:border-slate-300 dark:hover:border-slate-700 transition-all space-y-5"
                >
                  {/* Card Top Row */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100 dark:border-slate-800">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-slate-900 dark:text-slate-100 bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded border border-slate-200 dark:border-slate-700">
                          {doc.firNo}
                        </span>
                        <span className="text-xs font-bold text-[#FF6A1A]">
                          Draft v{doc.draftVersion || '1.1'}
                        </span>
                        <span className="px-2 py-0.5 rounded-md text-[10px] font-bold bg-amber-50 dark:bg-amber-950 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800">
                          Pending Quorum
                        </span>
                      </div>
                      <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 font-serif">
                        {doc.caseTitle}
                      </h3>
                    </div>

                    {/* Jurisdictional Pool Level Badge (Master Spec Section 20.2) */}
                    <div className="flex items-center gap-2">
                      <span className="px-3 py-1 bg-sky-50 dark:bg-sky-950 text-sky-700 dark:text-sky-300 border border-sky-200 dark:border-sky-800 rounded-xl text-xs font-semibold flex items-center gap-1.5">
                        <Building className="w-3.5 h-3.5 text-[#4FA8E0]" />
                        <span>Routed to: {session.poolLabel || doc.jurisdictionalPool || "District Police Review Pool"}</span>
                      </span>
                      <button
                        onClick={() => setExpandedDocId(isExpanded ? null : doc.id)}
                        className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
                        title={isExpanded ? "Collapse" : "Expand Details"}
                      >
                        {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  {/* Summary of Proposed Amendment */}
                  <div className="p-3.5 bg-slate-50 dark:bg-slate-800/60 rounded-2xl border border-slate-200 dark:border-slate-800 text-xs text-slate-700 dark:text-slate-300 space-y-1">
                    <div className="font-bold text-slate-900 dark:text-slate-100 flex items-center justify-between">
                      <span>Proposed Amendment Summary:</span>
                      <span className="text-[11px] font-normal text-slate-500 dark:text-slate-400">
                        Investigating Officer: <strong>{doc.investigatingOfficer}</strong>
                      </span>
                    </div>
                    <p className="leading-relaxed">
                      {doc.draftData?.editSummary || doc.versions?.find(v => v.version === doc.draftVersion)?.summaryDiff || "Supplementary forensic evidence appended to docket."}
                    </p>
                  </div>

                  {/* Approval Status Header & Anonymous Approver List per Master Spec Section 12 */}
                  <div className="space-y-3">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-bold text-slate-800 dark:text-slate-200">
                        Approval Status:
                      </span>
                      <span className="font-semibold text-slate-600 dark:text-slate-400 font-mono">
                        {approvalCount} of {threshold} approvals received ({totalEligible} eligible peer slots)
                      </span>
                    </div>

                    {/* Horizontal Progress Bar */}
                    <div className="w-full h-2.5 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden border border-slate-200 dark:border-slate-700">
                      <div 
                        className="h-full bg-[#5FA777] transition-all duration-500 rounded-full"
                        style={{ width: `${progressPct}%` }}
                      />
                    </div>

                    {/* Plain Numbered List of Approvers */}
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 pt-1">
                      {(session.approverSlots || []).map((slot, index) => {
                        const isApproved = slot.hasVoted && slot.vote === 'APPROVE';
                        const isRejected = slot.hasVoted && slot.vote === 'REJECT';

                        return (
                          <div 
                            key={slot.slotIndex || index}
                            className={`p-3 rounded-2xl border flex items-center justify-between text-xs transition-colors ${
                              isApproved 
                                ? 'bg-emerald-50/60 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300'
                                : isRejected
                                ? 'bg-rose-50/60 dark:bg-rose-950/40 border-rose-200 dark:border-rose-800 text-rose-800 dark:text-rose-300'
                                : 'bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300'
                            }`}
                          >
                            <div className="flex items-center gap-2">
                              {isApproved ? (
                                <CheckCircle2 className="w-4 h-4 text-[#5FA777] flex-shrink-0" />
                              ) : isRejected ? (
                                <AlertTriangle className="w-4 h-4 text-rose-500 flex-shrink-0" />
                              ) : (
                                <Circle className="w-4 h-4 text-slate-300 dark:text-slate-600 flex-shrink-0" />
                              )}
                              <span className="font-bold">
                                {slot.title || `Approver ${slot.slotIndex || index + 1}`}
                              </span>
                            </div>
                            <span className="text-[10px] font-mono font-semibold">
                              {isApproved ? "Approved" : isRejected ? "Rejected" : "Pending"}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Actions Area: Read-Only for My Requests vs Actionable for Quorum Approval */}
                  {activeViewTab === 'my_requests' ? (
                    <div className="p-3 bg-amber-50 dark:bg-amber-950/50 border border-amber-200 dark:border-amber-900/60 rounded-2xl text-xs text-amber-800 dark:text-amber-300 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Lock className="w-4 h-4 text-amber-600 flex-shrink-0" />
                        <span><strong>Requester View:</strong> Requesters cannot approve their own submissions (Rule 4B anti-conflict lock).</span>
                      </div>
                      <span className="font-mono text-[11px] font-semibold">
                        Awaiting peer consensus
                      </span>
                    </div>
                  ) : isRequester ? (
                    <div className="p-3 bg-amber-50 dark:bg-amber-950/50 border border-amber-300 dark:border-amber-800 rounded-2xl text-xs text-amber-800 dark:text-amber-200 flex items-center gap-2">
                      <Lock className="w-4 h-4 text-amber-600 flex-shrink-0" />
                      <span>
                        <strong>Self-Approval Blocked (Rule 4B):</strong> As the requesting officer for this amendment, your vote is disabled to eliminate bias and conflicts of interest.
                      </span>
                    </div>
                  ) : (
                    /* Voting Actions */
                    <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3">
                      <div className="text-xs text-slate-500 dark:text-slate-400">
                        Authenticated as: <strong>{activeUser?.name || "Official Reviewer"}</strong>
                      </div>

                      <div className="flex items-center gap-2.5 w-full sm:w-auto">
                        <button
                          type="button"
                          disabled={votingId === doc.id}
                          onClick={() => handleCastVote(doc, 'REJECT')}
                          className="flex-1 sm:flex-none px-4 py-2 border border-slate-300 dark:border-slate-700 hover:border-rose-400 hover:bg-rose-50 dark:hover:bg-rose-950/40 text-rose-600 text-xs font-bold rounded-xl transition-all cursor-pointer disabled:opacity-50"
                        >
                          Reject Request
                        </button>
                        <button
                          type="button"
                          disabled={votingId === doc.id}
                          onClick={() => handleCastVote(doc, 'APPROVE')}
                          className="flex-1 sm:flex-none px-5 py-2 bg-[#5FA777] hover:bg-[#4E9264] text-white text-xs font-bold rounded-xl shadow-xs transition-all cursor-pointer disabled:opacity-50 flex items-center justify-center gap-1.5"
                        >
                          <CheckCircle2 className="w-4 h-4" />
                          <span>{votingId === doc.id ? 'Recording...' : 'Grant Quorum Approval'}</span>
                        </button>
                      </div>
                    </div>
                  )}

                </div>
              );
            })}
          </div>
        )}

      </div>
    </div>
  );
}
