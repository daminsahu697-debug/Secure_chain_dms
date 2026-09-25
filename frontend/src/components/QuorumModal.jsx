import React, { useState, useEffect } from 'react';
import { 
  X, 
  Check, 
  Circle, 
  CheckCircle2, 
  AlertCircle, 
  UserX, 
  ShieldAlert, 
  Sparkles,
  ArrowRight,
  Lock,
  Loader2,
  FileText,
  Download
} from 'lucide-react';
import confetti from 'canvas-confetti';
import { translations } from '../i18n/translations';
import { apiClient } from '../services/apiClient';

/**
 * M-of-N Quorum Approval Modal per Master Spec Section 9 & Step 6D.2 Phase 2:
 * - Connected to real FastAPI /api/v1/documents/{id}/edit-requests/{request_id} & /vote endpoints
 * - Light-background card (NO dark backgrounds, NO sci-fi styling)
 * - Numbered list of approvers derived from authoritative backend quorum data
 * - Rule 4B enforcement: If current user is requester, grey out & disable with message:
 *   "Rule 4B: Requester cannot approve own request" (server-side HTTP 403 enforced)
 */
export default function QuorumModal({ 
  isOpen, 
  onClose, 
  document: doc, 
  activeUser, 
  onVoteSuccess, 
  onFinalizeSuccess,
  onSwitchUser,
  lang = 'en'
}) {
  const t = translations[lang] || translations.en;
  const [submitting, setSubmitting] = useState(false);
  const [finalizing, setFinalizing] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [downloadingOriginal, setDownloadingOriginal] = useState(false);
  const [downloadingProposal, setDownloadingProposal] = useState(false);

  // Real Backend Request & Quorum State
  const [requestDetails, setRequestDetails] = useState(null);
  const [quorumData, setQuorumData] = useState(null);
  const [status, setStatus] = useState('PENDING');

  const requestId = requestDetails?.id || doc?.editRequestId || doc?.activeEditRequest?.id || doc?.id;
  const docId = doc?.id;

  const handleDownloadOriginal = async () => {
    if (!docId || downloadingOriginal) return;
    try {
      setDownloadingOriginal(true);
      const { blob, filename: headerFilename } = await apiClient.getBlob(`/documents/${docId}/download`);
      const blobUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = blobUrl;
      link.download = headerFilename || `Original_Document_${String(docId).substring(0, 8)}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(blobUrl);
    } catch (err) {
      console.error("Download original error:", err);
    } finally {
      setDownloadingOriginal(false);
    }
  };

  const handleDownloadProposal = async () => {
    if (!docId || !requestId || downloadingProposal) return;
    try {
      setDownloadingProposal(true);
      const { blob, filename: headerFilename } = await apiClient.getBlob(`/documents/${docId}/edit-requests/${requestId}/download`);
      const blobUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = blobUrl;
      link.download = headerFilename || `Proposed_Amendment_${String(requestId).substring(0, 8)}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(blobUrl);
    } catch (err) {
      console.error("Download proposal error:", err);
    } finally {
      setDownloadingProposal(false);
    }
  };

  // Fetch authoritative edit request details on mount/open
  useEffect(() => {
    let isMounted = true;
    if (!isOpen || !docId) return;

    const reqIdToFetch = doc?.editRequestId || doc?.activeEditRequest?.id || doc?.id;
    if (!reqIdToFetch) return;

    setLoading(true);
    setErrorMsg('');

    apiClient.get(`/documents/${docId}/edit-requests/${reqIdToFetch}`)
      .then(data => {
        if (isMounted && data) {
          setRequestDetails(data);
          setStatus(data.status || 'PENDING');
          if (data.quorum_data) {
            setQuorumData(data.quorum_data);
          }
          setLoading(false);
        }
      })
      .catch(err => {
        if (isMounted) {
          console.warn("Could not fetch edit request details:", err.message);
          setLoading(false);
        }
      });

    return () => { isMounted = false; };
  }, [isOpen, docId, doc?.editRequestId]);

  if (!isOpen || !doc) return null;

  // Derive Quorum Progress from Backend Quorum Data
  const qReq = quorumData?.data?.request || quorumData?.request || quorumData || {};
  const threshold = qReq.threshold_m ?? qReq.threshold ?? 2;
  const poolSize = qReq.pool_size_n ?? qReq.poolSize ?? 3;
  
  // Calculate exact approval count from actual votes or status
  const exactApprovals = qReq.vote_counts?.approve ?? qReq.approvalCount ?? (status === 'APPROVED' ? threshold : 0);
  const approvalCount = exactApprovals;
  
  const percentage = Math.round((approvalCount / threshold) * 100);
  const thresholdMet = status === 'APPROVED' || approvalCount >= threshold;

  // Check Self-Approval Conflict (Rule 4B)
  const requesterId = requestDetails?.requester_id || doc?.requester_id || doc?.requesterId || doc?.uploaded_by;
  const isRequester = activeUser && requesterId && (
    String(activeUser.id) === String(requesterId) ||
    String(activeUser.employee_id) === String(requesterId)
  );

  // Map the approver list dynamically from the nodejs backend schema
  let approverList = [];
  if (qReq.approval_pool && qReq.votes) {
    approverList = qReq.approval_pool.map((poolMember, index) => {
      const userVote = qReq.votes.find(v => v.pseudonym === poolMember.pseudonym);
      return {
        label: poolMember.pseudonym || `Approver ${index + 1}`,
        hasVoted: !!userVote,
        vote: userVote?.vote_choice || null
      };
    });
  } else if (qReq.approversPool) {
    approverList = qReq.approversPool;
  } else {
    // Fallback when backend quorum data hasn't loaded yet
    for (let i = 0; i < poolSize; i++) {
      approverList.push({
        label: `Approver ${i + 1}`,
        hasVoted: i < approvalCount,
        vote: i < approvalCount ? 'APPROVE' : null
      });
    }
  }

  const handleVote = async (voteType = 'APPROVE') => {
    if (isRequester) {
      setErrorMsg("Rule 4B Enforcement: Requester cannot approve own request (Server-Enforced 403)");
      return;
    }

    setSubmitting(true);
    setErrorMsg('');

    try {
      const activeReqId = requestDetails?.id || doc?.editRequestId || doc?.activeEditRequest?.id || doc?.id;
      const res = await apiClient.post(`/documents/${docId}/edit-requests/${activeReqId}/vote`, {
        vote_choice: voteType
      });

      if (res && res.status) {
        setStatus(res.status);
        if (res.quorum_data) {
          setQuorumData(res.quorum_data);
        }

        if (res.status === 'APPROVED') {
          confetti({
            particleCount: 80,
            spread: 70,
            origin: { y: 0.6 }
          });
        }

        if (onVoteSuccess) {
          onVoteSuccess({
            ...doc,
            status: res.status,
            editRequestId: activeReqId,
            activeEditRequest: res
          }, res.quorum_data);
        }
      }
    } catch (err) {
      console.error("Vote error:", err);
      let msg = err.message || "Failed to cast vote";
      if (err.status === 403) {
        msg = "Rule 4B Conflict: Requester cannot approve their own amendment request (Server 403).";
      } else if (err.status === 409) {
        msg = "Duplicate Vote: You have already voted on this amendment request.";
      }
      setErrorMsg(msg);
    } finally {
      setSubmitting(false);
    }
  };

  const handleFinalize = async () => {
    if (finalizing) return;
    const activeReqId = requestDetails?.id || doc?.editRequestId || doc?.activeEditRequest?.id || doc?.id;
    const docId = doc?.id;

    if (!docId || !activeReqId) return;

    setFinalizing(true);
    setErrorMsg('');

    try {
      const newVersion = await apiClient.post(`/documents/${docId}/edit-requests/${activeReqId}/finalize`);

      setStatus('FINALIZED');
      if (onFinalizeSuccess) {
        onFinalizeSuccess(docId, newVersion);
      }
      onClose();
    } catch (err) {
      console.error("Finalize error:", err);
      let msg = err.message || "Failed to finalize amendment";
      if (err.status === 409) {
        msg = "Conflict / Idempotency: Amendment already finalized or conflict detected.";
      } else if (err.status === 403) {
        msg = "Permission Denied: Unauthorized to finalize amendment.";
      } else if (err.status === 400) {
        msg = "Bad Request: Quorum approval token is not valid or approved.";
      }
      setErrorMsg(msg);
    } finally {
      setFinalizing(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm animate-in fade-in duration-200">
      
      {/* Light Background Card */}
      <div className="bg-white border border-slate-200 rounded-3xl shadow-2xl max-w-lg w-full p-6 sm:p-8 space-y-6 animate-in zoom-in-95 duration-200 text-slate-800">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-slate-100 pb-4">
          <div>
            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase bg-orange-100 text-[#FF6A1A] border border-orange-200">
              M-of-N Consensus
            </span>
            <h3 className="text-lg font-bold text-slate-900 mt-1">
              {t.quorumHeading}
            </h3>
            <p className="text-xs text-slate-500">
              Docket Ref: <strong className="text-slate-700">{doc.firNo || doc.case_id || doc.id}</strong> • Request ID: <span className="font-mono text-[10px]">{String(requestId).substring(0, 8)}</span>
            </p>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-xl hover:bg-slate-100 text-slate-400 hover:text-slate-700 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Loading State */}
        {loading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="w-6 h-6 text-[#FF6A1A] animate-spin" />
            <span className="ml-2 text-xs text-slate-600">Fetching authoritative quorum status...</span>
          </div>
        ) : (
          <>
            {/* Section: Proposed Amendment Document & Rationale Inspection Panel */}
            <div className="p-4 rounded-2xl bg-[#FFF9F2] border border-orange-200 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileText className="w-4 h-4 text-[#FF6A1A]" />
                  <span className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                    Amendment Proposal & Document Details
                  </span>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-orange-100 text-[#FF6A1A] border border-orange-200">
                  Target: Draft v1.1
                </span>
              </div>

              {/* Stated Rationale / Reason */}
              <div className="bg-white p-3 rounded-xl border border-slate-200 space-y-1">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                  Stated Rationale for Amendment
                </span>
                <p className="text-xs text-slate-800 font-medium leading-relaxed">
                  {requestDetails?.reason || doc?.reason || doc?.amendmentReason || "Supplementary evidence addition & factual update requested under CrPC 173(8)."}
                </p>
              </div>

              {/* Dual File Review Buttons (Original vs Proposed) */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1">
                <button
                  type="button"
                  onClick={handleDownloadOriginal}
                  disabled={downloadingOriginal}
                  className="px-3 py-2 bg-white hover:bg-slate-50 border border-slate-300 rounded-xl text-xs font-bold text-slate-700 flex items-center justify-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50 shadow-2xs"
                  title="Download and inspect the current locked Version 1.0 PDF"
                >
                  {downloadingOriginal ? <Loader2 className="w-3.5 h-3.5 animate-spin text-slate-500" /> : <Download className="w-3.5 h-3.5 text-sky-600" />}
                  <span>View Original File (v1.0)</span>
                </button>

                <button
                  type="button"
                  onClick={handleDownloadProposal}
                  disabled={downloadingProposal}
                  className="px-3 py-2 bg-[#FF6A1A] hover:bg-[#e05910] text-white rounded-xl text-xs font-bold flex items-center justify-center gap-1.5 shadow-xs transition-colors cursor-pointer disabled:opacity-50"
                  title="Download and inspect the proposed amendment PDF file"
                >
                  {downloadingProposal ? <Loader2 className="w-3.5 h-3.5 animate-spin text-white" /> : <Download className="w-3.5 h-3.5 text-white" />}
                  <span>View Proposed File (v1.1)</span>
                </button>
              </div>

              {requestDetails?.amendment_reason_code && (
                <div className="text-[10px] font-mono text-slate-500 truncate pt-0.5">
                  Proposal SHA-256 Digest: <strong className="text-slate-700">{requestDetails.amendment_reason_code}</strong>
                </div>
              )}
            </div>

            {/* Section: Plain Numbered Approver List */}
            <div className="space-y-3">
              <div className="text-xs font-bold text-slate-500 uppercase tracking-wider">
                Designated Supervisory Reviewers
              </div>

              <div className="divide-y divide-slate-100 border border-slate-200 rounded-2xl overflow-hidden">
                {approverList.map((app, index) => {
                  const label = app.label || `Approver ${index + 1}`;
                  const isApproved = app.hasVoted && (app.vote === 'APPROVE' || app.vote_choice === 'APPROVE');

                  return (
                    <div
                      key={index}
                      className="p-3.5 flex items-center justify-between bg-white hover:bg-slate-50 transition-colors"
                    >
                      <div className="flex items-center space-x-3">
                        {isApproved ? (
                          <div className="w-6 h-6 rounded-full bg-emerald-100 text-[#5FA777] flex items-center justify-center">
                            <Check className="w-3.5 h-3.5 stroke-[3]" />
                          </div>
                        ) : (
                          <div className="w-6 h-6 rounded-full border-2 border-slate-300 flex items-center justify-center text-slate-300">
                            <Circle className="w-2.5 h-2.5" />
                          </div>
                        )}

                        <div>
                          <div className="text-xs font-bold text-slate-800">
                            {label}
                          </div>
                          <div className="text-[10px] text-slate-400">
                            {app.title || "Independent Supervisory Officer"}
                          </div>
                        </div>
                      </div>

                      <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${
                        isApproved
                          ? 'bg-emerald-100 text-[#307044]'
                          : 'bg-slate-100 text-slate-500'
                      }`}>
                        {isApproved ? 'Approved' : 'Pending'}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Section: Plain Text Progress & Simple Horizontal Bar */}
            <div className="bg-slate-50 p-4 rounded-2xl border border-slate-200 space-y-2">
              <div className="flex items-center justify-between text-xs font-bold">
                <span className="text-slate-800">
                  {approvalCount} of {threshold} {t.quorumThresholdLabel}
                </span>
                <span className={thresholdMet ? 'text-[#307044]' : 'text-[#FF6A1A]'}>
                  {status === 'APPROVED' ? 'Threshold Satisfied' : status === 'REJECTED' ? 'Proposal Rejected' : `${percentage}% Completed`}
                </span>
              </div>

              <div className="w-full h-2.5 bg-slate-200 rounded-full overflow-hidden">
                <div
                  className={`h-full ${status === 'REJECTED' ? 'bg-red-500' : 'bg-[#5FA777]'} rounded-full transition-all duration-500`}
                  style={{ width: `${Math.min(100, Math.max(5, percentage))}%` }}
                ></div>
              </div>
            </div>

            {/* Rule 4B Enforcement Notice */}
            {isRequester && status === 'PENDING' && (
              <div className="p-3.5 rounded-2xl bg-amber-50 border border-amber-300 text-amber-900 text-xs flex items-start gap-2.5">
                <UserX className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
                <div>
                  <strong className="font-bold">Rule 4B Enforcement:</strong> Requester cannot approve own request. You are logged in as the Investigating Officer who initiated this amendment. Server-side API blocks self-approvals with 403 Forbidden.
                </div>
              </div>
            )}

            {errorMsg && (
              <div className="p-3 bg-red-50 border border-red-200 text-red-700 text-xs rounded-xl flex items-center gap-2">
                <AlertCircle className="w-4 h-4" />
                <span>{errorMsg}</span>
              </div>
            )}

            {/* Action Controls based on Authoritative Status */}
            {status === 'PENDING' ? (
              <div className="space-y-3 pt-2">
                {isRequester ? (
                  <div className="text-center p-3 bg-slate-50 border border-slate-200 rounded-2xl space-y-2">
                    <p className="text-xs text-slate-500">
                      Switch to an authorized supervisory reviewer account to cast a vote:
                    </p>
                    <div className="flex justify-center gap-2">
                      <button
                        onClick={() => onSwitchUser && onSwitchUser('JUD-JDG-001')}
                        className="px-3 py-1.5 bg-[#4FA8E0] hover:bg-[#3B97D1] text-white text-xs font-bold rounded-lg transition-colors cursor-pointer flex items-center gap-1"
                      >
                        <span>Switch to Approver 1 (Judge)</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                      <button
                        onClick={() => onSwitchUser && onSwitchUser('FOR-EXP-001')}
                        className="px-3 py-1.5 bg-[#2E7D32] hover:bg-[#1B5E20] text-white text-xs font-bold rounded-lg transition-colors cursor-pointer flex items-center gap-1"
                      >
                        <span>Switch to Approver 2 (Forensic Officer)</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => handleVote('APPROVE')}
                      disabled={submitting}
                      className="flex-1 py-2.5 bg-[#FF6A1A] hover:bg-[#E85B0E] text-white font-bold rounded-xl text-xs shadow-md transition-all flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50"
                    >
                      <Check className="w-4 h-4 stroke-[3]" />
                      <span>{submitting ? 'Submitting...' : t.castVoteApprove}</span>
                    </button>

                    <button
                      onClick={() => handleVote('REJECT')}
                      disabled={submitting}
                      className="px-4 py-2.5 bg-slate-100 hover:bg-red-50 text-slate-600 hover:text-red-600 border border-slate-300 rounded-xl text-xs font-bold transition-all cursor-pointer disabled:opacity-50"
                    >
                      <span>{t.castVoteReject}</span>
                    </button>
                  </div>
                )}
              </div>
            ) : status === 'APPROVED' ? (
              <div className="p-4 bg-emerald-50 border border-emerald-300 rounded-2xl text-center space-y-2">
                <div className="text-emerald-800 font-bold text-xs flex items-center justify-center gap-1.5">
                  <Sparkles className="w-4 h-4 text-[#5FA777]" />
                  <span>Quorum Consensus Achieved</span>
                </div>
                <p className="text-[11px] text-emerald-700">
                  Multi-officer quorum consensus has been ratified on the immutable ledger.
                </p>
                <div className="pt-1">
                  <button
                    onClick={handleFinalize}
                    disabled={finalizing}
                    className="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs rounded-xl shadow-md transition-all flex items-center justify-center gap-2 mx-auto cursor-pointer disabled:opacity-50"
                  >
                    {finalizing ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin text-white" />
                        <span>Finalizing Amendment...</span>
                      </>
                    ) : (
                      <>
                        <CheckCircle2 className="w-4 h-4 text-white" />
                        <span>Finalize Amendment & Seal Version</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            ) : (
              <div className="p-4 bg-red-50 border border-red-300 rounded-2xl text-center space-y-1">
                <div className="text-red-800 font-bold text-xs flex items-center justify-center gap-1.5">
                  <ShieldAlert className="w-4 h-4 text-red-600" />
                  <span>Amendment Proposal Rejected</span>
                </div>
                <p className="text-[11px] text-red-700">
                  Supervisory reviewers rejected this amendment request. The proposal cannot be finalized.
                </p>
              </div>
            )}
          </>
        )}

      </div>

    </div>
  );
}
