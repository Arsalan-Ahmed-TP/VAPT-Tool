// ---------------------------------------------------------------------------
// Remediation approval and application service
// ---------------------------------------------------------------------------

import { eq, and, inArray } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { remediationQueue } from '../queue/index.js';
import { recordAuditEvent } from '../middleware/audit.js';
import { AuditAction, ApprovalScope } from '@securescope/shared-types';
import type { ApproveRemediationRequest, ApplyRemediationRequest } from '@securescope/shared-types';
import { logger } from '../logger.js';

export async function getProposals(scanId: string) {
  return db.select()
    .from(schema.remediationProposals)
    .where(eq(schema.remediationProposals.scan_id, scanId));
}

export async function getProposal(id: string) {
  const [proposal] = await db.select()
    .from(schema.remediationProposals)
    .where(eq(schema.remediationProposals.id, id));
  return proposal || null;
}

export async function approveRemediation(data: ApproveRemediationRequest, actor: string) {
  // Determine which proposals to approve based on scope
  let proposalIds: string[] = [];

  switch (data.scope) {
    case ApprovalScope.AllSafe: {
      const proposals = await db.select()
        .from(schema.remediationProposals)
        .where(and(
          eq(schema.remediationProposals.scan_id, data.scan_id),
          eq(schema.remediationProposals.safe_to_auto_apply, true),
        ));
      proposalIds = proposals.map((p) => p.id);
      break;
    }
    case ApprovalScope.ByFinding: {
      proposalIds = data.proposal_ids || [];
      break;
    }
    case ApprovalScope.BySeverity: {
      if (!data.approved_severities?.length) break;
      const findings = await db.select()
        .from(schema.normalizedFindings)
        .where(and(
          eq(schema.normalizedFindings.scan_id, data.scan_id),
          inArray(schema.normalizedFindings.severity, data.approved_severities),
          eq(schema.normalizedFindings.autofixable, true),
        ));
      const findingIds = findings.map((f) => f.finding_id);
      if (findingIds.length) {
        const proposals = await db.select()
          .from(schema.remediationProposals)
          .where(inArray(schema.remediationProposals.finding_id, findingIds));
        proposalIds = proposals.map((p) => p.id);
      }
      break;
    }
    case ApprovalScope.ByCategory: {
      if (!data.approved_categories?.length) break;
      const findings = await db.select()
        .from(schema.normalizedFindings)
        .where(and(
          eq(schema.normalizedFindings.scan_id, data.scan_id),
          inArray(schema.normalizedFindings.category, data.approved_categories),
          eq(schema.normalizedFindings.autofixable, true),
        ));
      const findingIds = findings.map((f) => f.finding_id);
      if (findingIds.length) {
        const proposals = await db.select()
          .from(schema.remediationProposals)
          .where(inArray(schema.remediationProposals.finding_id, findingIds));
        proposalIds = proposals.map((p) => p.id);
      }
      break;
    }
    case ApprovalScope.RecommendOnly:
    case ApprovalScope.ExportPatchOnly:
    case ApprovalScope.CreateBranchOnly:
      // These don't change proposal status in DB
      break;
  }

  // Create the approval record
  const [approval] = await db.insert(schema.remediationApprovals).values({
    scan_id: data.scan_id,
    scope: data.scope,
    proposal_ids: proposalIds,
    approved_severities: data.approved_severities,
    approved_categories: data.approved_categories,
    approved_by: actor,
    notes: data.notes,
  }).returning();

  // Update proposal statuses
  if (proposalIds.length > 0) {
    await db.update(schema.remediationProposals)
      .set({ status: 'approved', updated_at: new Date() })
      .where(inArray(schema.remediationProposals.id, proposalIds));
  }

  await recordAuditEvent({
    action: AuditAction.RemediationApproved,
    actor,
    target_type: 'scan',
    target_id: data.scan_id,
    details: {
      scope: data.scope,
      proposal_count: proposalIds.length,
      approval_id: approval.id,
    },
  });

  logger.info('Remediation approved', {
    approval_id: approval.id,
    scope: data.scope,
    proposal_count: proposalIds.length,
  });

  return { approval, proposal_ids: proposalIds };
}

export async function applyRemediation(data: ApplyRemediationRequest, actor: string) {
  const [approval] = await db.select()
    .from(schema.remediationApprovals)
    .where(eq(schema.remediationApprovals.id, data.approval_id));

  if (!approval) throw new Error('Approval not found');

  // Enqueue remediation application
  await remediationQueue.add('apply-fixes', {
    approval_id: data.approval_id,
    scan_id: approval.scan_id,
    create_branch: data.create_branch ?? true,
    branch_name: data.branch_name,
    dry_run: data.dry_run ?? false,
    actor,
  }, {
    jobId: `remediate-${data.approval_id}`,
  });

  await recordAuditEvent({
    action: AuditAction.RemediationApplied,
    actor,
    target_type: 'approval',
    target_id: data.approval_id,
    details: {
      dry_run: data.dry_run,
      create_branch: data.create_branch,
    },
  });

  return { queued: true, approval_id: data.approval_id };
}

export async function exportPatch(scanId: string) {
  const proposals = await db.select()
    .from(schema.remediationProposals)
    .where(and(
      eq(schema.remediationProposals.scan_id, scanId),
      eq(schema.remediationProposals.status, 'approved'),
    ));

  const diffs = proposals.map((p) => p.diff);
  const files = [...new Set(proposals.map((p) => p.file_path))];

  return {
    unified_diff: diffs.join('\n'),
    file_count: files.length,
    files,
  };
}
