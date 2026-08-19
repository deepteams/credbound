package credbound

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"iter"
	"strconv"
)

// auditChainGenesis is the previous hash of the first chained audit event.
var auditChainGenesis = make([]byte, sha256.Size)

// ComputeAuditHash returns the SHA-256 hash that chains an audit event to its
// predecessor. Every field is length-prefixed so no two distinct events share
// a canonical encoding. Stores call it inside the commit transaction; hosts
// and auditors can recompute it to verify exported audit logs.
func ComputeAuditHash(previous []byte, event AuditEvent) []byte {
	if len(previous) == 0 {
		previous = auditChainGenesis
	}
	h := sha256.New()
	h.Write(previous)
	write := func(value string) {
		_, _ = io.WriteString(h, strconv.Itoa(len(value)))
		h.Write([]byte{':'})
		_, _ = io.WriteString(h, value)
		h.Write([]byte{';'})
	}
	write(strconv.FormatInt(event.Sequence, 10))
	// Identifiers are hashed in their canonical text form, not as raw bytes:
	// the chain is append-only and its persisted hashes were computed that
	// way, so changing the representation would make every existing chain
	// unverifiable. An absent identifier hashes as the empty string, exactly
	// as it did when identifiers were strings.
	write(hashedID(event.ID))
	write(strconv.FormatInt(event.OccurredAt.UTC().UnixMicro(), 10))
	write(string(event.ActorKind))
	write(hashedID(event.ActorID))
	write(event.Action)
	write(event.ResourceType)
	write(event.ResourceID)
	write(hashedID(event.WorkspaceID))
	write(string(event.Outcome))
	write(event.Reason)
	write(event.IPAddress)
	write(event.UserAgent)
	return h.Sum(nil)
}

// hashedID renders an identifier the way the audit chain has always hashed it:
// canonical text, and the empty string when absent.
func hashedID(id UUID) string {
	if id == (UUID{}) {
		return ""
	}
	return id.String()
}

// VerifyAuditChain recomputes the whole audit hash chain from the genesis
// and compares it with the persisted chain head. Any edited, deleted or
// reordered chained event yields ErrAuditCompromised. It requires admin
// audit read; VerifyAuditChainFrom verifies only the delta after a trusted
// checkpoint when the full scan grows too expensive.
func (m *Manager) VerifyAuditChain(ctx context.Context, actor Authentication) (_ AuditChainReport, err error) {
	return m.VerifyAuditChainFrom(ctx, actor, AuditChainCheckpoint{})
}

// VerifyAuditChainFrom recomputes the chain from a previously verified
// checkpoint — the HeadSequence and HeadHash of an earlier report — to the
// current head, so periodic verification costs the delta instead of a full
// scan. The zero checkpoint verifies from the genesis. The checkpoint must
// come from the caller's own trusted record (the previous run's report,
// ideally anchored outside the database as OPERATIONS.md recommends): a
// checkpoint read back from compromised storage would vouch for a
// rewritten prefix, since events at or below its sequence are not re-read.
func (m *Manager) VerifyAuditChainFrom(ctx context.Context, actor Authentication, checkpoint AuditChainCheckpoint) (_ AuditChainReport, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "audit.chain.verify", started, err) }()
	if err := m.AuthorizeAdmin(ctx, actor, PermissionAuditRead); err != nil {
		return AuditChainReport{}, err
	}
	if checkpoint.Sequence < 0 || (checkpoint.Sequence == 0) != (len(checkpoint.Hash) == 0) {
		return AuditChainReport{}, fmt.Errorf("%w: an audit checkpoint pairs a positive sequence with its hash", ErrInvalidInput)
	}
	previous := auditChainGenesis
	sequence := int64(0)
	if checkpoint.Sequence > 0 {
		previous = checkpoint.Hash
		sequence = checkpoint.Sequence
	}
	for event, iterErr := range m.store.ChainedAuditEvents(ctx, sequence) {
		if iterErr != nil {
			return AuditChainReport{}, iterErr
		}
		sequence++
		if event.Sequence != sequence {
			return AuditChainReport{}, fmt.Errorf("%w: expected sequence %d, found %d (%s)", ErrAuditCompromised, sequence, event.Sequence, event.ID)
		}
		if !bytes.Equal(event.PreviousHash, previous) || !bytes.Equal(event.Hash, ComputeAuditHash(previous, event)) {
			return AuditChainReport{}, fmt.Errorf("%w: audit event %s does not extend its predecessor", ErrAuditCompromised, event.ID)
		}
		previous = event.Hash
	}
	headSequence, headHash, err := m.store.AuditChainHead(ctx)
	if err != nil {
		return AuditChainReport{}, err
	}
	if headSequence != sequence || !bytes.Equal(headHash, previous) {
		return AuditChainReport{}, fmt.Errorf("%w: chain head does not match the last chained event", ErrAuditCompromised)
	}
	return AuditChainReport{Events: sequence, HeadSequence: headSequence, HeadHash: headHash}, nil
}

// AuditEvents streams the audit log of one workspace. The actor needs a
// fresh AAL2 step-up and workspace audit read in that workspace.
func (m *Manager) AuditEvents(ctx context.Context, actor Authentication, workspaceID UUID, page PageRequest) iter.Seq2[PageEvent[AuditEvent], error] {
	if err := m.requireStepUp(ctx, actor, "audit.workspace.list"); err != nil {
		return errorSeq[PageEvent[AuditEvent]](err)
	}
	if err := m.AuthorizePermission(ctx, actor, workspaceID, PermissionWorkspaceAuditRead); err != nil {
		return errorSeq[PageEvent[AuditEvent]](err)
	}
	page, err := normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[AuditEvent]](err)
	}
	return m.store.AuditEvents(ctx, workspaceID, page)
}

// InstanceAuditEvents streams the audit log of the whole instance. It
// requires admin audit read.
func (m *Manager) InstanceAuditEvents(ctx context.Context, actor Authentication, page PageRequest) iter.Seq2[PageEvent[AuditEvent], error] {
	if err := m.AuthorizeAdmin(ctx, actor, PermissionAuditRead); err != nil {
		return errorSeq[PageEvent[AuditEvent]](err)
	}
	page, err := normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[AuditEvent]](err)
	}
	return m.store.InstanceAuditEvents(ctx, page)
}
