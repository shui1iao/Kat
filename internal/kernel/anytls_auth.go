package kernel

// anyTLSAuthority identifies one uninterrupted authorization period on one
// listening socket. It is separate from the shared, budget-dependent codec:
// names, routing, metadata, providers and budgets do not change authorization.
// A removed/replaced listener or changed password gets a fresh token, even if
// the same listener/password is subsequently restored. No revoked-token table,
// password or generation reference is retained here.
type anyTLSAuthority struct{ slot string }

type anyTLSPreviousAuthority struct {
	identity  [32]byte
	authority *anyTLSAuthority
}

// refAnyTLS is the new logical flow admission point, after authentication and
// complete TCP/UoT target parsing. A SYNACK alone is not flow admission. Holding
// bindMu across both the token check and reference acquisition linearizes this
// with commit's listener rebinding + gen.Store. A flow admitted before commit
// keeps its generation; one admitted after commit cannot see an old binding.
//
// Lock order: commit holds reloadMu -> bindMu(write); this path takes only
// bindMu(read), never reloadMu, core.mu or a codec lock. No handshake, target
// read, routing, dial or stream I/O runs under the lock.
func (k *core) refAnyTLS(a *anyTLSAuthority) *Server {
	if a == nil {
		return nil
	}
	k.bindMu.RLock()
	defer k.bindMu.RUnlock()
	e := k.tcpEntries[a.slot]
	if e == nil || e.closed.Load() {
		return nil
	}
	b := e.bind.Load()
	if b.g.cfg.Inbounds[b.idx].anytlsAuth != a {
		return nil
	}
	b.g.refs.Add(1) // current binding owns the current-generation reference
	return b.g
}
