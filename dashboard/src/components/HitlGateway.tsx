'use client';

import React, { useEffect, useState } from 'react';
import GlassCard from './GlassCard';

interface PendingAction {
  action_id: string;
  action_type: string;
  target: string;
  reason: string;
  source: string;
  status: string;
}

export default function HitlGateway() {
  const [actions, setActions] = useState<PendingAction[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchActions = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/approvals/pending');
      const data = await res.json();
      setActions(data.actions || []);
    } catch (e) {
      console.error("Failed to fetch pending actions", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchActions();
    const interval = setInterval(fetchActions, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleDecision = async (actionId: string, decision: 'approve' | 'reject') => {
    try {
      await fetch(`http://localhost:8000/api/approvals/${actionId}/${decision}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ feedback_reason: `Human ${decision}d via Dashboard` })
      });
      fetchActions();
    } catch (e) {
      console.error(`Failed to ${decision} action`, e);
    }
  };

  return (
    <GlassCard title="🛡️ HITL Approval Gateway">
      {loading ? (
        <p>Loading pending actions...</p>
      ) : actions.length === 0 ? (
        <p style={{ color: 'var(--success)' }}>✅ No pending critical actions. System is stable.</p>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {actions.map((act) => (
            <div key={act.action_id} style={{
              background: 'rgba(0,0,0,0.3)',
              padding: '16px',
              borderRadius: '8px',
              borderLeft: '4px solid var(--danger)'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <h3 style={{ color: 'var(--text-bright)', marginBottom: '4px' }}>{act.action_type} on {act.target}</h3>
                  <p style={{ fontSize: '0.9rem', color: 'var(--text-main)' }}><strong>Reason:</strong> {act.reason}</p>
                  <p style={{ fontSize: '0.8rem', color: 'var(--secondary-accent)', marginTop: '4px' }}>Proposed by: {act.source}</p>
                </div>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button className="glow-btn success" onClick={() => handleDecision(act.action_id, 'approve')}>
                    Approve
                  </button>
                  <button className="glow-btn danger" onClick={() => handleDecision(act.action_id, 'reject')}>
                    Reject
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </GlassCard>
  );
}
