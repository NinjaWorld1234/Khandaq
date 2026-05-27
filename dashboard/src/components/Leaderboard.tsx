'use client';

import React from 'react';
import GlassCard from './GlassCard';

export default function Leaderboard() {
  // Mock data for the demonstration, this would normally be fetched from Redis soc:agent_reputation
  const agents = [
    { name: "Commander Agent", weight: 1.55, status: "Active" },
    { name: "Deception Agent", weight: 1.40, status: "Active" },
    { name: "W12 - Malware Analysis", weight: 1.15, status: "Active" },
    { name: "W04 - Reconnaissance", weight: 0.95, status: "Active" },
    { name: "W31 - Noise Reduction", weight: 0.45, status: "Penalized" },
  ];

  return (
    <GlassCard title="🏆 Agent Reputation Leaderboard">
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {agents.map((agent, index) => (
          <div key={index} style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            background: 'rgba(255,255,255,0.05)',
            padding: '12px',
            borderRadius: '6px'
          }}>
            <div>
              <span style={{ fontSize: '1.1rem', fontWeight: 'bold', marginRight: '8px' }}>#{index + 1}</span>
              <span style={{ color: 'var(--text-bright)' }}>{agent.name}</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <span style={{ color: agent.weight > 1.0 ? 'var(--success)' : (agent.weight < 0.5 ? 'var(--danger)' : 'var(--secondary-accent)') }}>
                Weight: {agent.weight.toFixed(2)}
              </span>
              <span style={{ 
                fontSize: '0.8rem', 
                padding: '2px 6px', 
                borderRadius: '4px',
                background: agent.status === 'Active' ? 'rgba(75, 181, 67, 0.2)' : 'rgba(255, 75, 75, 0.2)',
                color: agent.status === 'Active' ? 'var(--success)' : 'var(--danger)'
              }}>
                {agent.status}
              </span>
            </div>
          </div>
        ))}
      </div>
    </GlassCard>
  );
}
