'use client';

import React from 'react';
import HitlGateway from '../components/HitlGateway';
import AttackGraph from '../components/AttackGraph';
import Leaderboard from '../components/Leaderboard';

export default function Dashboard() {
  return (
    <main style={{ padding: '24px', maxWidth: '1400px', margin: '0 auto' }}>
      <header style={{ marginBottom: '32px', textAlign: 'center' }}>
        <h1 style={{ 
          fontSize: '2.5rem', 
          fontWeight: 800, 
          color: 'var(--text-bright)',
          textShadow: '0 0 15px rgba(102, 252, 241, 0.5)'
        }}>
          Khandaq SOC Command Center
        </h1>
        <p style={{ color: 'var(--secondary-accent)', fontSize: '1.1rem' }}>
          Agentic AI Defensive Mesh | Zero Trust Ledger | Predictive Simulation
        </p>
      </header>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))',
        gap: '24px',
        marginBottom: '24px'
      }}>
        {/* Top Row: Attack Graph and HITL */}
        <div style={{ gridColumn: 'span 2' }}>
          <AttackGraph />
        </div>
        
        <div>
          <HitlGateway />
        </div>
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: '1fr',
        gap: '24px'
      }}>
        {/* Bottom Row: Leaderboard */}
        <Leaderboard />
      </div>
    </main>
  );
}
