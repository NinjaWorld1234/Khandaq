'use client';

import React from 'react';
import GlassCard from './GlassCard';

export default function AttackGraph() {
  return (
    <GlassCard title="🕸️ Live Attack Graph (Neo4j)" className="h-full">
      <div style={{
        height: '400px',
        width: '100%',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'radial-gradient(circle, rgba(69,162,158,0.1) 0%, rgba(11,12,16,0.5) 100%)',
        border: '1px dashed var(--secondary-accent)',
        borderRadius: '8px',
        position: 'relative',
        overflow: 'hidden'
      }}>
        {/* Animated radar/scanner effect */}
        <div style={{
          position: 'absolute',
          width: '150%',
          height: '150%',
          background: 'conic-gradient(from 0deg, transparent 70%, rgba(102, 252, 241, 0.3) 100%)',
          animation: 'spin 4s linear infinite',
          borderRadius: '50%'
        }} />
        <style>{`
          @keyframes spin {
            100% { transform: rotate(360deg); }
          }
        `}</style>

        <div style={{ zIndex: 1, textAlign: 'center', padding: '20px', background: 'rgba(0,0,0,0.6)', borderRadius: '8px' }}>
          <h3 style={{ color: 'var(--primary-accent)', marginBottom: '8px' }}>Neo4j Cytoscape Renderer</h3>
          <p style={{ color: 'var(--text-main)', fontSize: '0.9rem' }}>
            Awaiting WebSocket connection to graph stream...
          </p>
          <div style={{ marginTop: '16px', display: 'flex', gap: '8px', justifyContent: 'center' }}>
            <span style={{ display: 'inline-block', width: '12px', height: '12px', borderRadius: '50%', background: 'var(--danger)', boxShadow: '0 0 10px var(--danger)' }}></span>
            <span style={{ color: 'var(--danger)', fontSize: '0.8rem' }}>10.0.0.45 (Compromised)</span>
            
            <span style={{ display: 'inline-block', width: '24px', height: '2px', background: 'var(--secondary-accent)', alignSelf: 'center' }}></span>
            
            <span style={{ display: 'inline-block', width: '12px', height: '12px', borderRadius: '50%', background: 'var(--success)', boxShadow: '0 0 10px var(--success)' }}></span>
            <span style={{ color: 'var(--success)', fontSize: '0.8rem' }}>10.0.0.100 (Safe)</span>
          </div>
        </div>
      </div>
    </GlassCard>
  );
}
