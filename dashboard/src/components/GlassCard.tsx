import React from 'react';

interface GlassCardProps {
  children: React.ReactNode;
  title?: string;
  className?: string;
}

export default function GlassCard({ children, title, className = '' }: GlassCardProps) {
  return (
    <div className={`glass-panel p-6 ${className}`} style={{ padding: '24px' }}>
      {title && (
        <h2 style={{ 
          marginBottom: '16px', 
          fontSize: '1.25rem', 
          fontWeight: 600, 
          color: 'var(--primary-accent)',
          borderBottom: '1px solid var(--glass-border)',
          paddingBottom: '8px'
        }}>
          {title}
        </h2>
      )}
      <div>{children}</div>
    </div>
  );
}
