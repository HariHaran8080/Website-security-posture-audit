import React from 'react';
import { ShieldAlert, CheckCircle, X, Shield } from 'lucide-react';

export default function ConsentModal({ isOpen, onClose, onConfirm }) {
  if (!isOpen) return null;

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      backgroundColor: 'rgba(3, 6, 12, 0.85)',
      backdropFilter: 'blur(8px)',
      WebkitBackdropFilter: 'blur(8px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 200,
      padding: '1.25rem'
    }}>
      <div className="cyber-card" style={{
        maxWidth: '560px',
        width: '100%',
        position: 'relative',
        background: 'var(--bg-surface)',
        border: '1px solid var(--border-subtle)',
        boxShadow: '0 20px 50px rgba(0, 0, 0, 0.8)'
      }}>
        <button 
          onClick={onClose}
          style={{
            position: 'absolute',
            top: '1.25rem',
            right: '1.25rem',
            background: 'transparent',
            border: 'none',
            color: 'var(--text-muted)',
            cursor: 'pointer',
            padding: '0.25rem'
          }}
        >
          <X size={18} />
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', marginBottom: '1.25rem' }}>
          <div style={{
            background: 'rgba(244, 63, 94, 0.15)',
            border: '1px solid rgba(244, 63, 94, 0.3)',
            borderRadius: '10px',
            width: '40px',
            height: '40px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <ShieldAlert size={20} color="var(--cyber-rose)" />
          </div>
          <div>
            <h3 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#fff' }}>
              Authorization & Ethical Engagement Policy
            </h3>
            <p style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-subtle)' }}>
              MANDATORY CONSENT VERIFICATION
            </p>
          </div>
        </div>

        <div style={{ fontSize: '0.875rem', color: 'var(--text-muted)', lineHeight: '1.6', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          <p>
            Under international computer crime frameworks (such as the CFAA 18 U.S.C. § 1030), probing or auditing 
            the security posture of networks and applications without explicit permission is strictly prohibited.
          </p>

          <div style={{
            backgroundColor: 'rgba(6, 9, 17, 0.75)',
            padding: '1rem',
            borderRadius: '8px',
            borderLeft: '4px solid var(--cyber-cyan)',
            borderTop: '1px solid var(--border-subtle)',
            borderRight: '1px solid var(--border-subtle)',
            borderBottom: '1px solid var(--border-subtle)'
          }}>
            <strong style={{ color: '#fff', fontSize: '0.85rem' }}>By proceeding, you certify that:</strong>
            <ul style={{ paddingLeft: '1.2rem', marginTop: '0.5rem', display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.825rem' }}>
              <li>You are the verified owner of the target website domain, OR</li>
              <li>You possess explicit written authorization from the owner to conduct posture assessments, OR</li>
              <li>You are auditing a local sandboxed target (such as OWASP Juice Shop on localhost).</li>
            </ul>
          </div>

          <p style={{ fontSize: '0.8rem', color: 'var(--text-subtle)' }}>
            Audit records and authorization confirmations are preserved in the local SQLite database.
          </p>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '1.75rem' }}>
          <button className="btn btn-cyber-secondary" onClick={onClose}>
            Cancel
          </button>
          <button 
            className="btn btn-cyber-primary" 
            onClick={() => {
              onConfirm();
              onClose();
            }}
          >
            <CheckCircle size={15} />
            <span>I Acknowledge & Authorize</span>
          </button>
        </div>
      </div>
    </div>
  );
}
