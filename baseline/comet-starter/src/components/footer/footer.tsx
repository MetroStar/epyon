import { APP_TITLE } from '@src/utils/constants';
import React from 'react';
import { NavLink } from 'react-router-dom';

const NAV_LINKS = [
  { name: 'Dashboard',    url: '/' },
  { name: 'Applications', url: '/applications' },
  { name: 'Run Scan',     url: '/new-scan' },
  { name: 'Settings',     url: '/settings' },
];

export const Footer = (): React.ReactElement => {
  const year = new Date().getFullYear();

  return (
    <footer className="usa-footer">
      <div className="usa-footer__primary-section">
        <nav className="usa-footer__nav" aria-label="Footer navigation">
          <ul className="grid-row grid-gap">
            {NAV_LINKS.map((link) => (
              <li
                key={link.url}
                className="mobile-lg:grid-col-auto usa-footer__primary-content"
              >
                <NavLink className="usa-footer__primary-link" to={link.url}>
                  {link.name}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
      </div>
      <div className="usa-footer__secondary-section">
        <div className="grid-container">
          <div className="grid-row grid-gap" style={{ alignItems: 'center', justifyContent: 'space-between' }}>
            <div className="usa-footer__logo" style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <img src="/epyon-logo.svg" alt="Epyon" style={{ height: 32, width: 32 }} />
              <div>
                <p className="usa-footer__logo-heading" style={{ margin: 0 }}>
                  {APP_TITLE}
                </p>
                <p style={{ fontSize: 12, color: 'var(--epyon-text-dim)', margin: '4px 0 0' }}>
                  Absolute Security Control
                </p>
              </div>
            </div>
            <div style={{ fontSize: 12, color: 'var(--epyon-text-dim)', textAlign: 'right' }}>
              © {year} {APP_TITLE}
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
};

