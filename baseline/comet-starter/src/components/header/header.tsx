import { Banner, Icon, useHeader } from '@metrostar/comet-uswds';
import { APP_TITLE } from '@src/utils/constants';
import { lowercaseHyphenateString } from '@src/utils/helpers';
import React, { useEffect, useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';

const NAV_LINKS = [
  { name: 'Dashboard',     url: '/' },
  { name: 'Applications',  url: '/applications' },
  { name: 'Run Scan',      url: '/new-scan' },
  { name: 'Metrics',       url: '/metrics' },
  { name: 'Settings',      url: '/settings' },
];

export const Header = (): React.ReactElement => {
  const { on, off } = useHeader();
  const [showMenu, setShowMenu] = useState(false);
  const location = useLocation();

  const handleMenuClick = (): void => {
    window.scrollTo({ top: 0 });
    setShowMenu(!showMenu);
  };

  useEffect(() => {
    const bodyElement = document.body;
    on(bodyElement);
    return () => { off(bodyElement); };
  });

  useEffect(() => {
    const ref = document.body.style;
    ref.overflow = showMenu ? 'hidden' : 'visible';
  }, [showMenu]);

  useEffect(() => { setShowMenu(false); }, [location]);

  return (
    <>
      <a className="usa-skipnav" href="#mainSection">Skip to main content</a>
      <Banner id="banner" />
      <div className="usa-overlay"></div>
      <header className="usa-header usa-header--basic">
        <div className="usa-nav-container">
          <div className="usa-navbar">
            <div className="usa-logo" id="logo">
              <NavLink id="logo-link" to="/" style={{ display: 'flex', alignItems: 'center', gap: 10, textDecoration: 'none' }}>
                <img src="/epyon-logo.svg" alt="Epyon" style={{ height: 32, width: 32 }} />
                <em className="usa-logo__text" style={{ fontStyle: 'normal', fontWeight: 700, color: 'var(--epyon-text)', fontSize: '1.1rem' }}>
                  {APP_TITLE}
                </em>
              </NavLink>
            </div>
            <button type="button" className="usa-menu-btn" onClick={handleMenuClick}>
              Menu
            </button>
          </div>
          <nav className="usa-nav">
            <button type="button" className="usa-nav__close">
              <Icon id="menu-icon" type="close" />
            </button>
            <ul className="usa-nav__primary usa-accordion">
              {NAV_LINKS.map((link) => (
                <li key={link.url} className="usa-nav__primary-item">
                  <NavLink
                    id={`${lowercaseHyphenateString(link.name)}-link`}
                    to={link.url}
                    className={`usa-nav__link ${location.pathname === link.url ? 'usa-current' : ''}`}
                  >
                    {link.name}
                  </NavLink>
                </li>
              ))}
            </ul>
          </nav>
        </div>
      </header>
    </>
  );
};
