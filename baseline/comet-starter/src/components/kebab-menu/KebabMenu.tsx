import React, { useEffect, useRef, useState } from 'react';

export interface KebabMenuItem {
  label: string;
  onClick: () => void;
  danger?: boolean;
}

interface KebabMenuProps {
  items: KebabMenuItem[];
}

export const KebabMenu = ({ items }: KebabMenuProps): React.ReactElement => {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  return (
    <div ref={ref} className="epyon-kebab" aria-expanded={open}>
      <button
        type="button"
        className="epyon-kebab__trigger"
        aria-label="Actions"
        onClick={() => setOpen((o) => !o)}
      >
        <span />
        <span />
        <span />
      </button>
      {open && (
        <ul className="epyon-kebab__menu" role="menu">
          {items.map((item) => (
            <li key={item.label} role="menuitem">
              <button
                type="button"
                className={`epyon-kebab__item${item.danger ? ' epyon-kebab__item--danger' : ''}`}
                onMouseDown={() => {
                  item.onClick();
                  setOpen(false);
                }}
              >
                {item.label}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};
