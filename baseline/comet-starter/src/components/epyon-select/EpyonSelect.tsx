import React, { useEffect, useRef, useState } from 'react';

export interface EpyonSelectOption {
  value: string;
  label: string;
}

interface EpyonSelectProps {
  id?: string;
  value: string;
  options: EpyonSelectOption[];
  placeholder?: string;
  onChange: (value: string) => void;
}

export const EpyonSelect = ({
  id,
  value,
  options,
  placeholder = '— select —',
  onChange,
}: EpyonSelectProps): React.ReactElement => {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const selected = options.find((o) => o.value === value);
  const label = selected ? selected.label : placeholder;

  return (
    <div id={id} ref={ref} className="epyon-select" aria-expanded={open}>
      <button
        type="button"
        className="epyon-select__trigger"
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="listbox"
      >
        <span>{label}</span>
        <svg
          className="epyon-select__caret"
          viewBox="0 0 10 6"
          width="10"
          height="6"
          aria-hidden="true"
        >
          <path d="M0 0l5 6 5-6z" fill="currentColor" />
        </svg>
      </button>
      {open && (
        <ul className="epyon-select__list" role="listbox" aria-label={id}>
          {options.map((opt) => (
            <li
              key={opt.value}
              role="option"
              aria-selected={opt.value === value}
              className={`epyon-select__item${opt.value === value ? ' epyon-select__item--active' : ''}`}
              onMouseDown={() => {
                onChange(opt.value);
                setOpen(false);
              }}
            >
              {opt.value === value && (
                <svg viewBox="0 0 12 9" width="12" height="9" aria-hidden="true" style={{ marginRight: 6, flexShrink: 0 }}>
                  <path d="M1 4l3.5 3.5L11 1" stroke="currentColor" strokeWidth="1.8" fill="none" strokeLinecap="round" />
                </svg>
              )}
              {opt.label}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};
