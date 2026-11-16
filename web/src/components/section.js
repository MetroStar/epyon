export function toggleSection(id) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('collapsed');
}
