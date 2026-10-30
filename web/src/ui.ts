import { ApiError } from './api.js';
import { h } from './dom.js';

/** Shared page helpers, so every view renders and reports errors the same way. */

const root = document.getElementById('app') as HTMLElement;

export function show(...nodes: (Node | null)[]): void {
  root.replaceChildren(...nodes.filter((n): n is Node => n !== null));
  root.focus({ preventScroll: true });
  window.scrollTo(0, 0);
}

export const alert = (message: string, kind: 'error' | 'info' = 'error') => h('p', { class: `alert alert-${kind}`, role: 'alert' }, message);

export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 429) return 'Trop de tentatives. Fais une pause avant de réessayer.';
    // Validation errors say what to fix: show the reasons, as text (never interpreted as HTML).
    if (err.issues.length > 0) return `${err.message} : ${err.issues.map((i) => (i.path ? `${i.path} : ${i.message}` : i.message)).join(' ; ')}`;
    return err.message;
  }
  return 'Le serveur ne répond pas. Vérifie que Bastion est bien lancé.';
}

/**
 * Wires a form to an async action: disables the button while it runs and shows
 * the error in `status`. Keeps every form's behaviour identical.
 */
export function onSubmit(form: HTMLFormElement, status: HTMLElement, action: () => Promise<void>): void {
  const button = form.querySelector('button[type="submit"]');
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (button instanceof HTMLButtonElement) button.disabled = true;
    status.replaceChildren();
    action()
      .catch((err: unknown) => {
        status.replaceChildren(alert(errorMessage(err)));
      })
      .finally(() => {
        if (button instanceof HTMLButtonElement) button.disabled = false;
      });
  });
}
