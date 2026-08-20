import { ChangeDetectionStrategy, Component, signal } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { MenuComponent } from './menu.component';

/**
 * HOST shell root: brand header + menubar + the router-outlet every federated
 * remote mounts into. [textContent] bindings only (see menu.component.ts).
 */
@Component({
  selector: 'snap-host-root',
  standalone: true,
  imports: [RouterOutlet, MenuComponent],
  template: `
    <header class="snap-shell-header">
      <span class="brand" [textContent]="brand()"></span>
      <snap-host-menu />
    </header>
    <main>
      <router-outlet />
    </main>
  `,
  styles: [
    `
      .snap-shell-header {
        display: flex;
        align-items: center;
        gap: 2rem;
        padding: 0.75rem 1.5rem;
        background: var(--hug-bg-1);
        border-bottom: 1px solid var(--hug-border);
      }
      .snap-shell-header .brand {
        color: var(--hug-accent-soft);
        font-weight: 600;
      }
    `,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AppComponent {
  readonly brand = signal('{{BRAND_TITLE}}');
}
