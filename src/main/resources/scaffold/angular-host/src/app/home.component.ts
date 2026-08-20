import { ChangeDetectionStrategy, Component, signal } from '@angular/core';

/**
 * Local landing view (the exemplar host's public home slot). Standalone +
 * signals + OnPush, [textContent] bindings only — see menu.component.ts for why
 * Angular's double-curly interpolation cannot appear in a skeleton source file.
 */
@Component({
  selector: 'hug-host-home',
  standalone: true,
  template: `
    <section class="hug-home">
      <h1 [textContent]="title()"></h1>
      <p [textContent]="message()"></p>
    </section>
  `,
  styles: [
    `
      .hug-home {
        max-width: 32rem;
        margin: 4rem auto;
        text-align: center;
        color: var(--hug-text);
      }
      .hug-home h1 {
        color: var(--hug-accent-soft);
      }
      .hug-home p {
        color: var(--hug-text-muted);
      }
    `,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class HomeComponent {
  readonly title = signal('{{BRAND_TITLE}}');
  readonly message = signal('Host shell up — pick a federated remote from the menu.');
}
