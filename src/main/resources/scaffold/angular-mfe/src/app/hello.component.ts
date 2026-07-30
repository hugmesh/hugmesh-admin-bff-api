import { ChangeDetectionStrategy, Component, signal } from '@angular/core';

/**
 * The one example view this remote federates. Standalone + signals + OnPush —
 * the house component shape.
 *
 * WHY [textContent] AND NOT ANGULAR INTERPOLATION: the mesh templating renderer
 * treats every bare double-curly identifier in a template as a brand token and
 * fail-closes on non-allowlisted names, so Angular's own mustache interpolation
 * cannot appear anywhere in an archetype-skeleton source file (not even in a
 * comment). Property bindings ([textContent]="title()") express the same thing
 * without mustaches; keep that style for any text this skeleton renders.
 */
@Component({
  selector: 'snap-{{APP_SLUG}}-hello',
  standalone: true,
  template: `
    <main class="snap-hello">
      <h1 [textContent]="title()"></h1>
      <p [textContent]="message()"></p>
    </main>
  `,
  styles: [
    `
      /* Consume the cross-repo --sd-* palette contract (src/styles.scss). */
      .snap-hello {
        max-width: 24rem;
        margin: 4rem auto;
        text-align: center;
        color: var(--sd-text);
      }
      .snap-hello h1 {
        color: var(--sd-accent-soft);
      }
      .snap-hello p {
        color: var(--sd-text-muted);
      }
    `,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class HelloComponent {
  readonly title = signal('{{BRAND_TITLE}} {{TITLE_WORD}}');
  readonly message = signal('This remote is served by native federation.');
}
