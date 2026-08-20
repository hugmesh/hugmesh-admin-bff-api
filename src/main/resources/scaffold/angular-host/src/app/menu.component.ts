import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { RouterLink, RouterLinkActive } from '@angular/router';
import { CapabilitiesStub } from './capabilities.stub';

/** A primary menubar entry. `slug` is the optional federation-capability slug an
 *  entry depends on (absent for the always-present Home); an entry whose slug is
 *  not installed renders GREYED with the reason as its tooltip — the exemplar's
 *  visible-but-disabled convention (grey + explain, never hide, never a dead
 *  link). */
interface NavEntry {
  readonly label: string;
  readonly route: string;
  readonly slug?: string;
}

/**
 * Minimal host menubar keyed off the capabilities stub. The router-outlet is the
 * swappable content region; selecting an entry navigates the host shell to the
 * matching federated remote.
 *
 * WHY [textContent] AND NOT ANGULAR INTERPOLATION: the mesh templating renderer
 * treats every bare double-curly identifier in a template as a brand token and
 * fail-closes on non-allowlisted names, so Angular's own mustache interpolation
 * cannot appear anywhere in an archetype-skeleton source file. Property bindings
 * ([textContent]="entry.label") express the same thing without mustaches.
 */
@Component({
  selector: 'snap-host-menu',
  standalone: true,
  imports: [RouterLink, RouterLinkActive],
  template: `
    <nav class="snap-menu" aria-label="Main navigation">
      <ul role="menubar">
        @for (entry of navEntries; track entry.route) {
          <li role="none">
            @if (isEnabled(entry)) {
              <a
                role="menuitem"
                [routerLink]="entry.route"
                routerLinkActive="active"
                ariaCurrentWhenActive="page"
                [textContent]="entry.label"
              ></a>
            } @else {
              <span
                role="menuitem"
                aria-disabled="true"
                class="disabled"
                [title]="disabledReason(entry)"
                [textContent]="entry.label"
              ></span>
            }
          </li>
        }
      </ul>
    </nav>
  `,
  styles: [
    `
      .snap-menu ul {
        display: flex;
        gap: 1.5rem;
        margin: 0;
        padding: 0;
        list-style: none;
      }
      .snap-menu a {
        color: var(--hug-text);
        text-decoration: none;
      }
      .snap-menu a.active {
        color: var(--hug-accent-soft);
      }
      .snap-menu .disabled {
        color: var(--hug-text-muted);
        cursor: not-allowed;
      }
    `,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class MenuComponent {
  private readonly capabilities = inject(CapabilitiesStub);

  /** Home + the one example remote (route + slug = its app_slug identity). */
  readonly navEntries: readonly NavEntry[] = [
    { label: 'Home', route: '/home' },
    { label: '{{TITLE_WORD}}', route: '/{{APP_SLUG}}', slug: '{{APP_SLUG}}' },
  ];

  /** Slug-less entries are always reachable; slugged ones follow install-state. */
  isEnabled(entry: NavEntry): boolean {
    return entry.slug === undefined || this.capabilities.installed(entry.slug);
  }

  disabledReason(entry: NavEntry): string {
    return entry.slug === undefined
      ? ''
      : 'Not installed on this deployment';
  }
}
