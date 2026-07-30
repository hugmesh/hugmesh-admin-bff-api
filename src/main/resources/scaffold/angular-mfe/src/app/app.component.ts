import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';

/**
 * Dev-shell root for the standalone `ng serve` run. In production the HOST
 * shell bootstraps its own root and mounts this remote's exposed `./routes`
 * (ROUTES) directly — this component never renders there.
 */
@Component({
  selector: 'snap-{{APP_SLUG}}-root',
  standalone: true,
  imports: [RouterOutlet],
  template: '<router-outlet />',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AppComponent {}
