import { bootstrapApplication } from '@angular/platform-browser';
import { provideRouter } from '@angular/router';
import { AppComponent } from './app/app.component';
import { routes } from './app/app.routes';

// Bootstrap the standalone dev-shell application. This file is only executed
// when the remote is served standalone (`ng serve {{APP_SLUG}}`); in production
// the host shell bootstraps its own Angular app and federates `./routes`
// directly — this bootstrap is not involved. Add provideHttpClient(withFetch())
// here the moment this remote grows BFF-backed datastore services (the fleet
// remotes use the fetch adapter for native-federation compatibility).
bootstrapApplication(AppComponent, {
  providers: [
    provideRouter(routes),
  ],
}).catch((err) => console.error(err));
