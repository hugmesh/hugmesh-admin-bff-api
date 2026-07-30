import { bootstrapApplication } from '@angular/platform-browser';
import { provideRouter } from '@angular/router';
import { AppComponent } from './app/app.component';
import { routes } from './app/app.routes';

// Bootstrap the HOST shell. Runs only after main.ts's initFederation() resolved
// (or gracefully degraded), so loadRemoteModule() inside the REMOTE_ROUTES lazy
// loaders can find every registered remote. Add provideHttpClient(withFetch())
// here the moment the capabilities STUB is replaced by the HTTP-backed
// CapabilitiesService (public GET /api/federation/capabilities — see
// src/app/capabilities.stub.ts).
bootstrapApplication(AppComponent, {
  providers: [
    provideRouter(routes),
  ],
}).catch((err) => console.error(err));
