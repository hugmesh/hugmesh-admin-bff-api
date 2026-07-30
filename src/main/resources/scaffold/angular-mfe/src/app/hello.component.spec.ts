import { TestBed } from '@angular/core/testing';
import { HelloComponent } from './hello.component';

describe('HelloComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [HelloComponent] }).compileComponents();
  });

  it('renders the EXACT branded title and message via [textContent]', () => {
    const fixture = TestBed.createComponent(HelloComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    // Exact-text assertions: the title is the brand+role pair the archetype
    // renders; the message is the component's literal copy.
    expect(el.querySelector('h1')?.textContent).toBe('{{BRAND_TITLE}} {{TITLE_WORD}}');
    expect(el.querySelector('p')?.textContent).toBe('This remote is served by native federation.');
  });
});
