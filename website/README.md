# Firewall Insight landing page

A standalone, bilingual (English/Thai) product site for Firewall Insight. It always opens in English; the TH/EN toggle switches language for the current visit. It is a static site with no build step and no runtime API, deployed to GitHub Pages by `.github/workflows/deploy-website.yml`.

## Design

The page follows a Clerk-style rhythm — light sections with crisp cards, broken up by dark bands that hold live, interactive demos — with Resend-style restraint. Every seam blends: the dark bands fade in and out through an eased, slate-tinted gradient (height set by `--seam`), and the CTA floor and footer fade into each other with no borders. Other details: one glow per viewport, micro-glass only on chrome (nav, tab rails, floating chips), and monospace details. Tokens (colors, radii, spacing, motion) are at the top of `styles.css`. Type is Geist / Geist Mono with IBM Plex Sans Thai for Thai glyphs.

| Section | What it does |
| --- | --- |
| Glass nav | TH/EN toggle; mobile menu (Esc closes) |
| Hero + component stage | Four tabs (Policy health, Traffic path, Unknown ≠ false, Network map) rendered as real HTML cards from the captured screens |
| Built-on strip | Technologies the project actually uses |
| Overview | Problem statement, the migration that started the project, three capability cards |
| Capabilities (dark) | Bento of live demos: review feed, read-only command guard, three-state logic, Thai question parser, review sections, diff-by-uid |
| Product screens | Eight real captures in a browser frame (Analyze → Trends) |
| Research | Figures from paper v12 as native, bilingual charts with a 10/20/30% toggle |
| How it works (dark) | Code window with the real read-only allowlists and setup, a sample read log, architecture and lab paths |
| Principle, source CTA, footer | GitHub link and QR code |

## On phones (≤ 700px)

Most visitors open the page from a QR code on a phone, so the phone layout is designed separately rather than just stacked:

- Overview cards, the six capability demos and the three research charts become swipe carousels with snap points, a peek of the next card, and pagination dots.
- The hero headline sizes itself to stay on two lines; the hero tabs and product-screen tabs scroll sideways and keep the selected tab in view; the `git clone` chip is hidden.
- Product screenshots show a taller crop with **Tap to zoom**, which opens a full-screen viewer you can pan.
- Stats sit in a 2×2 grid; the architecture and lab diagrams become compact timelines; the module list scrolls in two rows.
- The CTA swaps the QR code for a **Share** button (native share sheet, or copies the link).
- A floating back-to-top button shows reading progress as a ring; the menu opens as a sheet with large tap targets.

The phone rules live in the `Phone layout (≤ 700px)` block near the end of `styles.css`; carousels are any element with `data-carousel`.

## Interactive demo (`demo/`)

**Try the live demo** (hero), **Explore the platform** (How it works), **Try the interactive demo** (Product screens), **Live demo** in the menu and footer all open `demo/`. It is the real Firewall Insight interface, `app/templates/index.html`, `app.js` and `app.css` copied unchanged, running entirely in the browser with no server behind it:

- `mock-api.js` loads before `app.js` and answers every `/api/*` request the interface makes. Results come from the files in `demo/data/`. Traffic Path and Ask are computed live, by a JavaScript port of the tri-state tracer (`traffic.py`, `matching.py`, `envelope.py`, `implied.py`, `nat_correlate.py`, `path_map.py`, `ask.py`), so any source, destination and service can be tried, in Thai or English.
- `demo.js` loads after `app.js`. It turns downloads (CSV, cleanup script) into in-browser files, opens the stored PDF reports, makes **Exit demo** return to the site, keeps the Package and Layer selectors visible on phones, and adds the **Demo guide** with ready-made traces (EXACT, UNVERIFIED on AD-Services, UNVERIFIED on a time-window rule, a question in Thai).
- On phones (≤ 900px) the demo has its own layout, in `demo.css` (*Phone layout*) and `demo.js` (*phones*): the page scrolls normally; a two-row header keeps Package and Layer selectable; a bottom tab bar (Home, Policy, Trace, Map, Guide) replaces the floating action button; the guide opens as a bottom sheet; tables become labelled cards (the rulebase as one compact card per rule); metric tiles sit two-up; long notes fold to three lines; the network map is taller and pans and zooms with one or two fingers. The application's own `app.js` and `app.css` are unchanged.
- Nothing is saved or sent. Settings are shown as configured in the lab but cannot be saved or tested, and every password and webhook field is switched off. Snapshots, reviews and schedules made during a visit live only in that browser tab.

### Where the demo data comes from

`demo/data/` was produced by running the project's own engine modules (snapshot diff, compliance, trends, remediation, object hygiene, log usage, health diff, topology map and the PDF report) over the External-FW lab data from 15 October 2026:

- **Real lab data:** three snapshots, the 15:45 review and three gateway-health readings; the Internal-FW export (one Allow-Any rule); the objects, compliance and rule-usage results seen in `poster/captures-2026-10-15`. The demo reproduces those captures: 20 rules, 6 compliance checks with 4 failed, 18/16/2/4 objects with 3 duplicates and 3 redundant group members, 12 nodes and 15 links on the map, a 500-record log sample.
- **Changed for publication:** `172.23.0.0/16` is shown as `10.40.0.0/16` (object names included) and the unused VPN pool as `10.66.56.0/24`. The 192.168.x lab VLANs are unchanged.
- **Constructed for the demo:** four scheduled reviews on 9, 12, 13 and 14 October before the real one (the E5 experiment rules appear on 12 October), the gateway objects behind the map, the default *Standard* package (one cleanup rule), a few objects that make up the captured object counts, the time-object name on E5-Time and the source-port range on E5-SrcPort.
- No `NSTH_POLICY` data, credentials or `.env` values are used.

`demo/data/` is generated output, so regenerate it rather than editing it by hand. When the application changes, copy the new `app.js`, `app.css` and template over the files in `demo/`, keeping the three script tags (`mock-api.js`, `app.js`, `demo.js`) and the `demo.css` link in `demo/index.html`.

## Edit the page

| File | Edit here |
| --- | --- |
| `index.html` | English copy (the default language), section layout, navigation, static image paths |
| `content.js` | Thai translations, product-screen descriptions (both languages), demo strings, code samples, chart values |
| `styles.css` | Tokens at the top (including `--seam`, the gradient blend height); section styles and breakpoints (1100 / 900 / 600 px) below |
| `script.js` | Language toggle, accessible tabs, demos, live tickers, scroll reveal |

Every element with `data-i18n` swaps to the matching key in `content.js` when Thai is selected; English is read from the HTML itself. To change the opening language, edit `DEFAULT_LANGUAGE` at the top of `script.js`.

## Motion and accessibility

- Live tickers (review feed, read log) run only while on screen and while the tab is visible, and never under `prefers-reduced-motion`.
- All animation and scroll reveals switch off under `prefers-reduced-motion`; blur switches off under `prefers-reduced-transparency`.
- Tabs follow the WAI-ARIA pattern (arrow keys, Home/End, roving tabindex). Live logs are `aria-live="off"`; the copy button announces through a polite live region.
- Content stays visible with JavaScript disabled.

## Preview locally

From the repository root:

```powershell
python -m http.server 4173 --directory website
```

Open `http://localhost:4173`.

## Deploy on GitHub Pages

`.github/workflows/deploy-website.yml` uploads only this folder whenever `website/**` changes on `main`. In the repository's **Settings → Pages → Build and deployment**, select **GitHub Actions** as the source, then push. The workflow can also be started manually from the Actions tab. Asset paths are relative, so the site works under a project URL such as `https://<account>.github.io/firewall-insight/`.

## Factual scope

- Product screenshots come from `poster/captures-2026-10-15` (15 October 2026). The Traffic Path image is a frame from the user-provided recording, as its caption says.
- Hero cards are transcribed from those captures and the NCCY 2026 poster: health score 95 with 20 rules; Rule 11.1 / Allow-Web / Accept / exact; the UNVERIFIED trace; the simplified ClusterXL lab path.
- Research figures come from paper v12: 7,050 synthetic rules with known answers, 180,000 simulated connections, recall 0.77 → 1.00 for unreachable rules, per-100-question results at 10/20/30% unknown conditions, and 22 real-gateway cases (15/15 confirmed matches, 7 abstentions, 6/6 write commands rejected, 4/4 log matches, 2 defects fixed). Test policies were written for the project; no customer data appears.
- Demo feeds and the read log are labelled “sample data”. The command allowlists and setup commands are copied from the main README.
- No customer logos, testimonials or performance metrics are invented. The quote is the project's own design principle.
- `assets/space/` holds imagery from the previous design and is no longer referenced by the page.

The landing page and the demo do not connect to Check Point, save credentials, or change the Firewall Insight application.
