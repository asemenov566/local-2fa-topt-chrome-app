---
name: add-autofill-site
description: Add or adapt a site-specific TOTP autofill strategy in Local 2FA Authenticator, including its service metadata, generated bundle and synthetic browser tests.
---

# Add a TOTP autofill site

Use this workflow for the extension's site integrations. The shared runner owns activation, login intent, timing, cleanup and messages; each site class owns its DOM selectors and continuation button.

## Inspect and implement

1. Read [the runner](../../extension/autofill.js), [background checks](../../extension/background.js), an existing class in [strategy](../../extension/strategy), and the relevant tests. Inspect the requested login and TOTP forms without submitting real credentials. Capture only structural details needed for selectors; do not put account names, live authentication URLs, tokens or screenshots into fixtures.
2. Add `extension/strategy/<id>.js` with a default-exported class. The lowercase `<id>` must match `static id`. Define `static displayName`, `static domain` and `static customDomain`. Fixed domains use an exact HTTPS origin; a self-hosted service uses `domain = null` and `customDomain = true`. Keep both public and administration login paths in one class when they use the same account binding.
3. Implement `static route(url, otp = false)` for background URL validation and instance methods `isAuthPage()`, `fields(visible)`, `loginAction(button)`, `authTarget(target)` and `submit(fields, visible)`, matching the existing runner's contract. Inspect the actual element attributes rather than guessing a generic six-digit field selector. Separate authenticator TOTP from SMS, email and recovery codes. A submit action must identify the same visible authentication form and its intended enabled continuation button; never click a generic page-wide button or bypass disabled controls.

## Build and verify

- Run `npm run build:strategies`. It discovers class files, validates metadata, generates the registry used by the service selector/core/background, and bundles one runner with one site class into each `extension/generated/<id>.js`. Do not hand-edit the generated registry or bundles and do not add a service-specific branch to the UI, core or background.
- Commit the class, generated registry/bundles and `scripts/strategy-files.json`. The release packager uses that explicit list; adding a strategy must not broaden packaging to an arbitrary directory copy. Run `npm run check:strategies` to verify generated files match their inputs.
- Add routed synthetic browser cases to [the autofill tests](../../tests/autofill-test.cjs) or a new file registered in [the runner](../../tests/run-browser-tests.cjs). Use reserved example domains for self-hosted services and synthetic keys. Route fixed public domains locally in tests; never send fixture OTPs to a real site.
- Cover recognized TOTP forms, login intent and navigation, continuation exactly once, an unrelated form, manual/nonempty input, denied permission, disabled mode, lock/unlock and turning the mode off while a request is in flight. Verify site bindings survive disabling and re-enabling. Run `npm test` and the affected browser tests; run the full suite before release.

## Security and resource limits

Only the bound exact origin with Chrome's granted host permission can receive its code. The page must never receive the secret key. Keep fixed-origin enforcement and path checks in the strategy metadata/route, in addition to DOM recognition. A new integration does not grant browser permissions automatically.

Preserve the runner's event-driven lifetime: no background polling, global scanning timer or permanently active DOM observer. Observation may be bounded to the user's login flow and must stop on fill, cancellation, timeout or mode disable. Loading a class/registry must have no DOM side effects; its constructor must not attach listeners. Off means no registered content scripts or live listeners.

Report which observed forms and synthetic tests support the integration, and distinguish those checks from a real successful login. Publishing a release remains a separate authorized action.
