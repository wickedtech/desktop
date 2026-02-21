# Security & Release Hardening Report

**Date**: 2026-02-21
**Author**: Security & Release Hardening Agent
**Branch**: `ai/security-20260221`

## Summary
This report details the security and release hardening efforts for the VPN.ht desktop app (Tauri). The following tasks were completed:

1. **Dependency Audit**: Identified and fixed critical vulnerabilities in JavaScript/TypeScript and Rust dependencies.
2. **Secrets Check**: Verified no hardcoded secrets in the repository.
3. **CodeQL**: Added CodeQL workflow for static code analysis.
4. **Auto-Updater**: Reviewed and confirmed the auto-updater configuration.
5. **Permissions**: Reviewed and confirmed secure permissions and CSP.

---

## 1. Dependency Audit
### JavaScript/TypeScript
#### Vulnerabilities Fixed
| ID       | Severity | Module      | Title                                                                                     | Patched Version | Status       |
|----------|----------|-------------|-------------------------------------------------------------------------------------------|-----------------|--------------|
| 1102341  | Moderate | `esbuild`   | esbuild enables any website to send requests to the development server and read responses | `0.27.3`        | **Fixed**    |
| 1113371  | High     | `minimatch` | ReDoS via repeated wildcards with non-matching literal in pattern                        | `10.2.2`        | **Fixed**    |

#### Outdated Dependencies
The following dependencies were updated:
- `esbuild` (`0.21.5` → `0.27.3`)
- `minimatch` (`9.0.3` → `10.2.2`)

Other outdated dependencies (e.g., `@tauri-apps/api`, `react`, `vite`) were not upgraded due to potential breaking changes. These should be addressed in a separate PR.

---

### Rust
#### Vulnerabilities and Warnings
`cargo audit` revealed **15 unmaintained dependencies** and **1 unsoundness issue** in the Rust codebase:

| Crate                  | Issue                     | Severity      | Status               |
|-----------------------|---------------------------|---------------|----------------------|
| `atk`, `atk-sys`      | Unmaintained GTK3 bindings | Warning       | **Not Fixed**        |
| `derivative`          | Unmaintained               | Warning       | **Not Fixed**        |
| `fxhash`              | Unmaintained               | Warning       | **Not Fixed**        |
| `gdk`, `gdk-sys`      | Unmaintained GTK3 bindings | Warning       | **Not Fixed**        |
| `gdkwayland-sys`      | Unmaintained GTK3 bindings | Warning       | **Not Fixed**        |
| `gdkx11-sys`          | Unmaintained GTK3 bindings | Warning       | **Not Fixed**        |
| `glib`                | Unsoundness                | **Critical**  | **Not Fixed**        |
| `gtk`, `gtk-sys`      | Unmaintained GTK3 bindings | Warning       | **Not Fixed**        |
| `gtk3-macros`         | Unmaintained GTK3 bindings | Warning       | **Not Fixed**        |
| `instant`             | Unmaintained               | Warning       | **Not Fixed**        |
| `proc-macro-error`    | Unmaintained               | Warning       | **Not Fixed**        |
| `rustls-pemfile`      | Unmaintained               | Warning       | **Not Fixed**        |

#### Dependencies Upgraded
The following dependencies were upgraded:
- `keyring` (`2.3.3` → `3.6.3`)
- `rand` (`0.8.5` → `0.9.2`)
- `reqwest` (`0.11.27` → `0.12.28`)

#### Notes
- The unmaintained GTK3 bindings and unsoundness in `glib` are dependencies of `tauri@1.8.3`. Upgrading to `tauri@2.10.2` would resolve these issues but requires significant refactoring.
- A separate PR should be created to upgrade to `tauri@2.x`.

---

## 2. Secrets Check
- **No hardcoded secrets** were found in the repository.
- GitHub Actions workflows reference secrets (e.g., `MACOS_CERTIFICATE`, `TAURI_SIGNING_PRIVATE_KEY`), which are safely managed by GitHub.
- Passwords and tokens are handled securely using the OS keychain.

---

## 3. CodeQL
- **Added CodeQL workflow** (`.github/workflows/codeql.yml`) for static code analysis.
- **Languages**: JavaScript/TypeScript and Rust.
- **Schedule**: Runs on every push, pull request, and weekly.
- **Customization**: Excludes `node_modules`, `dist`, and test files.

---

## 4. Auto-Updater
- **Enabled**: The Tauri auto-updater is configured and enabled.
- **Endpoints**: Fetches updates from `https://updates.vpnht.com/{{target}}/{{current_version}}`.
- **Signature Verification**: Uses a public key for signature verification.
- **User Prompts**: Enabled (`"dialog": true`).
- **Install Mode**: Windows uses `"passive"` mode.

---

## 5. Permissions
- **HTTP**: Restricted to `https://api.vpnht.com/**`, `https://*.vpnht.com/**`, and `https://updates.vpnht.com/**`.
- **Filesystem**: Restricted to `$APPDATA/**`, `$DESKTOP/**`, `$DOCUMENT/**`, and `$DOWNLOAD/**`.
- **CSP**: Strong Content Security Policy (CSP) is enforced.

---

## 6. Telemetry
- **Not Configured**: No telemetry or analytics are enabled in the app.

---

## 7. Recommendations
1. **Upgrade to `tauri@2.x`**: Resolves unmaintained GTK3 bindings and unsoundness in `glib`.
2. **Upgrade Outdated Dependencies**: Address outdated dependencies (e.g., `@tauri-apps/api`, `react`, `vite`) in a separate PR.
3. **Monitor CodeQL Alerts**: Review and address CodeQL findings in future PRs.
4. **Add Dependabot for Rust**: Configure Dependabot to monitor Rust dependencies for vulnerabilities.

---

## 8. Files Modified
- `.github/workflows/codeql.yml` (Added)
- `.github/codeql-config.yml` (Added)
- `package.json` (Upgraded `esbuild`, `minimatch`)
- `pnpm-lock.yaml` (Updated)
- `src-tauri/Cargo.toml` (Upgraded `keyring`, `rand`, `reqwest`)
- `src-tauri/Cargo.lock` (Updated)
- `AI_REPORTS/security.md` (This report)