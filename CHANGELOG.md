# Change Log

All notable changes to the Offensive 360 Visual Studio Extension will be documented in this file.

## [3.0.3] - 2026-05-03

### Added
- **ExternalScan endpoint with automatic fallback to `Project/scanProjectFile`.** The plugin now probes `/app/api/ExternalScan/scanQueuePosition` first; if available it uses the inline ExternalScan flow, otherwise it falls back to the persistent `scanProjectFile` flow with project-id polling. This makes External-token-only servers work end-to-end without any user configuration.
- `WaitForScanAndFetchResults` and `FetchProjectResults` helpers covering the persistent-project path: poll `/app/api/Project/{id}` for status (Queued / InProgress / Succeeded / Partial / Failed / Skipped), then fetch `/LangaugeScanResult?page=1&pageSize=500` for findings.

### Fixed
- View > Other Windows menu: switched the tool window group's parent from `IDG_VS_VIEW_TOOLWINDOWS` to `IDG_VS_VIEW_DEV_WINDOWS` so the Offensive 360 Tool Window now appears under **View > Other Windows** as expected (it was being placed in the wrong group).

## [3.0.2] - 2026-04-08

### Fixed
- Various marketplace listing fixes (screenshots, validation, MenuResourceID, OptionsPage GUID).
