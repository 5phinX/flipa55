# Project Context: Flipa55 (Flipper Zero Application)

## Overview
- **App ID:** `flipa55` (`FlipperAppType.EXTERNAL`)
- **Language:** C++ (`main.cpp`) compiled via the Flipper Zero `uFBT` toolchain.
- **Architecture:** Uses `ViewDispatcher` with `Submenu`, `Widget`, and `TextInput` GUI modules, plus `LFRFIDWorker`, `ProtocolDict`, `DialogsApp`, and `Storage`.

## Build & Deployment Commands
- **Compile only (use this to verify all code changes):** `ufbt`
- **Compile and flash to connected Flipper Zero:** `ufbt launch`
- **CRITICAL:** Never run `ufbt cli` as an automated agent command, as it opens an interactive serial session that blocks the terminal indefinitely.

## Flipper Zero Coding Rules & Guardrails
1. **Verify SDK Headers First:** Never guess Flipper OS function prototypes, enum names, or callback signatures. Always search `~/.ufbt/current/sdk_headers/` (e.g., `~/.ufbt/current/sdk_headers/f7_sdk/`) to verify exact parameter orders and types before writing code.
2. **C++ Compatibility:** 
   - Keep `extern "C"` on the `flipa55_main` entry point.
   - Explicitly cast `void*` returns (such as `malloc` and `furi_record_open`) to their target pointer types.
   - Ensure callback function signatures match the exact typedef in the SDK headers—do not rely on `-fpermissive`.
3. **Thread Safety:** 
   - Background worker callbacks (like `LFRFIDWorkerReadCallback` and `LFRFIDWorkerWriteCallback`) run on worker threads.
   - Never call `lfrfid_worker_stop_thread()` or `view_dispatcher_switch_to_view()` inside a worker callback. Always send a custom event via `view_dispatcher_send_custom_event()` and handle thread teardown and UI updates inside `custom_event_callback` on the main thread.
4. **Memory Management:** Every `*_alloc()` or `furi_record_open()` in `flipa55_main` must have a matching `*_free()` or `furi_record_close()` in the exit cleanup block.
