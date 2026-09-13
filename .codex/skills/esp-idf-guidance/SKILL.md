---
name: esp-idf-guidance
description: Apply shared ESP-IDF, FreeRTOS, and multi-core guidance when changing embedded application or component code.
---

# ESP-IDF Guidance

- Prefer established ESP-IDF types and error paths: `esp_err_t`, `ESP_OK`, `ESP_ERR_*`, and the local `ESP_RETURN_ON_*` patterns. Validate public or reusable helper inputs early and retain surrounding `assert(...)` checks.
- Preserve the component's existing FreeRTOS, ESP-IDF, MbedTLS, and utility-library patterns. Do not introduce exceptions, RTTI-dependent code, or heavyweight STL facilities into embedded paths unless the current design already relies on them.
- Keep component registration, dependency declarations, target exclusions, embedded assets, and publish/include rules consistent with the existing CMake and component manifest files.

## Multi-core FreeRTOS

- Treat every task and shared object as potentially concurrent. An unpinned task may run on any available core; do not rely on the creating task's core for ownership or correctness.
- Use `xTaskCreatePinnedToCore()` or its static variant only when affinity has a documented hardware, latency, or isolation requirement. Use `tskNO_AFFINITY` when a task does not require a core, and never hardcode core 1 without confirming the target supports it; single-core targets run only on core 0.
- Protect cross-task or cross-core state with the established mutex, queue, event-group, semaphore, or atomic pattern. Do not use `vTaskSuspendAll()` as cross-core mutual exclusion. Use a `portMUX_TYPE` critical section only for short, non-blocking shared-state operations.
- Do not hold locks or critical sections across I/O, allocation, callbacks, delays, or blocking FreeRTOS calls. Use synchronization primitives rather than tick timing to coordinate work between cores.
- ESP-IDF task stack depths are measured in bytes. Ensure a task's parameter and static storage remain valid for its full lifetime, and make task shutdown and ownership explicit.
