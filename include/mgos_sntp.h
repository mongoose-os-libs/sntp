#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Returns 0 until synced. After that, returns uptime in seconds of the
 * last sync event, as returned by `mgos_uptime()`.
 */
double mgos_sntp_get_last_synced_uptime(void);

#ifdef __cplusplus
}
#endif
