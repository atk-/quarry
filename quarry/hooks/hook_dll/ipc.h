#pragma once
#include <windows.h>
#include <stdint.h>

/* HookId values — keep in sync with quarry/hooks/ipc_server.py HookId enum */
typedef enum {
    HOOK_VIRTUAL_ALLOC         = 1,
    HOOK_VIRTUAL_PROTECT       = 2,
    HOOK_WRITE_PROCESS_MEMORY  = 3,
    HOOK_CREATE_REMOTE_THREAD  = 4,
    HOOK_CRYPT_ENCRYPT         = 5,
    HOOK_CRYPT_DECRYPT         = 6,
    HOOK_BCRYPT_ENCRYPT        = 7,
    HOOK_INTERNET_CONNECT      = 8,
    HOOK_HTTP_SEND_REQUEST     = 9,
    HOOK_CREATE_SERVICE        = 10,
    HOOK_CHANGE_SERVICE_CONFIG = 11,
    HOOK_MEM_DUMP              = 12,  /* RW→RX region dumped; payload = file path */
} HookId;

BOOL quarry_ipc_init(void);
void quarry_ipc_teardown(void);
void quarry_ipc_send(uint32_t hook_id, const char *payload, uint32_t payload_len);
