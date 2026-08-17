#pragma once
#include <windows.h>
#include <stdint.h>

/* Call once from DllMain DLL_PROCESS_ATTACH to set up the per-process dump dir. */
void  dumper_init(void);

/* Write the memory region [addr, addr+size) to a file under the dump dir.
 * Returns a heap-allocated path string that the caller must LocalFree(),
 * or NULL if the dump could not be written (region unreadable, disk error,
 * or size exceeds MAX_DUMP_BYTES). */
char *dumper_write(LPVOID addr, SIZE_T size);
