/*
 * Wrapper for Falcon implementation.
 * This combines all Falcon components into a single compilation unit.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Include all Falcon implementation files */
#include "api.h"
#include "fpr.h"
#include "inner.h"

/* The actual implementation is in these files which are already being compiled separately.
 * This file acts as a placeholder/wrapper to satisfy the build system.
 */

/*
 * Dummy function to ensure this file produces object code
 */
void falcon_dummy(void) {
    /* This function exists solely to ensure the compiler generates an object file */
}
