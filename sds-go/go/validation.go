package dd_sds

/*
#include <stdlib.h>
#include <dd_sds.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func ValidateRegex(regex string) (bool, error) {
	cRegex := C.CString(regex)
	defer C.free(unsafe.Pointer(cRegex))

	result := C.validate_regex(cRegex, nil)
	// If result is null, regex is valid
	if result == nil {
		return true, nil
	}
	// Otherwise, result contains error message
	errorMsg := C.GoString(result)
	C.free_string(result) // Free the string allocated by Rust
	return false, fmt.Errorf("invalid regex: %s", errorMsg)
}
