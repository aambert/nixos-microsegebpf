// SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
// SPDX-License-Identifier: MIT

package identity

import "unsafe"

// unsafePointer is a small wrapper that converts the byte address into
// the InotifyEvent pointer the watcher needs. Isolating it keeps the
// `unsafe` import to one file.
func unsafePointer(p any) unsafe.Pointer {
	switch v := p.(type) {
	case *byte:
		return unsafe.Pointer(v)
	}
	return nil
}
