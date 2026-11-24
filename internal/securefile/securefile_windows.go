//go:build windows

package securefile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileAllAccess is FILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF),
// which is what the SDDL shorthand "FA" expands to.
const fileAllAccess = 0x1F01FF

// WriteFile writes data with an owner-only, protected DACL. The DACL is part of
// the create call and is also applied to the opened handle, so secret bytes are
// never present under inherited permissions.
func WriteFile(path string, data []byte) error {
	return writeFile(path, data, windows.CREATE_ALWAYS)
}

// WriteFileExclusive creates a new file and fails with fs.ErrExist instead of
// reusing an existing path. The name is claimed and the security descriptor is
// applied in one create operation.
func WriteFileExclusive(path string, data []byte) error {
	return writeFile(path, data, windows.CREATE_NEW)
}

func writeFile(path string, data []byte, disposition uint32) error {
	if path == "" {
		return errors.New("empty path")
	}
	sd, dacl, err := ownerOnlyDescriptor(false)
	if err != nil {
		return err
	}
	defer runtime.KeepAlive(sd)

	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	h, err := windows.CreateFile(
		p,
		windows.GENERIC_WRITE|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		&sa,
		disposition,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return fs.ErrExist
		}
		return err
	}
	// The create-time descriptor only applies to a newly created object. For an
	// existing file the restriction is installed on the handle before any bytes
	// are written, which closes the path-replacement window.
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		windows.CloseHandle(h)
		return fmt.Errorf("restricting file permissions: %w", err)
	}
	f := os.NewFile(uintptr(h), path)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// MkdirAll creates a directory with an owner-only, protected DACL. Each missing
// component is restricted immediately after creation and before its children
// are created, so a newly created child inherits only owner access.
func MkdirAll(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	var missing []string
	for p := abs; ; p = filepath.Dir(p) {
		if _, err := os.Stat(p); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return err
		}
		missing = append(missing, p)
		parent := filepath.Dir(p)
		if parent == p {
			return fmt.Errorf("cannot create %s", path)
		}
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if err := os.Mkdir(missing[i], 0700); err != nil && !os.IsExist(err) {
			return err
		}
		if err := RestrictDir(missing[i]); err != nil {
			return err
		}
	}
	return RestrictDir(abs)
}

// RestrictFile replaces the file DACL with a protected owner-only ACE.
func RestrictFile(path string) error {
	return setOwnerOnly(path, false)
}

// RestrictDir replaces the directory DACL with a protected owner-only ACE that
// is inheritable by children.
func RestrictDir(path string) error {
	return setOwnerOnly(path, true)
}

// IsOwnerOnly reports whether the object has a protected DACL that grants
// access only to the object owner.
func IsOwnerOnly(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return checkOwnerOnly(path, info.IsDir())
}

func ownerSIDString() (string, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}

// ownerOnlyDescriptor builds the protected DACL used both at create time and
// when tightening an existing object.
func ownerOnlyDescriptor(dir bool) (*windows.SECURITY_DESCRIPTOR, *windows.ACL, error) {
	sid, err := ownerSIDString()
	if err != nil {
		return nil, nil, fmt.Errorf("resolving process owner SID: %w", err)
	}
	sddl := "D:P(A;;FA;;;" + sid + ")"
	if dir {
		sddl = "D:P(A;OICI;FA;;;" + sid + ")"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, nil, fmt.Errorf("building security descriptor: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, nil, fmt.Errorf("extracting DACL: %w", err)
	}
	return sd, dacl, nil
}

func setOwnerOnly(path string, dir bool) error {
	if path == "" {
		return errors.New("empty path")
	}
	sd, dacl, err := ownerOnlyDescriptor(dir)
	if err != nil {
		return err
	}
	defer runtime.KeepAlive(sd)
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
}

func checkOwnerOnly(path string, dir bool) bool {
	h, err := openForSecurity(path)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)

	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}

	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}

	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false
	}

	dacl, defaulted, err := sd.DACL()
	if err != nil || dacl == nil || defaulted || dacl.AceCount != 1 {
		return false
	}

	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		return false
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		return false
	}
	if ace.Mask != fileAllAccess {
		return false
	}
	if dir {
		const inherit = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
		if ace.Header.AceFlags&inherit != inherit {
			return false
		}
	}

	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	return aceSID.Equals(owner)
}

func openForSecurity(path string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(
		p,
		windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
}
