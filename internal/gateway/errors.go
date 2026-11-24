package gateway

import "errors"

// ErrNoActiveLink reports that no connection is selected. It is permanent for
// this start attempt, but the daemon keeps running so the panel can be used to
// import and select one.
var ErrNoActiveLink = errors.New("no active link configured")

// PermanentError marks a startup failure that waiting cannot fix: the stored
// configuration, credentials or host state must be corrected first. The run
// loop uses IsPermanent to exit instead of retrying every 30 seconds, which
// would otherwise look like a transient outage forever.
type PermanentError struct {
	Err error
}

func (e *PermanentError) Error() string { return e.Err.Error() }

func (e *PermanentError) Unwrap() error { return e.Err }

func permanent(err error) error {
	if err == nil {
		return nil
	}
	var p *PermanentError
	if errors.As(err, &p) {
		return err
	}
	return &PermanentError{Err: err}
}

// IsPermanent reports whether err is a startup failure that requires operator
// action rather than another attempt.
func IsPermanent(err error) bool {
	var p *PermanentError
	return errors.As(err, &p)
}
