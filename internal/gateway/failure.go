package gateway

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/profile"
)

// linkFailure is the error returned when the selected link and every eligible
// fallback failed. It keeps the failed link, the time and the cause that
// belongs to it, and lists the fallbacks that were tried.
//
// Reporting the last attempt's error instead made an unrelated candidate
// (for example 'us-udp53b') look like the cause of a failure that started on
// the selected link, so the summary names the selected link first and labels
// every other attempt as a fallback.
type linkFailure struct {
	Selected  string
	Group     string
	At        time.Time
	Cause     error
	Fallbacks []linkAttempt
}

type linkAttempt struct {
	Link string
	Err  error
}

func linkLabel(link *profile.Link) string {
	if link == nil {
		return ""
	}
	if link.Group == "" {
		return link.Remark
	}
	return link.Group + ":" + link.Remark
}

// outcomeError normalises a failed attempt. A nil error means the engine
// started but could not move traffic, which is a failure the operator must
// still see named with its link.
func outcomeError(link *profile.Link, err error) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("link '%s' started but did not pass the connectivity probe", linkLabel(link))
}

func (f *linkFailure) Error() string {
	var b strings.Builder
	if f.Selected == "" {
		b.WriteString(fmt.Sprintf("no working link found in group '%s'", f.Group))
	} else {
		b.WriteString(fmt.Sprintf("link '%s' failed at %s", f.Selected, f.At.UTC().Format(time.RFC3339)))
		if f.Cause != nil {
			b.WriteString(": ")
			b.WriteString(f.Cause.Error())
		}
	}
	if len(f.Fallbacks) > 0 {
		parts := make([]string, 0, len(f.Fallbacks))
		for _, a := range f.Fallbacks {
			parts = append(parts, fmt.Sprintf("%s → %v", a.Link, a.Err))
		}
		b.WriteString("; fallback links tried: ")
		b.WriteString(strings.Join(parts, "; "))
	}
	return b.String()
}

func (f *linkFailure) Unwrap() error { return f.Cause }

// allLocalConfig reports whether every recorded failure is a local
// configuration error. Waiting cannot fix one of those, so startup stops
// instead of retrying forever.
func (f *linkFailure) allLocalConfig() bool {
	if f.Cause == nil || !errors.Is(f.Cause, engine.ErrLocalConfig) {
		return false
	}
	for _, a := range f.Fallbacks {
		if a.Err == nil || !errors.Is(a.Err, engine.ErrLocalConfig) {
			return false
		}
	}
	return true
}
