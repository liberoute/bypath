package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// speedDurationCap bounds one transfer in time as well as in bytes, so a slow
// server cannot hold the serial throughput queue for the whole byte cap.
const speedDurationCap = 15 * time.Second

// targetRejectedError carries the plain-language stage-0 rejection.
type targetRejectedError struct{ reason string }

func (e targetRejectedError) Error() string { return e.reason }

// provenRelay reports whether the connection's latest latency result is a
// proven, non-stale relay result. A speed number without one would describe an
// unproven path.
func (s *Local) provenRelay(connectionID string) (bool, string) {
	if s.layer == nil {
		return false, "run a latency test for this connection first; a speed result needs a proven path"
	}
	results, err := s.TestResults(context.Background(), connectionID)
	if err != nil || len(results) == 0 {
		return false, "run a latency test for this connection first; a speed result needs a proven path"
	}
	for i := len(results) - 1; i >= 0; i-- {
		res := results[i]
		if res.Kind == TestKindSpeed {
			continue
		}
		if res.Kind == "" && res.LatencyMS == 0 && res.Status != TestStatusOK {
			// Pre-kind history cannot prove a path.
			continue
		}
		if VerifiedTestResult(res) {
			return true, ""
		}
		if res.Status == TestStatusOK {
			return false, "the last proof is stale, superseded, or not bound to this configuration; test again first"
		}
		return false, "the last latency test did not prove the path; a speed result would be meaningless"
	}
	return false, "run a latency test for this connection first; a speed result needs a proven path"
}

// speedThrough validates a target on the tested path and downloads it from the
// first address that accepts the connection. Every address is re-checked at
// use, and the connection is pinned to it for the whole transfer.
func (s *Local) speedThrough(ctx context.Context, port int, live bool, target SpeedTarget, capBytes int64) (downloadResult, TargetCheck, error) {
	if capBytes <= 0 {
		capBytes = 10 << 20
	}
	check := s.checkTargetThroughPath(ctx, port, target, live)
	if !check.OK {
		return downloadResult{}, check, targetRejectedError{reason: check.Reason}
	}
	dynamic := localDeniedNets()
	var lastErr error
	var spent int64
	for _, raw := range check.ResolvedIPs {
		ip := net.ParseIP(raw)
		if why := deniedAddress(ip, dynamic); why != "" {
			lastErr = fmt.Errorf("target address is %s", why)
			continue
		}
		client := pinnedClient(port, target.Host, ip)
		res, err := downloadBounded(ctx, client, target.URL, capBytes, speedDurationCap)
		client.CloseIdleConnections()
		spent += res.Bytes
		if err == nil {
			res.Spent = spent
			return res, check, nil
		}
		lastErr = err
		if errors.Is(err, errRedirected) {
			break
		}
		if ctx.Err() != nil {
			return downloadResult{Spent: spent}, check, ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no validated address accepted the connection")
	}
	return downloadResult{Spent: spent}, check, lastErr
}

// chargeSpeedAttempt records the payload a measurement actually transferred,
// including a cancelled or failed attempt. The display keeps a cancelled row's
// numbers at zero, but the month's budget is real traffic and must be charged.
func (s *Local) chargeSpeedAttempt(dres downloadResult) {
	if dres.Spent > 0 {
		s.addCountedBytes(dres.Spent)
	}
}

// speedFailure maps a transfer failure onto the result contract. A target that
// fails stage 0 is Inconclusive, not Failed: the link was never measured.
func speedFailure(res TestResult, check TargetCheck, err error) TestResult {
	var rejected targetRejectedError
	switch {
	case errors.As(err, &rejected):
		res.Status = TestStatusInconclusive
		res.Reason = ReasonTargetRejected
		res.Detail = rejected.reason
	case errors.Is(err, errRedirected):
		res.Status = TestStatusInconclusive
		res.Reason = ReasonTargetRejected
		res.Detail = errRedirected.Error()
	case errors.Is(err, context.Canceled):
		res.Status = TestStatusCancelled
		res.Detail = "the transfer was cancelled by user"
	case errors.Is(err, context.DeadlineExceeded):
		res.Status, res.Category = TestStatusFailed, CategoryUnreachable
		res.Detail = "the transfer timed out"
	default:
		res.Status = TestStatusFailed
		res.Detail = Redact(err.Error())
	}
	if check.Host != "" && res.Target == "" {
		res.Target = check.Host
	}
	res.Bytes = 0
	res.MBps = 0
	res.Seconds = 0
	return res
}

// zeroMeasurement removes numbers that must not be ranked after the proof
// failed.
func zeroMeasurement(res *TestResult) {
	res.LatencyMS, res.P50MS, res.P90MS = 0, 0, 0
	res.MBps, res.Bytes, res.Seconds = 0, 0, 0
}
