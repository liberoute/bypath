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

// speedPreflight reports whether the connection's latest measurement proved
// that HTTPS actually answered through it. Exit ownership is deliberately not
// required: a subscription that shares one exit address is measured normally.
// An open listener or a TCP handshake never qualifies.
func (s *Local) speedPreflight(connectionID string) (bool, string) {
	const needHTTPS = "run the relay and latency test for this connection first; a download needs a proven HTTPS answer"
	if s.layer == nil {
		return false, needHTTPS
	}
	results, err := s.TestResults(context.Background(), connectionID)
	if err != nil || len(results) == 0 {
		return false, needHTTPS
	}
	for i := len(results) - 1; i >= 0; i-- {
		res := results[i]
		if res.Kind == TestKindSpeed {
			continue
		}
		if res.Kind == "" && res.LatencyMS == 0 && res.Status != TestStatusOK && res.Status != TestStatusMeasured {
			// Pre-kind history cannot prove a path.
			continue
		}
		if resultStale(res.TestedAt) {
			return false, "the last HTTPS measurement is stale; run the relay and latency test again"
		}
		if operationalHTTPS(res) {
			return true, ""
		}
		return false, "the last measurement did not prove an HTTPS answer through this connection; run the relay and latency test again"
	}
	return false, needHTTPS
}

// operationalHTTPS reports whether a stored row records a completed HTTPS
// request through the tested connection, regardless of the exit proof.
func operationalHTTPS(res TestResult) bool {
	measured := res.P50MS > 0 || res.LatencyMS > 0
	if res.Kind == TestKindSpeed {
		measured = res.MBps > 0 && res.Bytes > 0
	}
	switch res.Status {
	case TestStatusOK:
		return VerifiedTestResult(res) || (res.HTTPSProven && measured)
	case TestStatusMeasured:
		return res.HTTPSProven && measured
	case TestStatusInconclusive:
		// Rows stored before the operational layer existed carry the same fact
		// in their path proof: the probe answered HTTPS through the instance.
		return res.Path != nil && res.Path.TunneledHTTPS && measured
	}
	return false
}

// speedMinRemainder stops retrying when the budget left for this link is too
// small to produce a rate worth ranking.
const speedMinRemainder = 256 << 10

// speedThrough validates a target on the tested path and downloads it from the
// first address that accepts the connection. Every address is re-checked at
// use, and the connection is pinned to it for the whole transfer. A failed
// attempt hands the next address only the budget that is left, so retries can
// never spend more payload than the link's cap.
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
	var last downloadResult
	var spent int64
	for _, raw := range check.ResolvedIPs {
		ip := net.ParseIP(raw)
		if why := deniedAddress(ip, dynamic); why != "" {
			lastErr = fmt.Errorf("target address is %s", why)
			continue
		}
		remaining := capBytes - spent
		if remaining < speedMinRemainder {
			if lastErr == nil {
				lastErr = errors.New("the transfer budget for this connection is spent")
			}
			break
		}
		client := pinnedClient(port, target.Host, ip)
		res, err := downloadBounded(ctx, client, target.URL, remaining, speedDurationCap)
		client.CloseIdleConnections()
		spent += res.Received
		if err == nil {
			res.Spent = spent
			return res, check, nil
		}
		last = res
		lastErr = err
		if errors.Is(err, errRedirected) {
			break
		}
		if ctx.Err() != nil {
			return downloadResult{Spent: spent, Received: spent}, check, ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no validated address accepted the connection")
	}
	last.Spent = spent
	return last, check, lastErr
}

// chargeSpeedAttempt records the payload a measurement actually transferred,
// including a cancelled or failed attempt. The display keeps a cancelled row's
// numbers at zero, but the month's budget is real traffic and must be charged.
func (s *Local) chargeSpeedAttempt(dres downloadResult) {
	if dres.Spent > 0 {
		s.addCountedBytes(dres.Spent)
	}
}

// countedBytes is the month's counted payload. A batch compares what it
// actually spent against its cap instead of trusting a worst-case estimate.
func (s *Local) countedBytes() int64 {
	if s.layer == nil {
		return 0
	}
	usage, err := s.layer.Usage()
	if err != nil || usage.Month != time.Now().UTC().Format("2006-01") {
		return 0
	}
	return usage.Bytes
}

// speedFailure maps a transfer failure onto the result contract. A target that
// fails stage 0 is Inconclusive, not Failed: the link was never measured. A
// transfer that died mid-body stays Failed and keeps the observed progress in
// its detail; it is never ranked.
func speedFailure(res TestResult, check TargetCheck, err error) TestResult {
	var rejected targetRejectedError
	var transfer *transferError
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
	case errors.As(err, &transfer):
		res.Detail = transfer.describe(check.Host)
		if transfer.phase == "status" {
			// The link answered; the registered target is what refused the run.
			res.Status = TestStatusInconclusive
			res.Reason = ReasonTargetRejected
			break
		}
		res.Status = TestStatusFailed
		if errors.Is(err, context.DeadlineExceeded) {
			res.Category = CategoryUnreachable
		}
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
