package app

// WorkerResultFDEnv names the environment entry that tells a host test worker
// which inherited descriptor carries its one result message. The daemon passes
// the write end of a private pipe there, so embedded-engine logging cannot be
// mistaken for the answer.
const WorkerResultFDEnv = "BYPATH_WORKER_RESULT_FD"

// WorkerResultFD is the descriptor the daemon hands the result pipe to.
const WorkerResultFD = 3

// workerResultLimit bounds the single result message a worker may report.
const workerResultLimit = 4 << 20
