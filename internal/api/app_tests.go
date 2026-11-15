package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/liberoute/bypath/internal/app"
)

func (s *Server) appStartTestJob(w http.ResponseWriter, r *http.Request) {
	var req app.TestRequest
	if !decodeBody(w, r, &req, 1<<16) {
		return
	}
	job, err := s.svc.StartTestJob(r.Context(), req)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusAccepted, job)
}

func (s *Server) appGetTestJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.svc.GetTestJob(r.Context(), mux.Vars(r)["id"])
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, job)
}

func (s *Server) appCancelTestJob(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.CancelTestJob(r.Context(), mux.Vars(r)["id"]); err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

func (s *Server) appTestResults(w http.ResponseWriter, r *http.Request) {
	connection := r.URL.Query().Get("connection")
	results, err := s.svc.TestResults(r.Context(), connection)
	if err != nil {
		appError(w, err)
		return
	}
	if results == nil {
		results = []app.TestResult{}
	}
	jsonResponse(w, http.StatusOK, results)
}

// appTestJobEvents streams progress as server-sent events. The polling
// endpoint remains authoritative: a client that reconnects passes ?after=<seq>
// and receives every event it missed, so a dropped stream never loses a result.
func (s *Server) appTestJobEvents(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	after, _ := strconv.Atoi(r.URL.Query().Get("after"))
	backlog, ch, stop, err := s.svc.SubscribeTestEvents(id, after)
	if err != nil {
		appError(w, err)
		return
	}
	defer stop()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	write := func(ev app.TestEvent) {
		data, err := json.Marshal(ev)
		if err != nil {
			return
		}
		fmt.Fprintf(w, "id: %d\nevent: test\ndata: %s\n\n", ev.Seq, data)
		flusher.Flush()
	}
	for _, ev := range backlog {
		write(ev)
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			write(ev)
		}
	}
}

func (s *Server) appSpeedTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := s.svc.SpeedTargets(r.Context())
	if err != nil {
		appError(w, err)
		return
	}
	if targets == nil {
		targets = []app.SpeedTarget{}
	}
	jsonResponse(w, http.StatusOK, targets)
}

func (s *Server) appAddSpeedTarget(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	if !decodeBody(w, r, &body, 1<<12) {
		return
	}
	target, err := s.svc.AddSpeedTarget(r.Context(), body.URL)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusCreated, target)
}

func (s *Server) appDeleteSpeedTarget(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.DeleteSpeedTarget(r.Context(), mux.Vars(r)["id"]); err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) appValidateSpeedTarget(w http.ResponseWriter, r *http.Request) {
	target, err := s.svc.ValidateSpeedTarget(r.Context(), mux.Vars(r)["id"])
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, target)
}

func (s *Server) appTestBudget(w http.ResponseWriter, r *http.Request) {
	var req app.TestRequest
	if !decodeBody(w, r, &req, 1<<12) {
		return
	}
	budget, err := s.svc.TestBudget(r.Context(), req)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, budget)
}

func (s *Server) appTestUsage(w http.ResponseWriter, r *http.Request) {
	usage, err := s.svc.UsageInfo(r.Context())
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, usage)
}
