package api

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/4yi-ai/codescan/internal/source"
)

type updateAllowedHostsRequest struct {
	Hosts string `json:"hosts"`
}

func (s *Server) handleUpdateAllowedHosts(w http.ResponseWriter, r *http.Request) {
	var req updateAllowedHostsRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	hosts, err := source.ParseAllowedHostsCSV(req.Hosts)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	raw, err := s.store.GetSetting(r.Context(), extraAllowedHostsSetting)
	if err != nil {
		writeErr(w, 500, "could not read allowed hosts")
		return
	}
	if expected := r.Header.Get("If-Match"); expected != "" && expected != hostsRevision(raw) {
		writeErr(w, http.StatusPreconditionFailed, "allowed hosts changed; reload before saving")
		return
	}
	saved, err := s.store.CompareAndSwapSetting(r.Context(), extraAllowedHostsSetting, raw, strings.Join(hosts, ","))
	if err != nil {
		writeErr(w, 500, "could not save allowed hosts")
		return
	}
	if !saved {
		writeErr(w, http.StatusPreconditionFailed, "allowed hosts changed; reload before saving")
		return
	}

	allowedHosts := source.MergeAllowedHosts(s.guards.AllowedHosts, hosts)
	writeJSON(w, http.StatusOK, map[string]any{
		"allowed_hosts":       allowedHosts,
		"extra_allowed_hosts": hosts,
		"base_allowed_hosts":  s.guards.AllowedHosts,
		"revision":            hostsRevision(strings.Join(hosts, ",")),
	})
}

func hostsRevision(raw string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(raw))) }

func (s *Server) handleGetAllowedHosts(w http.ResponseWriter, r *http.Request) {
	raw, err := s.store.GetSetting(r.Context(), extraAllowedHostsSetting)
	if err != nil {
		writeErr(w, 500, "could not read allowed hosts")
		return
	}
	hosts, err := source.ParseAllowedHostsCSV(raw)
	if err != nil {
		writeErr(w, 500, "invalid stored allowed hosts")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"allowed_hosts":       source.MergeAllowedHosts(s.guards.AllowedHosts, hosts),
		"extra_allowed_hosts": hosts, "base_allowed_hosts": s.guards.AllowedHosts, "revision": hostsRevision(raw),
	})
}
