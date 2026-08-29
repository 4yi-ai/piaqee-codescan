package api

import (
	"encoding/json"
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
	if err := s.store.PutSetting(r.Context(), extraAllowedHostsSetting, strings.Join(hosts, ",")); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not save allowed hosts")
		return
	}

	allowedHosts := source.MergeAllowedHosts(s.guards.AllowedHosts, hosts)
	writeJSON(w, http.StatusOK, map[string]any{
		"allowed_hosts":       allowedHosts,
		"extra_allowed_hosts": hosts,
	})
}
