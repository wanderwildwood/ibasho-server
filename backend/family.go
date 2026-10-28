package backend

import (
	"encoding/json"
	"errors"
	"fmd-server/user"
	"net/http"

	"github.com/rs/zerolog/log"
)

// Family sharing endpoints. See user/family.go for the model.

const maxFamilyItems = 64

type identityBody struct {
	PublicKey  string `json:"publicKey64"`
	EncPrivate string `json:"encPrivateKey64"`
}

func getIdentity2(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r)
	pub, enc, err := uio.Identity(u)
	if err != nil {
		http.Error(w, "failed to read identity", http.StatusInternalServerError)
		return
	}
	if pub == "" {
		http.Error(w, "no identity yet", http.StatusNotFound)
		return
	}
	writeAsJson(w, identityBody{pub, enc})
}

// The first identity wins. A second device that raced and lost gets the winner back with 409,
// and adopts it.
func postIdentity2(w http.ResponseWriter, r *http.Request) {
	var body identityBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, ERR_JSON_INVALID, http.StatusBadRequest)
		return
	}
	u := userFromContext(r)
	err := uio.SetIdentity(u, body.PublicKey, body.EncPrivate)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusOK)
	case errors.Is(err, user.ErrIdentityInvalid):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, user.ErrIdentityTaken):
		pub, enc, ierr := uio.Identity(u)
		if ierr != nil {
			http.Error(w, "failed to read identity", http.StatusInternalServerError)
			return
		}
		w.Header().Set(HEADER_CONTENT_TYPE, CT_APPLICATION_JSON)
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(identityBody{pub, enc})
	default:
		log.Error().Err(err).Str("user", u.Username).Msg("failed to set identity")
		http.Error(w, "failed to set identity", http.StatusInternalServerError)
	}
}

type familyResponse struct {
	Me     familyMe      `json:"me"`
	People []user.Person `json:"people"`
}

type familyMe struct {
	Username string `json:"username"`
	Paused   bool   `json:"paused"`
}

// Everyone registered here, with the key to seal to. Everyone sees everyone.
func getFamily2(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r)
	people, err := uio.People(u)
	if err != nil {
		log.Error().Err(err).Msg("failed to list people")
		http.Error(w, "failed to list people", http.StatusInternalServerError)
		return
	}
	paused, err := uio.IsPaused(u)
	if err != nil {
		http.Error(w, "failed to read state", http.StatusInternalServerError)
		return
	}
	writeAsJson(w, familyResponse{Me: familyMe{u.Username, paused}, People: people})
}

type pauseBody struct {
	Paused bool `json:"paused"`
}

func postFamilyPause2(w http.ResponseWriter, r *http.Request) {
	var body pauseBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, ERR_JSON_INVALID, http.StatusBadRequest)
		return
	}
	u := userFromContext(r)
	if err := uio.SetPaused(u, body.Paused); err != nil {
		log.Error().Err(err).Str("user", u.Username).Msg("failed to set pause")
		http.Error(w, "failed to set pause", http.StatusInternalServerError)
		return
	}
	writeAsJson(w, pauseBody{body.Paused})
}

type sealedPutRequest struct {
	Items []user.SealedPut `json:"items"`
}

type sealedGetResponse struct {
	Items []user.SealedGet `json:"items"`
}

func postFamilyLocations2(w http.ResponseWriter, r *http.Request) {
	var body sealedPutRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, ERR_JSON_INVALID, http.StatusBadRequest)
		return
	}
	if len(body.Items) > maxFamilyItems {
		http.Error(w, "too many items", http.StatusBadRequest)
		return
	}
	u := userFromContext(r)
	stored, err := uio.PutSealed(u, body.Items)
	switch {
	case err == nil:
		writeAsJson(w, map[string]int{"stored": stored})
	case errors.Is(err, user.ErrPaused):
		http.Error(w, "sharing is paused", http.StatusConflict)
	case errors.Is(err, user.ErrNoIdentity):
		http.Error(w, "set an identity first", http.StatusPreconditionFailed)
	default:
		log.Error().Err(err).Str("user", u.Username).Msg("failed to store sealed locations")
		http.Error(w, "failed to store", http.StatusInternalServerError)
	}
}

func getFamilyLocations2(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r)
	items, err := uio.SealedFor(u)
	if err != nil {
		log.Error().Err(err).Str("user", u.Username).Msg("failed to read sealed locations")
		http.Error(w, "failed to read", http.StatusInternalServerError)
		return
	}
	if items == nil {
		items = []user.SealedGet{}
	}
	writeAsJson(w, sealedGetResponse{items})
}
