// Copyright 2023 New Vector Ltd

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/matrix-org/gomatrix"
	"github.com/matrix-org/gomatrixserverlib/fclient"
	"github.com/matrix-org/gomatrixserverlib/spec"
)

type Handler struct {
	secret, bbbHost string
}

type OpenIDTokenType struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	MatrixServerName string `json:"matrix_server_name"`
}

type SFURequest struct {
	RoomName    string          `json:"room_name"`
	RoomId      string          `json:"room_id"`
	OpenIDToken OpenIDTokenType `json:"openid_token"`
	DeviceID    string          `json:"device_id"`
	DisplayName string          `json:"display_name"`
}

type SFUResponse struct {
	URL string `json:"url"`
}

type Response struct {
	XMLName    xml.Name `xml:"response"`
	ReturnCode string   `xml:"returncode"`
	Message    string   `xml:"message"` // Adding field for the response message
	MessageKey string   `xml:"messageKey"`
}

func exchangeOIDCToken(
	ctx context.Context, token OpenIDTokenType,
) (*fclient.UserInfo, error) {
	if token.AccessToken == "" || token.MatrixServerName == "" {
		return nil, errors.New("Missing parameters in OIDC token")
	}

	client := fclient.NewClient(fclient.WithWellKnownSRVLookups(true))
	// validate the openid token by getting the user's ID
	userinfo, err := client.LookupUserInfo(
		ctx, spec.ServerName(token.MatrixServerName), token.AccessToken,
	)
	if err != nil {
		log.Printf("Failed to look up user info: %v", err)
		return nil, errors.New("Failed to look up user info")
	}
	return &userinfo, nil
}

func (h *Handler) handle(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request from %s", r.RemoteAddr)

	// Set the CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token")

	// Handle preflight request (CORS)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	} else if r.Method == "POST" {
		var body SFURequest
		err := json.NewDecoder(r.Body).Decode(&body)
		if err != nil {
			log.Printf("Error decoding JSON: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			err = json.NewEncoder(w).Encode(gomatrix.RespError{
				ErrCode: "M_NOT_JSON",
				Err:     "Error decoding JSON",
			})
			if err != nil {
				log.Printf("failed to encode json error message! %v", err)
			}
			return
		}

		if body.RoomId == "" {
			log.Printf("Request missing room")
			w.WriteHeader(http.StatusBadRequest)
			err = json.NewEncoder(w).Encode(gomatrix.RespError{
				ErrCode: "M_BAD_JSON",
				Err:     "Missing parameters",
			})
			if err != nil {
				log.Printf("failed to encode json error message! %v", err)
			}
			return
		}

		userInfo, err := exchangeOIDCToken(r.Context(), body.OpenIDToken)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			err = json.NewEncoder(w).Encode(gomatrix.RespError{
				ErrCode: "M_LOOKUP_FAILED",
				Err:     "Failed to look up user info from homeserver",
			})
			if err != nil {
				log.Printf("failed to encode json error message! %v", err)
			}
			return
		}

		log.Printf("Got user info for %s", userInfo.Sub)

		moderatorPW := hashPassword(h.secret, body.RoomId, "moderatorPW")
		attendeePW := hashPassword(h.secret, body.RoomId, "attendeePW")

		defaultParams := map[string]string{
			"name":        body.RoomName,
			"meetingID":   body.RoomId,
			"moderatorPW": moderatorPW,
			"attendeePW":  attendeePW,
		}

		url, err := getBBBJoinUrl(h.bbbHost, h.secret, userInfo.Sub+body.DeviceID, body.DisplayName, defaultParams)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			err = json.NewEncoder(w).Encode(gomatrix.RespError{
				ErrCode: "M_UNKNOWN",
				Err:     "Internal Server Error",
			})
			if err != nil {
				log.Printf("failed to encode json error message! %v", err)
			}
			return
		}

		res := SFUResponse{URL: url}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(res)
		if err != nil {
			log.Printf("failed to encode json response! %v", err)
		}
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func main() {

	bbbSecret := os.Getenv("BBB_SECRET")
	bbbHost := os.Getenv("BBB_HOST")

	// Check if the secret or url are empty.
	if bbbSecret == "" || bbbHost == "" {
		log.Fatal("BBB_SECRET and BBB_URL environment variables must be set")
	}

	log.Printf("BBB_HOST %s", bbbHost)

	handler := &Handler{
		secret:  bbbSecret,
		bbbHost: bbbHost,
	}

	http.HandleFunc("/get_join_url", handler.handle)
	http.HandleFunc("/healthz", handler.healthcheck)

	log.Fatal(http.ListenAndServe(":8083", nil))
}

// BBB specific logic to generate a valid join url the BBB widget can redirect to.
func getBBBJoinUrl(bbbHost string, bbbSecret string, userId string, userName string, defaultParams map[string]string) (string, error) {
	// this will only be called once the openId token is verified and we know we are dealing with a valid matrix user.

	createURL := bbbAPI(bbbHost, bbbSecret, "create", defaultParams)

	resp, err := http.Get(createURL)
	if err != nil {
		fmt.Printf("Failed to create meeting: %v\n", err)
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Failed to read response: %v\n", err)
		return "", err
	}

	var doc Response
	if err := xml.Unmarshal(body, &doc); err != nil {
		fmt.Printf("Failed to parse XML: %v\n", err)
		return "", err
	}

	if doc.ReturnCode == "SUCCESS" {
		fmt.Println("Meeting created.")

		joinParams := map[string]string{
			"fullName":  userName,
			"userID":    userId,
			"meetingID": defaultParams["meetingID"],
			"role":      "MODERATOR",
		}

		joinURL := bbbAPI(bbbHost, bbbSecret, "join", joinParams)
		fmt.Println()
		fmt.Println("To join as moderator to meetingID '" + defaultParams["meetingID"] + "', open the following URL in your browser:")
		fmt.Println()
		fmt.Println(joinURL)
		fmt.Println()
		fmt.Println("For more details see https://docs.bigbluebutton.org/development/api/")
		return joinURL, nil
	} else {
		fmt.Printf("Failed to create meeting: %s (%s)\n", doc.Message, doc.MessageKey)
		fmt.Println("Full server response:")
		fmt.Println(string(body))
		return "", errors.New("failed to create meeting")
	}
}

func bbbAPI(host, secret, cmd string, params map[string]string) string {
	parameters := ""
	for key, value := range params {
		parameters += fmt.Sprintf("%s=%s&", key, url.QueryEscape(value))
	}

	checksumStr := cmd + parameters[:len(parameters)-1] + secret // Remove the last '&' before hashing
	checksum := fmt.Sprintf("%x", sha1.Sum([]byte(checksumStr)))

	return fmt.Sprintf("https://%s/bigbluebutton/api/%s?%schecksum=%s", host, cmd, parameters, checksum)
}

// Helper functions
func (h *Handler) healthcheck(w http.ResponseWriter, r *http.Request) {
	log.Printf("Health check from %s", r.RemoteAddr)
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == "GET" {
		w.WriteHeader(http.StatusOK)
		return
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func hashPassword(secret, meetingID, role string) string {
	hash := sha1.Sum([]byte(secret + meetingID + role))
	return fmt.Sprintf("%x", hash)[:8] // Get first 8 characters of the hash
}
