package misp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

const (
	mispMaxAttributesPerFetch = 100
)

type Attribute struct {
	ID                 string      `json:"id"`
	EventID            string      `json:"event_id"`
	ObjectID           string      `json:"object_id"`
	ObjectRelation     interface{} `json:"object_relation"`
	Category           string      `json:"category"`
	Type               string      `json:"type"`
	ToIds              bool        `json:"to_ids"`
	UUID               string      `json:"uuid"`
	Timestamp          string      `json:"timestamp"`
	Distribution       string      `json:"distribution"`
	SharingGroupID     string      `json:"sharing_group_id"`
	Comment            string      `json:"comment"`
	Deleted            bool        `json:"deleted"`
	DisableCorrelation bool        `json:"disable_correlation"`
	FirstSeen          interface{} `json:"first_seen"`
	LastSeen           interface{} `json:"last_seen"`
	Value              string      `json:"value"`
	Event              struct {
		OrgID        string `json:"org_id"`
		Distribution string `json:"distribution"`
		ID           string `json:"id"`
		Info         string `json:"info"`
		OrgcID       string `json:"orgc_id"`
		UUID         string `json:"uuid"`
	} `json:"Event"`
}

type Response struct {
	Response struct {
		Attribute []Attribute `json:"Attribute"`
	} `json:"response"`
}

func (m *MISP) FetchIndicators(daysToFetch uint32, typesToFetch []string) ([]Attribute, error) {
	indicators := make([]Attribute, 0)

	if daysToFetch == 0 {
		return nil, errors.New("cannot fetch 0 days")
	}

	httpClient := http.Client{Timeout: time.Minute * 5}

	url := strings.TrimSuffix(m.baseURL, "/") + "/attributes/restSearch"
	fromTime := time.Now().AddDate(0, 0, -1*int(daysToFetch))
	fromTimeStr := fromTime.Format("2006-01-02")

	page := int32(0)
	limit := mispMaxAttributesPerFetch
	submitted := 0

	for {
		body := struct {
			Format string `json:"returnFormat"`
			From   string `json:"last_seen"`

			SkipFalsePositives bool `json:"enforceWarninglist"`
			ExcludeDecayed     bool `json:"excludeDecayed"`
			Published          bool `json:"published"`
			Deleted            bool `json:"deleted"`

			Page  int32 `json:"page"`
			Limit int32 `json:"limit"`
		}{
			Format: "json",
			From:   fromTimeStr,

			SkipFalsePositives: true,
			ExcludeDecayed:     true,
			Published:          true,
			Deleted:            false,

			Page:  page,
			Limit: int32(limit),
		}

		bodyBytes, err := json.Marshal(&body)
		if err != nil {
			return nil, fmt.Errorf("could not encode body: %v", err)
		}

		httpRequest, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, fmt.Errorf("could not create http request: %v", err)
		}

		httpRequest.Header.Set("accept", "application/json")
		httpRequest.Header.Set("content-type", "application/json")
		httpRequest.Header.Set("authorization", m.accessKey)

		if m.logger.IsLevelEnabled(logrus.TraceLevel) {
			reqBytes, err := httputil.DumpRequest(httpRequest, true)
			if err != nil {
				m.logger.WithError(err).Warn("could not dump http request")
			}

			m.logger.Trace(string(reqBytes))
		}

		m.logger.WithField("page", page).WithField("limit", limit).
			WithField("fetched", len(indicators)).
			WithField("from", fromTimeStr).
			Debug("fetching MISP indicators")

		resp, err := httpClient.Do(httpRequest)
		if err != nil {
			return nil, fmt.Errorf("could not request: %v", err)
		}

		if resp.StatusCode > 399 {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("invalid response code: %d", resp.StatusCode)
		}

		m.logger.Debug("got misp response")

		respBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("could not read response: %v", err)
		}

		_ = resp.Body.Close()

		var response Response
		if err := json.Unmarshal(respBytes, &response); err != nil {
			return nil, fmt.Errorf("could not decode response: %v", err)
		}

		if len(response.Response.Attribute) > mispMaxAttributesPerFetch {
			m.logger.WithField("size", len(response.Response.Attribute)).
				Warn("MISP returned more results than expected")
		}

		// break the for/while loop if necessary
		if len(response.Response.Attribute) == 0 {
			m.logger.WithField("attributes", len(indicators)).
				Debug("received all MISP attributes, breaking")
			break
		}

		for _, attribute := range response.Response.Attribute {

			attLogger := m.logger.WithField("attribute", attribute.ID).WithField("type", attribute.Type)

			allowedType := false
			for _, t := range typesToFetch {
				if strings.EqualFold(t, attribute.Type) {
					allowedType = true
					break
				}
			}

			if !allowedType {
				attLogger.Debug("skipping attribute because of type")
				continue
			}

			if m.logger.IsLevelEnabled(logrus.TraceLevel) {
				b, _ := json.Marshal(&attribute)
				m.logger.Trace(string(b))
			}

			attLogger.WithField("i", submitted).
				WithField("value", attribute.Value).
				Debug("adding MISP attribute")

			indicators = append(indicators, attribute)

			submitted += 1
		}

		page += 1
	}

	m.logger.WithField("fetched", len(indicators)).WithField("submitted", submitted).
		Debug("fetched MISP indicators")

	return indicators, nil
}
