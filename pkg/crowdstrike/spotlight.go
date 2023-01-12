package crowdstrike

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/spotlight_vulnerabilities"
	"github.com/hazcod/crowdstrike2sentinel/pkg/vuln"
	"github.com/sirupsen/logrus"
	"time"
)

const (
	falconMaxRows = 5000
)

type SpotlightFinding struct {
	Created time.Time
	Closed  time.Time
	Host    struct {
		Hostname string
		HostID   string
	}
	Vulnerability struct {
		CVE           string
		ExpertAI      string
		Severity      string
		ExploitStatus string
		Score         float32
		Description   string
	}
}

func getFalconURL(l *logrus.Entry, cloud string, cveID string) string {
	if cloud == "" || cveID == "" {
		l.WithField("cloud", cloud).WithField("cve_id", cveID).Error("generating empty falcon url")
		return ""
	}

	return fmt.Sprintf("https://falcon.%s.crowdstrike.com/spotlight-v2/vulnerabilities/group-by/cve/%s", cloud, cveID)
}

func RetrieveSpotlight(ctx context.Context, l *logrus.Logger, accessKey, secretKey, region string) ([]vuln.Vulnerability, error) {
	findings := make([]vuln.Vulnerability, 0)

	logger := l.WithField("module", "crowdstrike")

	cs, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     accessKey,
		ClientSecret: secretKey,
		Context:      ctx,
		Cloud:        falcon.Cloud(region),
	})
	if err != nil {
		return nil, fmt.Errorf("could not connect to CrowdStrike:P %v", err)
	}

	paginationToken := ""
	for {
		logger.WithField("pagination", paginationToken).Info("retrieving spotlight vulnerabilities")

		result, err := cs.SpotlightVulnerabilities.CombinedQueryVulnerabilities(
			&spotlight_vulnerabilities.CombinedQueryVulnerabilitiesParams{
				After:   &paginationToken,
				Facet:   []string{"cve", "host_info", "remediation"},
				Filter:  "status:'open'",
				Context: ctx,
				Limit:   to.Ptr[int64](falconMaxRows),
			},
		)

		if err != nil {
			return nil, fmt.Errorf("could not retrieve Spotlight vulnerabilities: %v", err)
		}

		for _, vulnerability := range result.GetPayload().Resources {

			if l.IsLevelEnabled(logrus.TraceLevel) {
				b, _ := json.Marshal(&vulnerability)
				logger.Tracef("%s", b)
			}

			tsCreated, err := time.Parse(time.RFC3339, *vulnerability.CreatedTimestamp)
			if err != nil {
				logger.WithField("created_timestamp", vulnerability.CreatedTimestamp).Error("failed to parse")
			}

			var tsClosed time.Time
			if vulnerability.ClosedTimestamp != "" {
				tsClosed, err = time.Parse(time.RFC3339, vulnerability.ClosedTimestamp)
				if err != nil {
					logger.WithField("closed_timestamp", vulnerability.ClosedTimestamp).Error("failed to parse")
				}
			}

			appName := ""
			if nil != vulnerability.App && nil != vulnerability.App.ProductNameVersion {
				appName = *vulnerability.App.ProductNameVersion
			} else {
				if len(vulnerability.Apps) == 0 || nil == vulnerability.Apps[0].ProductNameVersion {
					logger.WithField("cve_id", *vulnerability.Cve.ID).Warn("no apps assigned")
				} else {
					appName = *vulnerability.Apps[0].ProductNameVersion
				}
			}

			findings = append(findings, vuln.Vulnerability{
				Title:       vulnerability.Cve.Name,
				Description: vulnerability.Cve.Description,
				CVE: vuln.CVE{
					ID:             *vulnerability.Cve.ID,
					Score:          float32(vulnerability.Cve.BaseScore),
					Vector:         vulnerability.Cve.Vector,
					Exploitability: float32(vulnerability.Cve.ExploitabilityScore),
				},
				SourceLink: getFalconURL(logger, region, *vulnerability.Cve.ID),
				References: vulnerability.Cve.References,
				Created:    tsCreated,
				Closed:     tsClosed,
				Product: vuln.Product{
					Name: appName,
					Type: vuln.ProductTypeApplication,
					ID:   *vulnerability.Aid,
				},
				Host: vuln.Host{
					Name: *vulnerability.HostInfo.Hostname,
					ID:   vulnerability.HostInfo.InstanceID,
					Type: vulnerability.HostInfo.ProductTypeDesc,
					OS:   vulnerability.HostInfo.Platform,
				},
				Source: vuln.Source{
					Name: "Crowdstrike",
					Type: vuln.SourceTypeSensor,
				},
			})
		}

		// stop pagination if we reached the end
		paginationToken = *result.GetPayload().Meta.Pagination.After

		logger.WithField("total", *result.GetPayload().Meta.Pagination.Total).
			WithField("limit", *result.GetPayload().Meta.Pagination.Limit).
			WithField("fetched", len(findings)).
			Debug("paginating")

		if paginationToken == "" {
			logger.Debug("stopping pagination")
			break
		}
	}

	logger.WithField("num", len(findings)).Debug("retrieved spotlight findings")

	return findings, nil
}
