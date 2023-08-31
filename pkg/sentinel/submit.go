package sentinel

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	insights "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/securityinsights/armsecurityinsights/v2"
	"github.com/hazcod/crowdstrike2sentinel/pkg/misp"
	"github.com/sirupsen/logrus"
	"strconv"
	"strings"
	"time"
)

const (
	threatTypeFile    = "file"
	threatTypeNetwork = "network-traffic"
	threatTypeURL     = "url"
	threatTypeEmail   = "email-addr"
	threatTypeDomain  = "domain-name"
)

func getThreatType(patternType string) string {
	patternType = strings.ToLower(patternType)

	switch patternType {
	case "ip-dst":
		return threatTypeNetwork
	case "vhash":
		return threatTypeFile
	case "filename":
		return threatTypeFile
	case "sha256":
		return threatTypeFile
	case "attachment":
		return threatTypeEmail
	default:
		return "Other"
	}
}

// TODO: migrate to the new uploadIndicators (beta) API
// https://github.com/Azure/azure-sdk-for-go/issues/20907

func (s *Sentinel) SubmitThreatIntel(ctx context.Context, l *logrus.Logger, expireMonths uint16, mispHostname string, attributes []misp.Attribute) error {
	logger := l.WithField("module", "sentinel_ti")

	cred, err := azidentity.NewClientSecretCredential(s.creds.TenantID, s.creds.ClientID, s.creds.ClientSecret, nil)
	if err != nil {
		return fmt.Errorf("could not authenticate to MS Sentinel: %v", err)
	}

	tiClient, err := insights.NewThreatIntelligenceIndicatorClient(s.creds.SubscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("could not create TI client: %v", err)
	}

	today := time.Now()
	defaultExpiration := time.Now().AddDate(0, int(expireMonths), 0)

	numCreated := 0

	for i, attribute := range attributes {
		attrLogger := logger.WithField("attr_id", attribute.ID)

		attrLogger.WithField("num", i).WithField("value", attribute.Value).
			Debug("pushing TI indicator")

		expirationDate, err := time.Parse("2006-01-02T15:04:05.999999999Z07:00", attribute.LastSeen.(string))
		if err != nil {
			expirationDate = defaultExpiration
			attrLogger.WithError(err).WithField("raw", attribute.LastSeen.(string)).Error("could not parse attribute last_seen")
		} else {
			expirationDate = expirationDate.AddDate(0, int(expireMonths), 0)
		}

		tsUnix, err := strconv.ParseInt(attribute.Timestamp, 10, 64)
		if err != nil {
			attrLogger.WithError(err).WithField("ts", attribute.Timestamp).
				Error("could not parse attribute timestamp")
			tsUnix = today.Unix()
		}

		timestamp := time.Unix(tsUnix, 0)

		attrLogger = attrLogger.WithField("expires", expirationDate.Format("2006-01-02"))

		if expirationDate.Before(today) {
			attrLogger.WithField("last_seen", attribute.LastSeen.(string)).
				WithField("last_seen_raw", attribute.LastSeen.(string)).
				Debug("skipping expired MISP attribute")
			continue
		}

		attributeName := attribute.Category + ": " + attribute.Value
		attrLogger = attrLogger.WithField("name", attributeName)

		if _, err := tiClient.Get(ctx, s.creds.ResourceGroup, s.creds.WorkspaceName, attributeName, nil); err != nil {
			attrLogger.Info("skipping pre-existing attribute")
			continue
		}

		threatType := getThreatType(attribute.Type)
		if attrLogger.Logger.IsLevelEnabled(logrus.DebugLevel) && strings.EqualFold(threatType, "Other") {
			attrLogger.WithField("type", attribute.Type).Debug("got attribute type Other")
		}

		if _, err = tiClient.CreateIndicator(ctx, s.creds.ResourceGroup, s.creds.WorkspaceName, insights.ThreatIntelligenceIndicatorModel{
			Kind: nil,
			Properties: &insights.ThreatIntelligenceIndicatorProperties{
				Confidence:                 nil,
				Created:                    to.Ptr[string](timestamp.Format(time.RFC3339)),
				CreatedByRef:               to.Ptr[string](mispHostname),
				Defanged:                   nil,
				Description:                to.Ptr[string](attribute.Comment),
				DisplayName:                to.Ptr[string](attributeName),
				Extensions:                 nil,
				ExternalID:                 to.Ptr[string](attribute.ID),
				ExternalLastUpdatedTimeUTC: nil,
				ExternalReferences:         nil,
				GranularMarkings:           nil,
				IndicatorTypes: []*string{
					to.Ptr[string](attribute.Type),
				},
				KillChainPhases: nil,
				Labels: []*string{
					to.Ptr[string]("info:" + attribute.Event.Info),
					to.Ptr[string]("category:" + attribute.Category),
					to.Ptr[string]("type:" + attribute.Type),
				},
				Language:               nil,
				LastUpdatedTimeUTC:     to.Ptr[string](timestamp.Format(time.RFC3339)),
				Modified:               to.Ptr[string](timestamp.Format(time.RFC3339)),
				ObjectMarkingRefs:      nil,
				ParsedPattern:          nil,
				Pattern:                to.Ptr[string](attribute.Value),
				PatternType:            to.Ptr[string](attribute.Type),
				PatternVersion:         nil,
				Revoked:                to.Ptr[bool](attribute.Deleted),
				Source:                 to.Ptr[string](mispHostname),
				ThreatIntelligenceTags: nil,
				ThreatTypes:            []*string{to.Ptr(threatType)},
				ValidFrom:              to.Ptr[string](timestamp.Format(time.RFC3339)),
				ValidUntil:             to.Ptr[string](expirationDate.Format(time.RFC3339)),
			},
		}, nil); err != nil {
			attrLogger.WithError(err).Error("could not create attribute")
			return fmt.Errorf("could not create attribute %s: %v", attribute.ID, err)
		}

		numCreated += 1

		attrLogger.WithField("expires", expirationDate.Format("2006-01-02")).
			Info("created attribute in Sentinel")
	}

	if numCreated > 0 {
		logger.WithField("num", numCreated).Info("successfully pushed TI attributes into Sentinel")
	}

	return nil
}
