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
	"time"
)

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

	for _, attribute := range attributes {
		attrLogger := logger.WithField("attr_id", attribute.ID)

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
			attrLogger.WithField("last_seen", attribute.LastSeen.(string)).Debug("skipping expired MISP attribute")
			continue
		}

		attributeName := attribute.Category + ": " + attribute.Value
		attrLogger = attrLogger.WithField("name", attributeName)

		if _, err := tiClient.Get(ctx, s.creds.ResourceGroup, s.creds.WorkspaceName, attributeName, nil); err != nil {
			attrLogger.Info("skipping pre-existing attribute")
			continue
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
				Source:                 to.Ptr[string]("misp.cert.be"),
				ThreatIntelligenceTags: nil,
				ThreatTypes:            nil,
				ValidFrom:              to.Ptr[string](timestamp.Format(time.RFC3339)),
				ValidUntil:             to.Ptr[string](expirationDate.Format(time.RFC3339)),
				AdditionalData:         nil,
				FriendlyName:           nil,
			},
		}, nil); err != nil {
			attrLogger.WithError(err).Error("could not create attribute")
			return fmt.Errorf("could not create attribute %s: %v", attribute.ID, err)
		}

		attrLogger.WithField("expires", expirationDate.Format("2006-01-02")).
			Info("created attribute in Sentinel")
	}

	return nil
}
