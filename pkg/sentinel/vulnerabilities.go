package sentinel

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	insights "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights/v2"
	"github.com/hazcod/crowdstrike2sentinel/pkg/vuln"
	"github.com/sirupsen/logrus"
	"time"
)

func CreateTable(ctx context.Context, l *logrus.Logger, retentionDays uint32, creds Credentials) error {
	logger := l.WithField("module", "sentinel_vuln")

	cred, err := azidentity.NewClientSecretCredential(creds.TenantID, creds.ClientID, creds.ClientSecret, nil)
	if err != nil {
		return fmt.Errorf("could not authenticate to MS Sentinel: %v", err)
	}

	logger.WithField("table_name", vuln.TableNameVulnerabilities).Info("creating table")

	tablesClient, err := insights.NewTablesClient(creds.SubscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("could not create ms graph table client: %v", err)
	}

	retention := int32(retentionDays)

	poller, err := tablesClient.BeginCreateOrUpdate(ctx,
		creds.ResourceGroup, creds.WorkspaceName, vuln.TableNameVulnerabilities,
		insights.Table{
			Properties: &insights.TableProperties{
				RetentionInDays:      &retention,
				TotalRetentionInDays: to.Ptr[int32](retention * 2),
				Schema: &insights.Schema{
					Columns: []*insights.Column{
						{
							Description: to.Ptr[string]("The timestamp of when the vulnerability was registered."),
							Name:        to.Ptr[string]("Name"),
							Type:        to.Ptr[insights.ColumnTypeEnum](insights.ColumnTypeEnumString),
						},
						{
							Description: to.Ptr[string]("The vulnerability name."),
							Name:        to.Ptr[string]("TimeGenerated"),
							Type:        to.Ptr[insights.ColumnTypeEnum](insights.ColumnTypeEnumDateTime),
						},
					},
					Name:        to.Ptr[string](vuln.TableNameVulnerabilities),
					Description: to.Ptr[string]("Table that contains historic data about security vulnerabilities."),
				},
			},
		}, nil)
	if err != nil {
		return fmt.Errorf("could not create table '%s': %v", vuln.TableNameVulnerabilities, err)
	}

	_, err = poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: time.Second * 3})
	if err != nil {
		return fmt.Errorf("could not poll table creation: %v", err)
	}

	logger.WithField("table_name", vuln.TableNameVulnerabilities).Info("created table")

	return nil
}
