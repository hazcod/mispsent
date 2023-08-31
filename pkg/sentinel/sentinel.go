package sentinel

type Credentials struct {
	TenantID       string
	ClientID       string
	ClientSecret   string
	SubscriptionID string
	ResourceGroup  string
	WorkspaceName  string
}

type Sentinel struct {
	creds Credentials
}

func New(creds Credentials) (*Sentinel, error) {
	sentinel := Sentinel{
		creds: creds,
	}

	return &sentinel, nil
}
