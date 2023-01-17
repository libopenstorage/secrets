package api

// Config contains the options needed by the client to connect and authenticate
type Config struct {

	// ClusterURL is the base URL of the DC/OS admin router.
	ClusterURL string

	// Insecure if true, indicates that the client does not verify server's
	// certificate chain. Not recommended as the connection could be susceptible to
	// man-in-the-middle attacks. When false, valid CACertFile should be provided.
	Insecure bool

	// CACertFile is the location of the root certificate authorities that clients
	// use when verifying server certificates. Not needed when Insecure flag is set.
	CACertFile string

	// ACSToken DC/OS authentication token used to authorize the API calls to the
	// admin router. Remember, that the DC/OS token expires after some time (five
	// days by default). So, it is recommended to refrest the token. Use the
	// GenerateACSToken() method to update the token at regular intervals or on
	// failure (401 Unauthorized).
	ACSToken string
}

// NewDefaultConfig has default options in the config, which can be overwritten
func NewDefaultConfig() Config {
	return Config{
		ClusterURL: DefaultClusterURL,
		Insecure:   false,
	}
}
