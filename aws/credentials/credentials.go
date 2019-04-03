package credentials

import (
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
)

type AWSCredentials interface {
	Get() (*credentials.Credentials, error)
}

type awsCred struct {
	creds *credentials.Credentials
}

func NewAWSCredentials(id, secret, token string) (AWSCredentials, error) {
	var creds *credentials.Credentials
	if id != "" && secret != "" {
		creds = credentials.NewStaticCredentials(id, secret, token)
		if _, err := creds.Get(); err != nil {
			return nil, err
		}
	} else {
		providers := []credentials.Provider{
			&credentials.EnvProvider{},
		}
		// Check if we are running on EC2 instance
		client := http.Client{Timeout: time.Second * 10}
		url := "http://169.254.169.254/latest/meta-data/"
		res, err := client.Get(url)
		if err == nil {
			sess := session.Must(session.NewSession())
			ec2RoleProvider := &ec2rolecreds.EC2RoleProvider{
				Client: ec2metadata.New(sess, &aws.Config{
					HTTPClient: &client,
				}),
			}
			providers = append(providers, ec2RoleProvider)
			res.Body.Close()
		}
		providers = append(providers, &credentials.SharedCredentialsProvider{})
		creds = credentials.NewChainCredentials(providers)
		if _, err := creds.Get(); err != nil {
			return nil, err
		}
	}
	return &awsCred{creds}, nil
}

func (a *awsCred) Get() (*credentials.Credentials, error) {
	if a.creds.IsExpired() {
		// Refresh the credentials
		_, err := a.creds.Get()
		if err != nil {
			return nil, err
		}
	}
	return a.creds, nil
}
