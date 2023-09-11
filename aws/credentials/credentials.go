package credentials

import (
	"fmt"
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

func NewAWSCredentials(id, secret, token string, runningOnEc2 bool) (AWSCredentials, error) {
	var creds *credentials.Credentials
	sess, err := session.NewSession()
	if err != nil {
		return nil, fmt.Errorf("error crewating new aws credentials: %w", err)
	}
	if id != "" && secret != "" {
		creds = credentials.NewStaticCredentials(id, secret, token)
		if _, err := creds.Get(); err != nil {
			return nil, err
		}
	} else if sess.Config.Credentials != nil {
		// sess config loads credential automatically from environment variable
		// this is used to prioritize loading aws web identity token whenever it's specified.
		creds = sess.Config.Credentials
	} else {
		providers := []credentials.Provider{
			&credentials.EnvProvider{},
		}
		if runningOnEc2 {
			client := http.Client{Timeout: time.Second * 10}
			ec2RoleProvider := &ec2rolecreds.EC2RoleProvider{
				Client: ec2metadata.New(sess, &aws.Config{
					HTTPClient: &client,
				}),
			}
			providers = append(providers, ec2RoleProvider)
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
