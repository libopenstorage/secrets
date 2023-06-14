package credentials

import (
	"context"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/config"
)

type AWSCredentials interface {
	Get() (*credentials.Credentials, error)
}

type awsCred struct {
	creds *credentials.Credentials
}

func NewAWSCredentials(id, secret, token string, runningOnEc2 bool) (AWSCredentials, error) {
	var creds *credentials.Credentials
	if id != "" && secret != "" {
		creds = credentials.NewStaticCredentialsProvider(id, secret, token)
		if _, err := creds.Retrieve(context.TODO()); err != nil {
			return nil, err
		}
	} else {
		cfg, err := external.LoadDefaultAWSConfig()
		if err != nil {
			return nil, err
		}
		providers := []credentials.Provider{
			&credentials.EnvProvider{},
		}
		if runningOnEc2 {
			cfg.HTTPClient = &http.Client{Timeout: time.Second * 10}
			ec2RoleProvider := &ec2rolecreds.EC2RoleProvider{
				Client: ec2metadata.New(cfg),
			}
			providers = append(providers, ec2RoleProvider)
		}
		providers = append(providers, &credentials.SharedCredentialsProvider{
			Filename: aws.StringValue(cfg.Credentials.SharedConfigFilename),
			Profile:  aws.StringValue(cfg.Credentials.Profile),
		})
		creds = credentials.NewChainCredentials(providers)
		if _, err := creds.Retrieve(context.TODO()); err != nil {
			return nil, err
		}
	}
	return &awsCred{creds}, nil
}

func (a *awsCred) Get() (*credentials.Credentials, error) {
	if a.creds.HasExpired() {
		// Refresh the credentials
		if _, err := a.creds.Retrieve(context.TODO()); err != nil {
			return nil, err
		}
	}
	return a.creds, nil
}