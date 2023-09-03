package credentials

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

type AWSCredentials interface {
	Get() (*aws.Credentials, error)
	GetCredentialsProvider() (aws.CredentialsProvider, error)
}

type awsCred struct {
	creds         *aws.Credentials
	credsprovider aws.CredentialsProvider
}

func NewAWSCredentials(id, secret, token string, runningOnEc2 bool) (AWSCredentials, error) {
	var creds aws.Credentials
	var credsprovider aws.CredentialsProvider
	var ctx context.Context
	if id != "" && secret != "" {
		cfg, err := config.LoadDefaultConfig(ctx, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(id, secret, token)))
		if err != nil {
			return nil, err
		}

		creds, err = cfg.Credentials.Retrieve(context.Background())
		if err != nil {
			return nil, err
		}

	} else if runningOnEc2 {

		ec2Provider := ec2rolecreds.New(func(o *ec2rolecreds.Options) {
			o.Client = imds.New(imds.Options{
				HTTPClient: http.NewBuildableClient().WithTimeout(10 * time.Second),
			})
		})

		cfg, err := config.LoadDefaultConfig(context.TODO(),
			config.WithCredentialsProvider(ec2Provider),
		)
		if err != nil {
			return nil, err
		}

		creds, err = cfg.Credentials.Retrieve(context.Background())
		if err != nil {
			return nil, err
		}
	}
	return &awsCred{&creds, credsprovider}, nil
}

func (a *awsCred) Get() (*aws.Credentials, error) {
	if a.creds.Expired() {
		// Refresh the credentials
		if _, err := a.credsprovider.Retrieve(context.TODO()); err != nil {
			return nil, err
		}
	}
	return a.creds, nil
}

func (a *awsCred) GetCredentialsProvider() (aws.CredentialsProvider, error) {
	return a.credsprovider, nil
}
