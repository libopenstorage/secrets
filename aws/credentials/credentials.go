package credentials

import (
	"context"
	"log"
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
}

type awsCred struct {
	creds *aws.Credentials
}

func NewAWSCredentials(id, secret, token string, runningOnEc2 bool) (AWSCredentials, error) {
	var creds aws.Credentials
	if id != "" && secret != "" {
		provider := credentials.NewStaticCredentialsProvider(id, secret, token)
		var err error
		if creds, err = provider.Retrieve(context.TODO()); err != nil {
			return nil, err
		}
	} else {
		defaultCfg, err := config.LoadDefaultConfig(context.TODO())
		if err != nil {
			return nil, err
		}
		if runningOnEc2 {
			defaultCfg.HTTPClient = http.NewBuildableClient().WithTimeout(10 * time.Second)

			defaultProvider := config.WithCredentialsProvider(defaultCfg.Credentials)
			ec2provider := config.WithCredentialsProvider(ec2rolecreds.New(func(o *ec2rolecreds.Options) {
				o.Client = imds.NewFromConfig(defaultCfg)
			}))

			cfg, err := config.LoadDefaultConfig(context.TODO(),
				defaultProvider,
				ec2provider,
			)
			if err != nil {
				log.Fatal(err)
			}

			creds, err = cfg.Credentials.Retrieve(context.Background())
			if err != nil {
				return nil, err
			}
		}
	}
	return &awsCred{&creds}, nil
}

func (a *awsCred) Get() (*aws.Credentials, error) {
	return a.creds, nil
}
