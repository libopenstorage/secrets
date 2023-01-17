package utils

import (
	"errors"
	"fmt"
)

const (
	// AwsAccessKey corresponds to AWS credential AWS_ACCESS_KEY_ID
	AwsAccessKey = "AWS_ACCESS_KEY_ID"
	// AwsSecretAccessKey corresponds to AWS credential AWS_SECRET_ACCESS_KEY
	AwsSecretAccessKey = "AWS_SECRET_ACCESS_KEY"
	// AwsTokenKey corresponds to AWS credential AWS_SECRET_TOKEN_KEY
	AwsTokenKey = "AWS_SECRET_TOKEN_KEY"
	// AwsRegionKey defines the AWS region
	AwsRegionKey = "AWS_REGION"
)

var (
	// ErrCMKNotProvided is returned when CMK is not provided.
	ErrCMKNotProvided = errors.New("AWS CMK not provided. Cannot perform secret operations.")
	// ErrAWSRegionNotProvided is returned when region is not provided.
	ErrAWSRegionNotProvided = errors.New("AWS Region not provided. Cannot perform secret operations.")
	// ErrInvalidKvdbProvided is returned when an incorrect KVDB implementation is provided for persistence store.
	ErrInvalidKvdbProvided = errors.New("Invalid kvdb provided. AWS KMS works in conjuction with a kvdb")
	// ErrAWSCredsNotProvided is returned when aws credentials are not provided
	ErrAWSCredsNotProvided = errors.New("aws credentials not provided")
)

func AuthKeys(params map[string]interface{}) (string, string, string, error) {
	accessKey, err := getAuthKey(AwsAccessKey, params)
	if err != nil {
		return "", "", "", err
	}

	secretKey, err := getAuthKey(AwsSecretAccessKey, params)
	if err != nil {
		return "", "", "", err
	}

	secretToken, err := getAuthKey(AwsTokenKey, params)
	if err != nil {
		return "", "", "", err
	}

	return accessKey, secretKey, secretToken, nil
}

func getAuthKey(key string, params map[string]interface{}) (string, error) {
	val, ok := params[key]
	valueStr := ""
	if ok {
		valueStr, ok = val.(string)
		if !ok {
			return "", fmt.Errorf("Authentication error. Invalid value for %v", key)
		}
	}
	return valueStr, nil
}
