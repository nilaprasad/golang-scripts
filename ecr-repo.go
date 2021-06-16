package main

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
)

func VulnerabilityFindings() {
	sess, sessErr := session.NewSession(&aws.Config{
		Region:      aws.String("ca-central-1"),
		Credentials: credentials.NewSharedCredentials("", "dev-credentials"),
	})
	if sessErr != nil {
		fmt.Printf("failed to create a session: %v", sessErr)
		return
	}

	svc := ecr.New(sess)
	params := &ecr.DescribeImageScanFindingsInput{
		ImageId: &ecr.ImageIdentifier{
			ImageTag: aws.String("Tag"), // Image tag name
		},
		RegistryId:     aws.String("RegistryName"), // Registry Name
		RepositoryName: aws.String("RepoName"),     // Repository Name
	}

	res, respErr := svc.DescribeImageScanFindings(params)
	if respErr != nil {
		fmt.Println(respErr.Error())
		return
	}

	fmt.Println(res)
}

func main() {

	fmt.Printf("Finding Vulnerability Reports.\n")
	VulnerabilityFindings()
}
