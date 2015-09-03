package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	//"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/service/ec2"
	"golang.org/x/crypto/ssh"
	"fmt"
	"errors"
	"io/ioutil"
	//"time"
)

type CloudState struct {
	Service *ec2.EC2
}

func Login(filename, user, region string) (*CloudState, error) {
	ec2_cfg := &aws.Config {
		Credentials: credentials.NewSharedCredentials(filename, user),
		Region: aws.String(region),
		LogLevel: aws.LogLevel(aws.LogDebug),
	}
	svc := ec2.New(ec2_cfg)

	return &CloudState{Service: svc}, nil
}

func RegionList() ([]string, error) {
	ec2_cfg := &aws.Config {
		Region: aws.String("us-west-1"),
		LogLevel: aws.LogLevel(aws.LogDebug),
	}
	svc := ec2.New(ec2_cfg)

	params := &ec2.DescribeRegionsInput{}
	resp, err := svc.DescribeRegions(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		return nil, err
	}

	var v []string
	for _, r := range resp.Regions {
		v = append(v, *r.RegionName)
	}

	return v, nil
}

func CurrentSpotPrices(st *CloudState, instType string) (error) {
	params := &ec2.DescribeSpotPriceHistoryInput{
		InstanceTypes: []*string{
			aws.String(instType),
			// More values...
		},


		Filters: []*ec2.Filter{
			{ // Required
				Name: aws.String("product-description"),
				Values: []*string{
					aws.String("Linux/UNIX"),
				},
			},
		},

		//Region: aws.String("us-east-1"),
		//MaxResults: aws.Int64(1000),
	}
	resp, err := st.Service.DescribeSpotPriceHistory(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		return err
	}

	// Pretty-print the response data.
	fmt.Println(resp)
	return nil
}

func RequestSpot(svc *ec2.EC2, amiId, instType, keyName, userData, jobId string, maxCph int) (string, error) {
	params := &ec2.RequestSpotInstancesInput{
		SpotPrice:           aws.String(fmt.Sprintf("%f", maxCph / 100.0)),
		//InstanceCount:       aws.Int64(1),
		//ValidFrom:           aws.Time(time.Now()),
		//ValidUntil:          aws.Time(time.Now()),
		LaunchSpecification: &ec2.RequestSpotLaunchSpecification{
			BlockDeviceMappings: []*ec2.BlockDeviceMapping{
				{ // Required
					//DeviceName: aws.String("String"),
					Ebs: &ec2.EbsBlockDevice{
						//DeleteOnTermination: aws.Bool(true),
						//VolumeType:          aws.String("VolumeType"),
					},
					//NoDevice:    aws.String("String"),
					//VirtualName: aws.String("String"),
				},
				// More values...
			},
			//EbsOptimized: aws.Bool(true),
			ImageId:      aws.String(amiId),
			InstanceType: aws.String(instType),
			KeyName:      aws.String(keyName),
			UserData:     aws.String(userData),
		},
	}
	resp, err := svc.RequestSpotInstances(params)

	if err != nil {
		return "", err
	}

	for _,v := range(resp.SpotInstanceRequests) {

		fmt.Println("Created SpotInstanceRequest ", v.SpotInstanceRequestId)

		_, err := svc.CreateTags(&ec2.CreateTagsInput{
			Resources: []*string{aws.String(*v.SpotInstanceRequestId)},
			Tags: []*ec2.Tag{
				{ Key: aws.String("Magnum-Job"), Value: aws.String(jobId), },
			},
		})

		if err != nil {
			fmt.Println("Error tagging new spot request", err)
			return "", err
		}
	}

	if len(resp.SpotInstanceRequests) != 1 {
		fmt.Println("Unexpected response", resp)
		return "", errors.New("Bad response to SpotInstanceRequest")
	}

	return *resp.SpotInstanceRequests[0].SpotInstanceRequestId, nil
}

func CreateKeyPair(st *CloudState, name string) (string, error) {
	resp, err := st.Service.CreateKeyPair(&ec2.CreateKeyPairInput{KeyName: aws.String(name),})

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		return "", err
	}

	// Pretty-print the response data.
	fmt.Println(resp)

	return *resp.KeyMaterial, nil
}

func CancelSpotRequest(st *CloudState, id string) (error) {
	params := &ec2.CancelSpotInstanceRequestsInput{
		SpotInstanceRequestIds: []*string{
			aws.String(id),
		},
	}

	resp, err := st.Service.CancelSpotInstanceRequests(params)
	fmt.Printf("%s", resp)

	return err
}

func CurrentSpotRequests(st* CloudState) error {
	resp, err := st.Service.DescribeSpotInstanceRequests(nil)

	for _,r := range(resp.SpotInstanceRequests) {
		fmt.Println(r)
	}
	fmt.Println(resp)
	return err
}

func findTag(tags []*ec2.Tag, tagName string) string {
	for _,tag := range(tags) {
		if tag.Key != nil && tag.Value != nil {
			if(*tag.Key == tagName) {
				return *tag.Value
			}
		}
	}

	return ""
}

func CurrentMagnumInstances(st* CloudState) {
	//resp, err := st.Service.DescribeSpotInstanceRequests(nil)

	params := &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("tag-key"),
				Values: []*string{
					aws.String("Magnum-Job"),
				},
			},
		},
		//MaxResults: aws.Int64(1000),
	}
	resp, err := st.Service.DescribeInstances(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
	}

	m := make(map[string]string)

	for _,reserv := range(resp.Reservations) {
		for _,inst := range(reserv.Instances) {
			fmt.Println(inst)

			if (inst.SpotInstanceRequestId == nil || inst.PublicIpAddress == nil) {
				fmt.Printf("Instance was not spot or does not have a public IP")
				continue
			}
			if inst.SpotInstanceRequestId != nil {
				fmt.Printf("ID %s\n", *inst.SpotInstanceRequestId)
			}
			if inst.PublicIpAddress != nil {
				fmt.Printf("IP %s\n", *inst.PublicIpAddress)
			}
			job := findTag(inst.Tags, "Magnum-Job")
			ip := *inst.PublicIpAddress
			fmt.Printf("IP %s job %s", job, ip)
			m[job] = ip

		}
	}
	fmt.Println(m)
}

func GetRegions(svc *ec2.EC2) ([]string, error) {
	resp, err := svc.DescribeRegions(nil)
	if err != nil {
		return nil, err
	}

	var v []string
	for _, r := range resp.Regions {
		v = append(v, *r.RegionName)
	}

	return v, nil
}

func TerminateInstances(svc *ec2.EC2, jobId string, instances []*string) {
	params := &ec2.TerminateInstancesInput{InstanceIds : instances,}

	resp, err := svc.TerminateInstances(params)
	if err != nil {
		fmt.Printf("Failed to cancel spot instance reqs", err)
		return
	}

	for _,ti := range(resp.TerminatingInstances) {
		fmt.Printf("Instance %s", ti.InstanceId)
		fmt.Printf("Current status %s", ti.CurrentState.String())
		fmt.Printf("Prev status %s", ti.PreviousState.String())
	}
}

func CancelSpotRequests(svc *ec2.EC2, jobId string, instances []*string) {
	params := &ec2.CancelSpotInstanceRequestsInput{SpotInstanceRequestIds: instances,}

	resp, err := svc.CancelSpotInstanceRequests(params)
	if err != nil {
		fmt.Printf("Failed to cancel spot instance reqs", err)
		return
	}

	for _,req := range(resp.CancelledSpotInstanceRequests) {
		fmt.Printf("Cancelled spot request %s: %s", req.SpotInstanceRequestId, req.State)
	}
}

func CloudMain() {
	defRegion := "us-east-1"

	st, err := Login("", "", defRegion)

	if err != nil {
		fmt.Printf("%s", err)
		return
	}

	/*
	regions, err := GetRegions(st.Ec2)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s", regions)
*/

	//CancelSpotRequest(st, "sir-021m66c9")

	/*
	regions, err := RegionList()
	fmt.Printf("%s\n", regions)

	CurrentSpotPrices(st, "c3.8xlarge")
*/

	//CurrentSpotRequests(st)
	CurrentMagnumInstances(st)
	return

	keyId := "testkey2"
	keyPriv, err := CreateKeyPair(st, keyId)
	if err != nil {
		fmt.Println(err)
	}
	ioutil.WriteFile("id_" + keyId + ".pem", []byte(keyPriv), 0600)

	fmt.Printf("%s\n", keyPriv)

	//userData := "something useful here...\n"
	//amiId := "ami-e3106686"
	//RequestSpot(st, amiId, "m3.medium", keyId, userData, "jobId", 1, .002)

	signer, err := ssh.ParsePrivateKey([]byte(keyPriv))

	if err != nil {
		fmt.Printf("Failure parsing private key")
		return
	}

	sshConfig := &ssh.ClientConfig{
		User: "ec2-user",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer),},
	}

	host := "1.2.3.4"
	client, err := ssh.Dial("tcp", host, sshConfig)
	if err != nil {
	}

	session, err := client.NewSession()
	if err != nil {
		client.Close()
	}

	output, err := session.CombinedOutput("wget https://%s/static/bootstrap.sh; sudo sh bootstrap.sh")
	fmt.Println(output)
}
