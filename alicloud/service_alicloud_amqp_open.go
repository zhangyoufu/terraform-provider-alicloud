package alicloud

import (
	"fmt"
	"time"

	"github.com/PaesslerAG/jsonpath"
	"github.com/aliyun/terraform-provider-alicloud/alicloud/connectivity"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

type AmqpOpenService struct {
	client *connectivity.AliyunClient
}

func (s *AmqpOpenService) DescribeAmqpVirtualHost(id string) (object map[string]interface{}, err error) {
	var response map[string]interface{}
	client := s.client
	action := "ListVirtualHosts"
	parts, err := ParseResourceId(id, 2)
	if err != nil {
		err = WrapError(err)
		return
	}
	request := map[string]interface{}{
		"InstanceId": parts[0],
		"MaxResults": 100,
	}
	idExist := false
	for {
		wait := incrementalWait(3*time.Second, 3*time.Second)
		err = resource.Retry(5*time.Minute, func() *resource.RetryError {
			response, err = client.RpcGet("amqp-open", "2019-12-12", action, request, nil)
			if err != nil {
				if NeedRetry(err) {
					wait()
					return resource.RetryableError(err)
				}
				return resource.NonRetryableError(err)
			}
			return nil
		})
		addDebug(action, response, request)
		if err != nil {
			return object, WrapErrorf(err, DefaultErrorMsg, id, action, AlibabaCloudSdkGoERROR)
		}
		data, _ := response["Data"].(map[string]any)
		virtualHosts, _ := data["VirtualHosts"].([]any)
		if len(virtualHosts) < 1 {
			return object, WrapErrorf(NotFoundErr("Amqp", id), NotFoundWithResponse, response)
		}
		for _, _virtualHost := range virtualHosts {
			virtualHost, _ := _virtualHost.(map[string]any)
			if virtualHost["Name"].(string) == parts[1] {
				idExist = true
				return virtualHost, nil
			}
		}

		if nextToken, _ := data["NextToken"].(string); nextToken != "" {
			request["NextToken"] = nextToken
		} else {
			break
		}
	}
	if !idExist {
		return object, WrapErrorf(NotFoundErr("Amqp", id), NotFoundWithResponse, response)
	}
	return
}

func (s *AmqpOpenService) DescribeAmqpQueue(id string) (object map[string]interface{}, err error) {
	var response map[string]interface{}
	client := s.client
	action := "ListQueues"
	parts, err := ParseResourceId(id, 3)
	if err != nil {
		err = WrapError(err)
		return
	}
	request := map[string]interface{}{
		"InstanceId":  parts[0],
		"VirtualHost": parts[1],
		"MaxResults":  100,
	}
	idExist := false
	for {
		wait := incrementalWait(3*time.Second, 3*time.Second)
		err = resource.Retry(5*time.Minute, func() *resource.RetryError {
			response, err = client.RpcGet("amqp-open", "2019-12-12", action, request, nil)
			if err != nil {
				if NeedRetry(err) {
					wait()
					return resource.RetryableError(err)
				}
				return resource.NonRetryableError(err)
			}
			return nil
		})
		addDebug(action, response, request)
		if err != nil {
			return object, WrapErrorf(err, DefaultErrorMsg, id, action, AlibabaCloudSdkGoERROR)
		}
		data, _ := response["Data"].(map[string]any)
		queues, _ := data["Queues"].([]any)
		if len(queues) < 1 {
			return object, WrapErrorf(NotFoundErr("Amqp", id), NotFoundWithResponse, response)
		}
		for _, _queue := range queues {
			queue, _ := _queue.(map[string]any)
			if queue["Name"].(string) == parts[2] {
				idExist = true
				return queue, nil
			}
		}

		if nextToken, _ := data["NextToken"].(string); nextToken != "" {
			request["NextToken"] = nextToken
		} else {
			break
		}
	}
	if !idExist {
		return object, WrapErrorf(NotFoundErr("Amqp", id), NotFoundWithResponse, response)
	}
	return
}

func (s *AmqpOpenService) DescribeAmqpExchange(id string) (object map[string]interface{}, err error) {
	var response map[string]interface{}
	client := s.client
	action := "ListExchanges"
	parts, err := ParseResourceId(id, 3)
	if err != nil {
		err = WrapError(err)
		return
	}
	request := map[string]interface{}{
		"InstanceId":  parts[0],
		"VirtualHost": parts[1],
		"MaxResults":  100,
	}
	idExist := false
	for {
		wait := incrementalWait(3*time.Second, 3*time.Second)
		err = resource.Retry(5*time.Minute, func() *resource.RetryError {
			response, err = client.RpcGet("amqp-open", "2019-12-12", action, request, nil)
			if err != nil {
				if NeedRetry(err) {
					wait()
					return resource.RetryableError(err)
				}
				return resource.NonRetryableError(err)
			}
			return nil
		})
		addDebug(action, response, request)
		if err != nil {
			if IsExpectedErrors(err, []string{"107"}) {
				return nil, WrapErrorf(err, NotFoundMsg, AlibabaCloudSdkGoERROR)
			}
			return object, WrapErrorf(err, DefaultErrorMsg, id, action, AlibabaCloudSdkGoERROR)
		}
		data, _ := response["Data"].(map[string]any)
		exchanges, _ := data["Exchanges"].([]any)
		if len(exchanges) < 1 {
			return object, WrapErrorf(NotFoundErr("Amqp", id), NotFoundWithResponse, response)
		}
		for _, _exchange := range exchanges {
			exchange, _ := _exchange.(map[string]any)
			if exchange["Name"].(string) == parts[2] {
				idExist = true
				return exchange, nil
			}
		}

		if nextToken, _ := data["NextToken"].(string); nextToken != "" {
			request["NextToken"] = nextToken
		} else {
			break
		}
	}
	if !idExist {
		return object, WrapErrorf(NotFoundErr("Amqp", id), NotFoundWithResponse, response)
	}
	return
}

func (s *AmqpOpenService) DescribeAmqpInstance(id string) (object map[string]interface{}, err error) {
	var response map[string]interface{}
	client := s.client
	action := "ListInstances"
	request := map[string]interface{}{
		"MaxResults": 100,
	}
	idExist := false
	for {
		wait := incrementalWait(3*time.Second, 3*time.Second)
		err = resource.Retry(5*time.Minute, func() *resource.RetryError {
			response, err = client.RpcGet("amqp-open", "2019-12-12", action, request, nil)
			if err != nil {
				if NeedRetry(err) {
					wait()
					return resource.RetryableError(err)
				}
				return resource.NonRetryableError(err)
			}
			return nil
		})
		addDebug(action, response, request)
		if err != nil {
			return object, WrapErrorf(err, DefaultErrorMsg, id, action, AlibabaCloudSdkGoERROR)
		}
		data, _ := response["Data"].(map[string]any)
		instances, _ := data["Instances"].([]any)
		if len(instances) < 1 {
			return object, WrapErrorf(NotFoundErr("Amqp", id), NotFoundWithResponse, response)
		}
		for _, _instance := range instances {
			instance, _ := _instance.(map[string]any)
			if instance["InstanceId"].(string) == id {
				idExist = true
				return instance, nil
			}
		}

		if nextToken, _ := data["NextToken"].(string); nextToken != "" {
			request["NextToken"] = nextToken
		} else {
			break
		}
	}
	if !idExist {
		return object, WrapErrorf(NotFoundErr("Amqp", id), NotFoundWithResponse, response)
	}
	return
}

func (s *AmqpOpenService) AmqpInstanceStateRefreshFunc(id string, failStates []string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		object, err := s.DescribeAmqpInstance(id)
		if err != nil {
			if NotFoundError(err) {
				// Set this to nil as if we didn't find anything.
				return nil, "", nil
			}
			return nil, "", WrapError(err)
		}

		for _, failState := range failStates {
			if fmt.Sprint(object["Status"]) == failState {
				return object, fmt.Sprint(object["Status"]), WrapError(Error(FailedToReachTargetStatus, fmt.Sprint(object["Status"])))
			}
		}
		return object, fmt.Sprint(object["Status"]), nil
	}
}
func (s *AmqpOpenService) DescribeAmqpBinding(id string) (object map[string]interface{}, err error) {
	var response map[string]interface{}
	action := "ListBindings"

	client := s.client

	parts, err := ParseResourceId(id, 4)
	if err != nil {
		return nil, WrapError(err)
	}

	request := map[string]interface{}{
		"InstanceId":  parts[0],
		"VirtualHost": parts[1],
		"MaxResults":  PageSizeLarge,
	}

	idExist := false
	for {
		wait := incrementalWait(3*time.Second, 3*time.Second)
		err = resource.Retry(5*time.Minute, func() *resource.RetryError {
			response, err = client.RpcGet("amqp-open", "2019-12-12", action, request, nil)
			if err != nil {
				if NeedRetry(err) {
					wait()
					return resource.RetryableError(err)
				}
				return resource.NonRetryableError(err)
			}
			return nil
		})
		addDebug(action, response, request)

		if err != nil {
			if IsExpectedErrors(err, []string{"ExchangeNotExist"}) {
				return nil, WrapErrorf(err, NotFoundMsg, AlibabaCloudSdkGoERROR)
			}
			return object, WrapErrorf(err, DefaultErrorMsg, id, action, AlibabaCloudSdkGoERROR)
		}

		data, _ := response["Data"].(map[string]any)
		bindings, _ := data["Bindings"].([]any)
		if len(bindings) < 1 {
			return object, WrapErrorf(NotFoundErr("Amqp:Binding", id), NotFoundWithResponse, response)
		}
		for _, _binding := range bindings {
			binding, _ := _binding.(map[string]any)
			if binding["SourceExchange"].(string) == parts[2] && binding["DestinationName"].(string) == parts[3] {
				idExist = true
				return binding, nil
			}
		}

		if nextToken, _ := data["NextToken"].(string); nextToken != "" {
			request["NextToken"] = nextToken
		} else {
			break
		}
	}

	if !idExist {
		return object, WrapErrorf(NotFoundErr("Amqp:Binding", id), NotFoundWithResponse, response)
	}

	return
}

func (s *AmqpOpenService) DescribeAmqpStaticAccount(id string) (object map[string]interface{}, err error) {
	client := s.client
	parts, err := ParseResourceId(id, 2)
	if err != nil {
		return object, WrapError(err)
	}

	request := map[string]interface{}{}
	request["InstanceId"] = parts[0]

	var response map[string]interface{}
	action := "ListAccounts"
	wait := incrementalWait(3*time.Second, 3*time.Second)
	err = resource.Retry(5*time.Minute, func() *resource.RetryError {
		resp, err := client.RpcPost("amqp-open", "2019-12-12", action, nil, request, true)
		if err != nil {
			if NeedRetry(err) {
				wait()
				return resource.RetryableError(err)
			}
			return resource.NonRetryableError(err)
		}
		response = resp
		addDebug(action, response, request)
		return nil
	})
	if err != nil {
		return object, WrapErrorf(err, DefaultErrorMsg, id, action, AlibabaCloudSdkGoERROR)
	}
	v, err := jsonpath.Get("$.Data", response)
	if err != nil {
		return object, WrapErrorf(err, FailedGetAttributeMsg, id, "$.Data", response)
	}
	data := v.(map[string]interface{})
	val, ok := data[parts[0]]
	if ok {
		allData := val.([]interface{})
		for _, i := range allData {
			detail := i.(map[string]interface{})
			if parts[1] == detail["accessKey"] {
				return detail, nil
			}
		}
		err = WrapErrorf(NotFoundErr("Amqp", id), NotFoundMsg, ProviderERROR)
		return object, err
	} else {
		err = WrapErrorf(NotFoundErr("Amqp", id), NotFoundMsg, ProviderERROR)
		return object, err
	}
}

func (s *AmqpOpenService) AmqpStaticAccountStateRefreshFunc(d *schema.ResourceData, failStates []string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		object, err := s.DescribeAmqpStaticAccount(d.Id())
		if err != nil {
			if NotFoundError(err) {
				return nil, "", nil
			}
			return nil, "", WrapError(err)
		}
		for _, failState := range failStates {
			if fmt.Sprint(object[""]) == failState {
				return object, fmt.Sprint(object[""]), WrapError(Error(FailedToReachTargetStatus, fmt.Sprint(object[""])))
			}
		}
		return object, fmt.Sprint(object[""]), nil
	}
}
