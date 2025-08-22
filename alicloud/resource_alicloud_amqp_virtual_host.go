package alicloud

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aliyun/terraform-provider-alicloud/alicloud/connectivity"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func resourceAlicloudAmqpVirtualHost() *schema.Resource {
	return &schema.Resource{
		Create: resourceAlicloudAmqpVirtualHostCreate,
		Read:   resourceAlicloudAmqpVirtualHostRead,
		Update: resourceAlicloudAmqpVirtualHostUpdate,
		Delete: resourceAlicloudAmqpVirtualHostDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"instance_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"virtual_host_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"force_delete": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
		},
	}
}

func resourceAlicloudAmqpVirtualHostCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*connectivity.AliyunClient)
	var response map[string]interface{}
	action := "CreateVirtualHost"
	request := make(map[string]interface{})
	var err error
	request["InstanceId"] = d.Get("instance_id")
	request["VirtualHost"] = d.Get("virtual_host_name")
	wait := incrementalWait(3*time.Second, 3*time.Second)
	err = resource.Retry(d.Timeout(schema.TimeoutCreate), func() *resource.RetryError {
		response, err = client.RpcPost("amqp-open", "2019-12-12", action, nil, request, false)
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
		return WrapErrorf(err, DefaultErrorMsg, "alicloud_amqp_virtual_host", action, AlibabaCloudSdkGoERROR)
	}

	d.SetId(fmt.Sprint(request["InstanceId"], ":", request["VirtualHost"]))

	return resourceAlicloudAmqpVirtualHostRead(d, meta)
}
func resourceAlicloudAmqpVirtualHostRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*connectivity.AliyunClient)
	amqpOpenService := AmqpOpenService{client}
	_, err := amqpOpenService.DescribeAmqpVirtualHost(d.Id())
	if err != nil {
		if NotFoundError(err) {
			log.Printf("[DEBUG] Resource alicloud_amqp_virtual_host amqpOpenService.DescribeAmqpVirtualHost Failed!!! %s", err)
			d.SetId("")
			return nil
		}
		return WrapError(err)
	}
	parts, err := ParseResourceId(d.Id(), 2)
	if err != nil {
		return WrapError(err)
	}
	d.Set("instance_id", parts[0])
	d.Set("virtual_host_name", parts[1])
	return nil
}

func resourceAlicloudAmqpVirtualHostUpdate(d *schema.ResourceData, meta interface{}) error {
	// The only attribute that can be updated is force_delete
	// Since this is only used during deletion and doesn't require an API call to update,
	// we just need to return nil here
	return nil
}

func resourceAlicloudAmqpVirtualHostDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*connectivity.AliyunClient)
	parts, err := ParseResourceId(d.Id(), 2)
	if err != nil {
		return WrapError(err)
	}
	action := "DeleteVirtualHost"
	var response map[string]interface{}
	request := map[string]interface{}{
		"InstanceId":  parts[0],
		"VirtualHost": parts[1],
	}

	wait := incrementalWait(3*time.Second, 3*time.Second)
	err = resource.Retry(d.Timeout(schema.TimeoutDelete), func() *resource.RetryError {
		if d.Get("force_delete").(bool) {
			// First, list and delete all exchanges
			exchangeAction := "ListExchanges"
			exchangeRequest := map[string]interface{}{
				"InstanceId":  parts[0],
				"VirtualHost": parts[1],
				"MaxResults":  100,
			}

			// Loop to handle pagination for exchanges
			for {
				exchangeResponse, err := client.RpcGet("amqp-open", "2019-12-12", exchangeAction, exchangeRequest, nil)
				if err != nil {
					if NeedRetry(err) {
						wait()
						return resource.RetryableError(err)
					}
					return resource.NonRetryableError(err)
				}

				data, ok := exchangeResponse["Data"].(map[string]interface{})
				if !ok {
					break
				}

				exchanges, ok := data["Exchanges"].([]interface{})
				if !ok || len(exchanges) == 0 {
					break
				}

				// Delete each exchange
				for _, item := range exchanges {
					exchange, ok := item.(map[string]interface{})
					if !ok {
						continue
					}

					// Skip default exchanges (they can't be deleted)
					exchangeName, ok := exchange["Name"].(string)
					if !ok || exchangeName == "" || strings.HasPrefix(exchangeName, "amq.") {
						continue
					}

					deleteExchangeAction := "DeleteExchange"
					deleteExchangeRequest := map[string]interface{}{
						"InstanceId":   parts[0],
						"VirtualHost":  parts[1],
						"ExchangeName": exchangeName,
					}

					_, err := client.RpcPost("amqp-open", "2019-12-12", deleteExchangeAction, nil, deleteExchangeRequest, false)
					if err != nil && !IsExpectedErrors(err, []string{"ExchangeNotExist"}) {
						if NeedRetry(err) {
							wait()
							return resource.RetryableError(err)
						}
						return resource.NonRetryableError(err)
					}
				}

				// Check if there are more exchanges to list
				if nextToken, ok := data["NextToken"].(string); ok && nextToken != "" {
					exchangeRequest["NextToken"] = nextToken
				} else {
					break
				}
			}

			// Next, list and delete all queues
			queueAction := "ListQueues"
			queueRequest := map[string]interface{}{
				"InstanceId":  parts[0],
				"VirtualHost": parts[1],
				"MaxResults":  100,
			}

			// Loop to handle pagination for queues
			for {
				queueResponse, err := client.RpcGet("amqp-open", "2019-12-12", queueAction, queueRequest, nil)
				if err != nil {
					if NeedRetry(err) {
						wait()
						return resource.RetryableError(err)
					}
					return resource.NonRetryableError(err)
				}

				data, ok := queueResponse["Data"].(map[string]interface{})
				if !ok {
					break
				}

				queues, ok := data["Queues"].([]interface{})
				if !ok || len(queues) == 0 {
					break
				}

				// Delete each queue
				for _, item := range queues {
					queue, ok := item.(map[string]interface{})
					if !ok {
						continue
					}

					queueName, ok := queue["Name"].(string)
					if !ok || queueName == "" {
						continue
					}

					deleteQueueAction := "DeleteQueue"
					deleteQueueRequest := map[string]interface{}{
						"InstanceId":  parts[0],
						"VirtualHost": parts[1],
						"QueueName":   queueName,
					}

					_, err := client.RpcPost("amqp-open", "2019-12-12", deleteQueueAction, nil, deleteQueueRequest, false)
					if err != nil && !IsExpectedErrors(err, []string{"QueueNotExist"}) {
						if NeedRetry(err) {
							wait()
							return resource.RetryableError(err)
						}
						return resource.NonRetryableError(err)
					}
				}

				// Check if there are more queues to list
				if nextToken, ok := data["NextToken"].(string); ok && nextToken != "" {
					queueRequest["NextToken"] = nextToken
				} else {
					break
				}
			}
		}
		response, err = client.RpcPost("amqp-open", "2019-12-12", action, nil, request, false)
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
		return WrapErrorf(err, DefaultErrorMsg, d.Id(), action, AlibabaCloudSdkGoERROR)
	}
	return nil
}
