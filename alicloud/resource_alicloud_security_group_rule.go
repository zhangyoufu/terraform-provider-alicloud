package alicloud

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	util "github.com/alibabacloud-go/tea-utils/service"

	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/aliyun/terraform-provider-alicloud/alicloud/connectivity"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func resourceAliyunSecurityGroupRule() *schema.Resource {
	return &schema.Resource{
		Create: resourceAliyunSecurityGroupRuleCreate,
		Read:   resourceAliyunSecurityGroupRuleRead,
		Update: resourceAliyunSecurityGroupRuleUpdate,
		Delete: resourceAliyunSecurityGroupRuleDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"security_group_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"type": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{"ingress", "egress"}, false),
				Description:  "Type of rule, ingress (inbound) or egress (outbound).",
			},
			"ip_protocol": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{"tcp", "udp", "icmp", "gre", "all"}, false),
			},
			"policy": {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				Default:      GroupRulePolicyAccept,
				ValidateFunc: validation.StringInSlice([]string{"accept", "drop"}, false),
			},
			"priority": {
				Type:         schema.TypeInt,
				Optional:     true,
				ForceNew:     true,
				Default:      1,
				ValidateFunc: validation.IntBetween(1, 100),
			},
			"source_cidr_ip": {
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"ipv6_source_cidr_ip", "ipv6_dest_cidr_ip", "source_prefix_list_id", "source_group_id"},
			},
			"dest_cidr_ip": {
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"ipv6_source_cidr_ip", "ipv6_dest_cidr_ip", "dest_prefix_list_id", "dest_group_id"},
			},
			"ipv6_source_cidr_ip": {
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"source_cidr_ip", "dest_cidr_ip", "source_prefix_list_id", "source_group_id"},
			},
			"ipv6_dest_cidr_ip": {
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"source_cidr_ip", "dest_cidr_ip", "dest_prefix_list_id", "dest_group_id"},
			},
			"port_range": {
				Type:             schema.TypeString,
				Optional:         true,
				ForceNew:         true,
				Default:          AllPortRange,
				DiffSuppressFunc: ecsSecurityGroupRulePortRangeDiffSuppressFunc,
			},
			"source_port_range": {
				Type:             schema.TypeString,
				Optional:         true,
				ForceNew:         true,
				Default:          AllPortRange,
				DiffSuppressFunc: ecsSecurityGroupRulePortRangeDiffSuppressFunc,
			},
			"source_prefix_list_id": {
				Type:             schema.TypeString,
				Optional:         true,
				Computed:         true,
				ForceNew:         true,
				ConflictsWith:    []string{"dest_prefix_list_id", "source_cidr_ip", "ipv6_source_cidr_ip", "source_group_id"},
				DiffSuppressFunc: ecsSecurityGroupRulePreFixListIdDiffSuppressFunc,
			},
			"dest_prefix_list_id": {
				Type:             schema.TypeString,
				Optional:         true,
				Computed:         true,
				ForceNew:         true,
				ConflictsWith:    []string{"source_prefix_list_id", "dest_cidr_ip", "ipv6_dest_cidr_ip", "dest_group_id"},
				DiffSuppressFunc: ecsSecurityGroupRulePreFixListIdDiffSuppressFunc,
			},
			"source_group_id": {
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"dest_group_id", "source_cidr_ip", "ipv6_source_cidr_ip", "source_prefix_list_id"},
			},
			"dest_group_id": {
				Type:          schema.TypeString,
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"source_group_id", "dest_cidr_ip", "ipv6_dest_cidr_ip", "dest_prefix_list_id"},
			},
			"source_group_owner_account": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},
			"dest_group_owner_account": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},
			"nic_type": {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				Computed:     true,
				ValidateFunc: validation.StringInSlice([]string{"internet", "intranet"}, false),
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
		},
	}
}

func resourceAliyunSecurityGroupRuleCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*connectivity.AliyunClient)
	var response map[string]interface{}
	request := make(map[string]interface{})
	conn, err := client.NewEcsClient()
	if err != nil {
		return WrapError(err)
	}

	request["RegionId"] = client.RegionId

	securityGroupId := d.Get("security_group_id").(string)
	request["SecurityGroupId"] = securityGroupId
	id := securityGroupId

	permissionsMaps := make([]map[string]interface{}, 0)
	permissionsMap := map[string]interface{}{}

	direction := d.Get("type").(string)
	id += ":" + direction

	id += ":"
	if v, ok := d.GetOk("priority"); ok {
		priority := strconv.Itoa(v.(int))
		permissionsMap["Priority"] = priority
		id += priority
	} else {
		id += "1"
	}

	id += ":"
	if v, ok := d.GetOk("policy"); ok {
		permissionsMap["Policy"] = v.(string)
		id += v.(string)
	} else {
		id += "accept"
	}

	id += ":"
	if v, ok := d.GetOk("source_cidr_ip"); ok {
		permissionsMap["SourceCidrIp"] = v.(string)
		id += v.(string)
	} else if v,ok := d.GetOk("ipv6_source_cidr_ip"); ok {
		permissionsMap["Ipv6SourceCidrIp"] = strings.Replace(v.(string), ":", "_", -1)
		id += v.(string)
	} else if v, ok := d.GetOk("source_prefix_list_id"); ok {
		permissionsMap["SourcePrefixListId"] = v.(string)
		id += v.(string)
	} else if v, ok := d.GetOk("source_group_id"); ok {
		permissionsMap["SourceGroupId"] = v.(string)
		id += v.(string)
	}
	if v, ok := d.GetOk("source_group_owner_account"); ok {
		if direction != string(DirectionIngress) {
			return fmt.Errorf(" 'source_group_owner_account' requires 'type' = 'ingress'. Please correct it and try again.")
		}
		permissionsMap["SourceGroupOwnerAccount"] = v
	}

	id += ":"
	if v, ok := d.GetOk("dest_cidr_ip"); ok {
		permissionsMap["DestCidrIp"] = v.(string)
		id += v.(string)
	} else if v, ok := d.GetOk("ipv6_dest_cidr_ip"); ok {
		permissionsMap["Ipv6DestCidrIp"] = strings.Replace(v.(string), ":", "_", -1)
		id += v.(string)
	} else if v, ok := d.GetOk("dest_prefix_list_id"); ok {
		permissionsMap["DestPrefixListId"] = v.(string)
		id += v.(string)
	} else if v, ok := d.GetOk("dest_group_id"); ok {
		permissionsMap["DestGroupId"] = v.(string)
		id += v.(string)
	}
	if v, ok := d.GetOk("dest_group_owner_account"); ok {
		if direction != string(DirectionEgress) {
			return fmt.Errorf(" 'dest_group_owner_account' requires 'type' = 'egress'. Please correct it and try again.")
		}
		permissionsMap["DestGroupOwnerAccount"] = v
	}

	ipProtocol := d.Get("ip_protocol").(string)
	permissionsMap["IpProtocol"] = ipProtocol
	id += ":" + ipProtocol

	id += ":"
	if v, ok := d.GetOk("port_range"); ok {
		permissionsMap["PortRange"] = v.(string)
		id += v.(string)

		if ipProtocol == string(Tcp) || ipProtocol == string(Udp) {
			if v.(string) == AllPortRange {
				return fmt.Errorf(" 'tcp' and 'udp' can support port range: [1, 65535]. Please correct it and try again.")
			}
		} else if v.(string) != AllPortRange {
			return fmt.Errorf(" 'icmp', 'gre' and 'all' only support port range '-1/-1'. Please correct it and try again.")
		}
	}

	id += ":"
	if v, ok := d.GetOk("source_port_range"); ok {
		permissionsMap["SourcePortRange"] = v.(string)
		id += v.(string)

		if ipProtocol == string(Tcp) || ipProtocol == string(Udp) {
			if v.(string) == AllPortRange {
				return fmt.Errorf(" 'tcp' and 'udp' can support source port range: [1, 65535]. Please correct it and try again.")
			}
		} else if v.(string) != AllPortRange {
			return fmt.Errorf(" 'icmp', 'gre' and 'all' only support source port range '-1/-1'. Please correct it and try again.")
		}
	}

	id += ":"
	if v, ok := d.GetOk("nic_type"); ok {
		permissionsMap["NicType"] = v.(string)
		id += v.(string)
	}

	if v, ok := d.GetOk("description"); ok {
		permissionsMap["Description"] = v.(string)
	}

	permissionsMaps = append(permissionsMaps, permissionsMap)
	request["Permissions"] = permissionsMaps

	if direction == string(DirectionIngress) {
		action := "AuthorizeSecurityGroup"

		runtime := util.RuntimeOptions{}
		runtime.SetAutoretry(true)
		wait := incrementalWait(3*time.Second, 5*time.Second)
		err = resource.Retry(client.GetRetryTimeout(d.Timeout(schema.TimeoutCreate)), func() *resource.RetryError {
			response, err = conn.DoRequest(StringPointer(action), nil, StringPointer("POST"), StringPointer("2014-05-26"), StringPointer("AK"), nil, request, &runtime)
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
			return WrapErrorf(err, DefaultErrorMsg, "alicloud_security_group_rule", action, AlibabaCloudSdkGoERROR)
		}
	} else {
		action := "AuthorizeSecurityGroupEgress"

		runtime := util.RuntimeOptions{}
		runtime.SetAutoretry(true)
		wait := incrementalWait(3*time.Second, 5*time.Second)
		err = resource.Retry(client.GetRetryTimeout(d.Timeout(schema.TimeoutCreate)), func() *resource.RetryError {
			response, err = conn.DoRequest(StringPointer(action), nil, StringPointer("POST"), StringPointer("2014-05-26"), StringPointer("AK"), nil, request, &runtime)
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
			return WrapErrorf(err, DefaultErrorMsg, "alicloud_security_group_rule", action, AlibabaCloudSdkGoERROR)
		}
	}

	d.SetId(id)

	return resourceAliyunSecurityGroupRuleRead(d, meta)
}

func resourceAliyunSecurityGroupRuleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*connectivity.AliyunClient)
	ecsService := EcsService{client}
	parts := strings.Split(d.Id(), ":")
	policy := parseSecurityRuleId(d, meta, 3)
	strPriority := parseSecurityRuleId(d, meta, 2)
	var priority int
	if policy == "" || strPriority == "" {
		policy = d.Get("policy").(string)
		priority = d.Get("priority").(int)
		d.SetId(d.Id() + ":" + policy + ":" + strconv.Itoa(priority))
	} else {
		prior, err := strconv.Atoi(strPriority)
		if err != nil {
			return WrapError(err)
		}
		priority = prior
	}
	sgId := parts[0]
	direction := parts[1]

	// wait the rule exist
	var object ecs.Permission
	wait := incrementalWait(3*time.Second, 5*time.Second)
	err := resource.Retry(10*time.Minute, func() *resource.RetryError {
		obj, err := ecsService.DescribeSecurityGroupRule(d.Id())
		if err != nil && d.IsNewResource() {
			wait()
			return resource.RetryableError(err)
		} else {
			object = obj
			return resource.NonRetryableError(err)
		}
	})
	if err != nil {
		if NotFoundError(err) && !d.IsNewResource() {
			log.Printf("[DEBUG] Resource alicloud_security_group_rule ecsService.DescribeSecurityGroupRule Failed!!! %s", err)
			d.SetId("")
			return nil
		}
		return WrapError(err)
	}

	d.Set("type", object.Direction)
	d.Set("ip_protocol", strings.ToLower(string(object.IpProtocol)))
	d.Set("nic_type", object.NicType)
	d.Set("policy", strings.ToLower(string(object.Policy)))
	d.Set("port_range", object.PortRange)
	d.Set("source_port_range", object.SourcePortRange)
	d.Set("description", object.Description)
	if pri, err := strconv.Atoi(object.Priority); err != nil {
		return WrapError(err)
	} else {
		d.Set("priority", pri)
	}
	d.Set("security_group_id", sgId)
	d.Set("source_cidr_ip", object.SourceCidrIp)
	d.Set("dest_cidr_ip", object.DestCidrIp)
	d.Set("ipv6_source_cidr_ip", object.Ipv6SourceCidrIp)
	d.Set("ipv6_dest_cidr_ip", object.Ipv6DestCidrIp)
	//support source and desc by type
	if direction == string(DirectionIngress) {
		d.Set("source_prefix_list_id", object.SourcePrefixListId)
		d.Set("source_group_id", object.SourceGroupId)
		d.Set("source_group_owner_account", object.SourceGroupOwnerAccount)
	} else {
		d.Set("dest_prefix_list_id", object.DestPrefixListId)
		d.Set("dest_group_id", object.DestGroupId)
		d.Set("dest_group_owner_account", object.DestGroupOwnerAccount)
	}

	return nil
}

func resourceAliyunSecurityGroupRuleUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*connectivity.AliyunClient)

	policy := parseSecurityRuleId(d, meta, 3)
	strPriority := parseSecurityRuleId(d, meta, 2)
	var priority int
	if policy == "" || strPriority == "" {
		policy = d.Get("policy").(string)
		priority = d.Get("priority").(int)
		d.SetId(d.Id() + ":" + policy + ":" + strconv.Itoa(priority))
	} else {
		prior, err := strconv.Atoi(strPriority)
		if err != nil {
			return WrapError(err)
		}
		priority = prior
	}

	request, err := buildAliyunSGRuleRequest(d, meta)
	if err != nil {
		return WrapError(err)
	}

	direction := d.Get("type").(string)

	if direction == string(DirectionIngress) {
		request.ApiName = "ModifySecurityGroupRule"
		_, err = client.WithEcsClient(func(ecsClient *ecs.Client) (interface{}, error) {
			return ecsClient.ProcessCommonRequest(request)
		})
	} else {
		request.ApiName = "ModifySecurityGroupEgressRule"
		_, err = client.WithEcsClient(func(ecsClient *ecs.Client) (interface{}, error) {
			return ecsClient.ProcessCommonRequest(request)
		})
	}

	raw, err := client.WithEcsClient(func(ecsClient *ecs.Client) (interface{}, error) {
		return ecsClient.ProcessCommonRequest(request)
	})

	if err != nil {
		return WrapErrorf(err, DefaultErrorMsg, d.Id(), request.GetActionName(), AlibabaCloudSdkGoERROR)
	}

	addDebug(request.GetActionName(), raw, request.Headers, request)

	return resourceAliyunSecurityGroupRuleRead(d, meta)
}

func deleteSecurityGroupRule(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*connectivity.AliyunClient)
	ruleType := d.Get("type").(string)
	request, err := buildAliyunSGRuleRequest(d, meta)
	if err != nil {
		return WrapError(err)
	}

	if ruleType == string(DirectionIngress) {
		request.ApiName = "RevokeSecurityGroup"
		_, err = client.WithEcsClient(func(ecsClient *ecs.Client) (interface{}, error) {
			return ecsClient.ProcessCommonRequest(request)
		})
	} else {
		request.ApiName = "RevokeSecurityGroupEgress"
		_, err = client.WithEcsClient(func(ecsClient *ecs.Client) (interface{}, error) {
			return ecsClient.ProcessCommonRequest(request)
		})
	}

	if err != nil {
		return WrapErrorf(err, DefaultErrorMsg, d.Id(), request.GetActionName(), AlibabaCloudSdkGoERROR)
	}
	return nil
}

func resourceAliyunSecurityGroupRuleDelete(d *schema.ResourceData, meta interface{}) error {
	policy := parseSecurityRuleId(d, meta, 3)
	strPriority := parseSecurityRuleId(d, meta, 2)
	var priority int
	if policy == "" || strPriority == "" {
		policy = d.Get("policy").(string)
		priority = d.Get("priority").(int)
		d.SetId(d.Id() + ":" + policy + ":" + strconv.Itoa(priority))
	} else {
		prior, err := strconv.Atoi(strPriority)
		if err != nil {
			return WrapError(err)
		}
		priority = prior
	}

	err := resource.Retry(5*time.Minute, func() *resource.RetryError {
		err := deleteSecurityGroupRule(d, meta)
		if err != nil {
			if NotFoundError(err) || IsExpectedErrors(err, []string{"InvalidSecurityGroupId.NotFound"}) {
				return nil
			}
			return resource.RetryableError(err)
		}
		return nil
	})
	if err != nil {
		return WrapError(err)
	}
	return nil
}

func buildAliyunSGRuleRequest(d *schema.ResourceData, meta interface{}) (*requests.CommonRequest, error) {
	client := meta.(*connectivity.AliyunClient)
	// Get product code from the built request
	ruleReq := ecs.CreateModifySecurityGroupRuleRequest()
	request, err := client.NewCommonRequest(ruleReq.GetProduct(), ruleReq.GetLocationServiceCode(), strings.ToUpper(string(Https)), connectivity.ApiVersion20140526)
	if err != nil {
		return request, WrapError(err)
	}

	direction := d.Get("type").(string)

	port_range := d.Get("port_range").(string)
	request.QueryParams["PortRange"] = port_range

	if v, ok := d.GetOk("ip_protocol"); ok {
		request.QueryParams["IpProtocol"] = v.(string)
		if v.(string) == string(Tcp) || v.(string) == string(Udp) {
			if port_range == AllPortRange {
				return nil, fmt.Errorf("'tcp' and 'udp' can support port range: [1, 65535]. Please correct it and try again.")
			}
		} else if port_range != AllPortRange {
			return nil, fmt.Errorf("'icmp', 'gre' and 'all' only support port range '-1/-1'. Please correct it and try again.")
		}
	}

	if v, ok := d.GetOk("policy"); ok {
		request.QueryParams["Policy"] = v.(string)
	}

	if v, ok := d.GetOk("priority"); ok {
		request.QueryParams["Priority"] = strconv.Itoa(v.(int))
	}

	if v, ok := d.GetOk("source_cidr_ip"); ok {
		request.QueryParams["SourceCidrIp"] = v.(string)
	}

	if v, ok := d.GetOk("dest_cidr_ip"); ok {
		request.QueryParams["DestCidrIp"] = v.(string)
	}

	if v, ok := d.GetOk("ipv6_source_cidr_ip"); ok {
		request.QueryParams["Ipv6SourceCidrIp"] = v.(string)
	}

	if v, ok := d.GetOk("ipv6_dest_cidr_ip"); ok {
		request.QueryParams["Ipv6DestCidrIp"] = v.(string)
	}

	if direction == string(DirectionIngress) {
		if v, ok := d.GetOk("source_prefix_list_id"); ok {
			request.QueryParams["SourcePrefixListId"] = v.(string)
		}
		if v, ok := d.GetOk("source_group_id"); ok {
			request.QueryParams["SourceGroupId"] = v.(string)
		}
		if v, ok := d.GetOk("source_group_owner_account"); ok {
			request.QueryParams["SourceGroupOwnerAccount"] = v.(string)
		}
	}

	if direction == string(DirectionEgress) {
		if v, ok := d.GetOk("dest_prefix_list_id"); ok {
			request.QueryParams["DestPrefixListId"] = v.(string)
		}
		if v, ok := d.GetOk("dest_group_id"); ok {
			request.QueryParams["DestGroupId"] = v.(string)
		}
		if v, ok := d.GetOk("dest_group_owner_account"); ok {
			request.QueryParams["DestGroupOwnerAccount"] = v.(string)
		}
	}

	if v, ok := d.GetOk("nic_type"); ok {
		request.QueryParams["NicType"] = v.(string)
	}

	request.QueryParams["SecurityGroupId"] = d.Get("security_group_id").(string)

	description := d.Get("description").(string)
	request.QueryParams["Description"] = description

	return request, nil
}

func parseSecurityRuleId(d *schema.ResourceData, meta interface{}, index int) (result string) {
	parts := strings.Split(d.Id(), ":")
	defer func() {
		if e := recover(); e != nil {
			log.Printf("Panicing %s\r\n", e)
			result = ""
		}
	}()
	return parts[index]
}
