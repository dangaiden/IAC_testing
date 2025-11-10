import json
import boto3
import uuid
import datetime
import base64
import gzip
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

PARTITION = "aws"
COMPANY_NAME = "Falco OSS"
PRODUCT_NAME = "Falco Runtime Security"

session = boto3.session.Session()
ec2 = session.resource("ec2")
sts = session.client('sts')

def format_datetime_for_securityhub(dt):
    """Fix datetime format to match Security Hub requirements: YYYY-MM-DDTHH:MM:SS.sssZ"""
    if dt is None:
        return datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    if isinstance(dt, str):
        try:
            dt = datetime.datetime.fromisoformat(dt.replace('Z', '+00:00'))
        except:
            return datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    else:
        dt = dt.astimezone(datetime.timezone.utc)
    return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

def safe_get_nested_value(data, keys, default_value="unknown"):
    """
    Safely extract nested values from dictionaries with fallback defaults.
    Supports both flat and nested Falco formats.
    """
    try:
        result = data
        for key in keys:
            if isinstance(result, dict) and key in result:
                result = result[key]
            else:
                # Try fallback to nested under 'log' if not found in flat
                if keys[0] != "log" and "log" in data:
                    # Try nested structure
                    nested_result = data["log"]
                    for nested_key in keys:
                        if isinstance(nested_result, dict) and nested_key in nested_result:
                            nested_result = nested_result[nested_key]
                        else:
                            logger.warning(f"Missing key path {keys} in data structure, using default: {default_value}")
                            return default_value
                    if nested_result is None or nested_result == "" or nested_result == "null":
                        logger.warning(f"Null/empty value found for {keys}, using default: {default_value}")
                        return default_value
                    return nested_result
                logger.warning(f"Missing key path {keys} in data structure, using default: {default_value}")
                return default_value
        if result is None or result == "" or result == "null":
            logger.warning(f"Null/empty value found for {keys}, using default: {default_value}")
            return default_value
        return result
    except Exception as e:
        logger.error(f"Error extracting value from {keys}: {str(e)}, using default: {default_value}")
        return default_value

def get_ec2_details(instance_id):
    try:
        if not instance_id or instance_id == "unknown":
            logger.warning(f"Invalid instance_id: {instance_id}, creating minimal EC2 resource")
            return None
        instance = ec2.Instance(instance_id)
        _ = instance.instance_type
        return instance
    except Exception as e:
        logger.error(f"Failed to get EC2 instance details for {instance_id}: {str(e)}")
        return None

def get_account_id():
    try:
        caller = sts.get_caller_identity()
        account_id = caller.get("Account")
        if not account_id:
            logger.error("Failed to get Account ID from STS, using fallback")
            return "Unknown AccountID"
        return account_id
    except Exception as e:
        logger.error(f"Error getting account ID: {str(e)}, using fallback")
        return "Unknown AccountID"

def map_finding_severity(priority):
    if not priority or not isinstance(priority, str):
        logger.warning(f"Invalid priority value: {priority}, defaulting to INFORMATIONAL")
        priority = "INFORMATIONAL"
    severity = {
        "EMERGENCY": "CRITICAL",
        "ALERT": "CRITICAL", 
        "CRITICAL": "CRITICAL",
        "ERROR": "HIGH",
        "WARNING": "HIGH",
        "NOTICE": "MEDIUM",
        "INFORMATIONAL": "INFORMATIONAL",
        "DEBUG": "INFORMATIONAL"
    }
    priority_upper = priority.upper().strip()
    label = severity.get(priority_upper, "INFORMATIONAL")
    if priority_upper not in severity:
        logger.warning(f"Unknown priority '{priority}', mapped to INFORMATIONAL")
    return {
        "Label": label,
        "Original": priority
    }

def generate_id(account_id, region):
    try:
        if not account_id or account_id == "Unknown AccountID":
            account_id = "unknown-account"
            logger.warning("Using fallback account ID for finding ID generation")
        if not region:
            region = "unknown-region"
            logger.warning("Using fallback region for finding ID generation")
        suffix = "falco-" + uuid.uuid4().hex
        full_id = f"{region}/{account_id}/{suffix}"
        return full_id
    except Exception as e:
        logger.error(f"Error generating ID: {str(e)}, using fallback")
        timestamp = int(datetime.datetime.now().timestamp())
        return f"unknown-region/unknown-account/falco-error-{timestamp}"

def get_ip_address(instance):
    ip = []
    try:
        if instance:
            if hasattr(instance, 'public_ip_address') and instance.public_ip_address:
                ip.append(instance.public_ip_address)
            if hasattr(instance, 'private_ip_address') and instance.private_ip_address:
                ip.append(instance.private_ip_address)
        if not ip:
            ip = ["0.0.0.0"]
            logger.warning("No IP addresses found, using fallback IP")
    except Exception as e:
        logger.error(f"Error extracting IP addresses: {str(e)}")
        ip = ["0.0.0.0"]
    return ip

def get_instance_id_from_event(falco_data):
    try:
        # Step 1: Get hostname directly from top level
        hostname = falco_data.get("hostname")
        
        if not hostname:
            logger.warning("No hostname found in Falco data")
            return "i-unknown000000000"
            
        logger.info(f"Found hostname: {hostname}")
        
        # Step 2: Extract private IP from hostname
        import re
        match = re.search(r"ip-(\d+-\d+-\d+-\d+)", hostname)
        if not match:
            logger.warning(f"No private IP pattern found in hostname: {hostname}")
            return "i-unknown000000000"
        
        private_ip = match.group(1).replace("-", ".")
        logger.info(f"Extracted private IP: {private_ip}")
        
        # Step 3: Find EC2 instance by private IP
        instances = list(ec2.instances.filter(
            Filters=[{"Name": "private-ip-address", "Values": [private_ip]}]
        ))
        
        if instances:
            instance_id = instances[0].id
            logger.info(f"Found instance ID: {instance_id} for private IP: {private_ip}")
            return instance_id
        else:
            logger.warning(f"No EC2 instance found for private IP: {private_ip}")
            return "i-unknown000000000"
            
    except Exception as e:
        logger.error(f"Error extracting instance ID: {str(e)}")
        return "i-unknown000000000"
    
def create_ec2_instance_resource(instance, instance_id):
    """
    Create EC2 instance resource for Security Hub ASFF.
    Uses fallback values if instance details are unavailable.
    """
    try:
        region = safe_get_nested_value({"region": session.region_name}, ["region"], "unknown-region")
        instance_resource = {
            "Details": {},
            "Type": "AwsEc2Instance",
            "Id": instance_id or "i-unknown000000000",
            "Partition": PARTITION,
            "Region": region,
            "Details": {
                "AwsEc2Instance": {}
            }
        }
        if instance:
            instance_resource["Details"]["AwsEc2Instance"]["Type"] = getattr(instance, 'instance_type', 'unknown')
            try:
                if hasattr(instance, 'launch_time') and instance.launch_time:
                    instance_resource["Details"]["AwsEc2Instance"]["LaunchedAt"] = format_datetime_for_securityhub(instance.launch_time)
            except Exception as e:
                logger.warning(f"Error formatting launch time: {str(e)}")
                instance_resource["Details"]["AwsEc2Instance"]["LaunchedAt"] = format_datetime_for_securityhub(datetime.datetime.now())
            instance_resource["Details"]["AwsEc2Instance"]["IpV4Addresses"] = get_ip_address(instance)
            instance_resource["Details"]["AwsEc2Instance"]["SubnetId"] = getattr(instance, 'subnet_id', 'unknown-subnet')
            instance_resource["Details"]["AwsEc2Instance"]["VpcId"] = getattr(instance, 'vpc_id', 'unknown-vpc')
            try:
                if hasattr(instance, 'iam_instance_profile') and instance.iam_instance_profile:
                    instance_resource["Details"]["AwsEc2Instance"]["IamInstanceProfileArn"] = instance.iam_instance_profile["Arn"]
                else:
                    instance_resource["Details"]["AwsEc2Instance"]["IamInstanceProfileArn"] = f"arn:aws:iam::{get_account_id()}:instance-profile/unknown"
            except Exception as e:
                logger.warning(f"Error extracting IAM instance profile: {str(e)}")
                instance_resource["Details"]["AwsEc2Instance"]["IamInstanceProfileArn"] = f"arn:aws:iam::{get_account_id()}:instance-profile/unknown"
        else:
            logger.warning(f"Instance {instance_id} not available, creating fallback resource")
            instance_resource["Details"]["AwsEc2Instance"]["Type"] = "unknown"
            instance_resource["Details"]["AwsEc2Instance"]["LaunchedAt"] = format_datetime_for_securityhub(datetime.datetime.now())
            instance_resource["Details"]["AwsEc2Instance"]["IpV4Addresses"] = ["0.0.0.0"]
            instance_resource["Details"]["AwsEc2Instance"]["SubnetId"] = "unknown-subnet"
            instance_resource["Details"]["AwsEc2Instance"]["VpcId"] = "unknown-vpc"
            instance_resource["Details"]["AwsEc2Instance"]["IamInstanceProfileArn"] = f"arn:aws:iam::{get_account_id()}:instance-profile/unknown"
        return instance_resource
    except Exception as e:
        logger.error(f"Error creating EC2 instance resource: {str(e)}")
        # Return minimal valid resource to prevent ASFF validation failure
        return {
            "Details": {
                "AwsEc2Instance": {
                    "Type": "unknown",
                    "LaunchedAt": format_datetime_for_securityhub(datetime.datetime.now()),
                    "IpV4Addresses": ["0.0.0.0"],
                    "SubnetId": "error-subnet",
                    "VpcId": "error-vpc",
                    "IamInstanceProfileArn": f"arn:aws:iam::{get_account_id()}:instance-profile/error"
                }
            },
            "Type": "AwsEc2Instance",
            "Id": instance_id or "error-instance",
            "Partition": PARTITION,
            "Region": session.region_name or "us-east-1"
        }

def get_eks_details(message):
    """
    Extract EKS/Kubernetes details with comprehensive error handling.
    Supports flat Falco format and falls back to nested if needed.
    """
    try:
        container_id = safe_get_nested_value(message, ["output_fields", "container.id"], "unknown-container-id")
        pod_name = safe_get_nested_value(message, ["output_fields", "k8s.pod.name"], "unknown-pod-name")
        namespace = safe_get_nested_value(message, ["output_fields", "k8s.ns.name"], "unknown-namespace")
        image = safe_get_nested_value(message, ["output_fields", "container.image.repository"], "unknown-image")
        if container_id == "unknown-container-id":
            container_id = f"unknown-container-{uuid.uuid4().hex[:8]}"
            logger.warning(f"Generated fallback container ID: {container_id}")
        if image == "unknown-image" or not image:
            image = "unknown-container-image"
            logger.warning(f"Using fallback image name: {image}")
        resources = []
        resource = {
            "Type": "Container",
            "Id": container_id,
            "Details": {
                "Container": {
                    "ImageName": image
                },
                "Other": {
                    "podName": pod_name,
                    "namespaceName": namespace
                }
            }
        }
        resources.append(resource)
        logger.info(f"Successfully created EKS resource for container {container_id} in pod {pod_name}")
        return resources
    except Exception as e:
        logger.error(f"Error extracting EKS details: {str(e)}")
        fallback_container_id = f"unknown-container-error-{uuid.uuid4().hex[:8]}"
        return [{
            "Type": "Container",
            "Id": fallback_container_id,
            "Details": {
                "Container": {
                    "ImageName": "unknown-image-error"
                },
                "Other": {
                    "podName": "unknown-pod-error",
                    "namespaceName": "unknown-namespace-error"
                }
            }
        }]

def eks_convert_falco_log_to_asff(entry):
    try:
        if not entry or not isinstance(entry, dict):
            logger.error("Invalid entry structure, cannot convert to ASFF")
            return None
        region = session.region_name or "us-east-1"
        instance_id = get_instance_id_from_event(entry)
        instance = get_ec2_details(instance_id)
        account_id = get_account_id()
        this_id = generate_id(account_id, region)
        output = safe_get_nested_value(entry, ["output"], "Falco alert - details unavailable")
        priority = safe_get_nested_value(entry, ["priority"], "Informational")
        rule_title = safe_get_nested_value(entry, ["rule"], "Unknown Falco Rule")
        severity = map_finding_severity(priority)
        instance_resource = create_ec2_instance_resource(instance, instance_id)
        eks_resources = get_eks_details(entry)
        resources = []
        resources.append(instance_resource)
        for container_resource in eks_resources:
            resources.append(container_resource)
        finding = {
            "SchemaVersion": "2018-10-08",
            "AwsAccountId": account_id,
            "Id": this_id,
            "Description": output[:1024],
            "GeneratorId": f"{instance_id}-{this_id.split('/')[-1]}",
            "ProductArn": f"arn:{PARTITION}:securityhub:{region}:{account_id}:product/{account_id}/default",
            "Severity": severity,
            "Resources": resources,
            "Title": rule_title[:256],
            "Types": ["Software and Configuration Checks"],
            "CompanyName": COMPANY_NAME,
            "ProductName": PRODUCT_NAME
        }
        try:
            now = datetime.datetime.now(datetime.timezone.utc)
            timestamp = format_datetime_for_securityhub(now)
            finding["UpdatedAt"] = timestamp
            finding["CreatedAt"] = timestamp
        except Exception as e:
            logger.error(f"Error setting timestamps: {str(e)}")
            finding["UpdatedAt"] = "2025-01-01T00:00:00.000Z"
            finding["CreatedAt"] = "2025-01-01T00:00:00.000Z"
        logger.info(f"Successfully converted Falco log to ASFF: {rule_title}")
        return finding
    except Exception as e:
        logger.error(f"Critical error converting Falco log to ASFF: {str(e)}")
        return {
            "SchemaVersion": "2018-10-08",
            "AwsAccountId": get_account_id(),
            "Id": generate_id(get_account_id(), session.region_name or "us-east-1"),
            "Description": f"Error processing Falco log: {str(e)}",
            "GeneratorId": "falco-error-handler",
            "ProductArn": f"arn:{PARTITION}:securityhub:{session.region_name or 'us-east-1'}:{get_account_id()}:product/{get_account_id()}/default",
            "Severity": {"Label": "INFORMATIONAL", "Original": "Error"},
            "Resources": [{
                "Type": "Other",
                "Id": "falco-processing-error",
                "Details": {}
            }],
            "Title": "Falco Log Processing Error",
            "Types": ["Software and Configuration Checks"],
            "UpdatedAt": format_datetime_for_securityhub(datetime.datetime.now()),
            "CreatedAt": format_datetime_for_securityhub(datetime.datetime.now()),
            "CompanyName": COMPANY_NAME,
            "ProductName": PRODUCT_NAME
        }

def validate_asff_finding(finding):
    try:
        required_fields = ["SchemaVersion", "AwsAccountId", "Id", "Description", 
                          "GeneratorId", "ProductArn", "Severity", "Resources", 
                          "Title", "Types", "UpdatedAt", "CreatedAt"]
        for field in required_fields:
            if field not in finding:
                logger.error(f"Missing required ASFF field: {field}")
                return False
        if not isinstance(finding["Severity"], dict) or "Label" not in finding["Severity"]:
            logger.error("Invalid severity structure in ASFF finding")
            return False
        if not isinstance(finding["Resources"], list) or len(finding["Resources"]) == 0:
            logger.error("Invalid or empty resources in ASFF finding")
            return False
        for resource in finding["Resources"]:
            if not resource.get("Id") or resource.get("Id") in [None, "", "null"]:
                logger.error(f"Invalid resource ID found: {resource.get('Id')}")
                return False
        logger.info("ASFF finding validation passed")
        return True
    except Exception as e:
        logger.error(f"Error validating ASFF finding: {str(e)}")
        return False

def lambda_handler(event, context):
    """
    Main Lambda handler with comprehensive error handling and progress tracking.
    """
    try:
        logger.info("Starting Falco to Security Hub processing")
        
        # Validate event structure
        if not event or 'awslogs' not in event or 'data' not in event['awslogs']:
            logger.error("Invalid event structure - missing awslogs data")
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'Invalid event structure',
                    'message': 'Missing awslogs.data field'
                })
            }

        # Decode CloudWatch logs data
        try:
            cw_data = event['awslogs']['data']
            data_decoded = base64.b64decode(cw_data)
            data = json.loads(gzip.decompress(data_decoded).decode('utf-8'))
        except Exception as e:
            logger.error(f"Error decoding CloudWatch data: {str(e)}")
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'Failed to decode CloudWatch data',
                    'message': str(e)
                })
            }

        findings = []
        processed_count = 0
        error_count = 0
        skipped_count = 0

        # Process log events
        log_events = data.get('logEvents', [])[:100]  # Limit batch size to 100
        for entry in log_events:
            try:
                logger.info(f"Raw log event message: {entry.get('message')}")
                message = json.loads(entry['message'])
                logger.info(f"Parsed log event message: {json.dumps(message, indent=2)}")

                # Extract instance ID using the new function
                instance_id = get_instance_id_from_event(message)
                logger.info(f"Extracted instance ID: {instance_id}")

                # Convert Falco log to ASFF format
                finding = eks_convert_falco_log_to_asff(message)

                # Validate and collect findings
                if finding and validate_asff_finding(finding):
                    findings.append(finding)
                    processed_count += 1
                    logger.info(f"Successfully processed finding {processed_count}: {finding.get('Title', 'Unknown')}")
                else:
                    error_count += 1
                    logger.warning(f"Failed to create valid finding for entry {processed_count + error_count}")
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error in log entry: {str(e)}")
                error_count += 1
            except Exception as e:
                logger.error(f"Unexpected error processing log entry: {str(e)}")
                error_count += 1

        # Send findings to Security Hub
        if findings:
            try:
                sh = session.client('securityhub')
                batch_size = 100
                total_sent = 0

                for i in range(0, len(findings), batch_size):
                    batch = findings[i:i + batch_size]
                    response = sh.batch_import_findings(Findings=batch)

                    # Check for processing errors in the batch
                    if 'FailedFindings' in response and response['FailedFindings']:
                        for failed_finding in response['FailedFindings']:
                            logger.error(f"Security Hub rejected finding: {failed_finding}")

                    total_sent += len(batch) - len(response.get('FailedFindings', []))
                    logger.info(f"Sent batch {i//batch_size + 1}, successfully imported: {len(batch) - len(response.get('FailedFindings', []))}")

                logger.info(f"Successfully sent {total_sent} findings to Security Hub")
            except Exception as e:
                logger.error(f"Error sending findings to Security Hub: {str(e)}")
                return {
                    'statusCode': 500,
                    'body': json.dumps({
                        'error': 'Failed to send findings to Security Hub',
                        'message': str(e),
                        'processed_count': processed_count,
                        'error_count': error_count
                    })
                }

        # Return success response
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Successfully processed Falco findings',
                'statistics': {
                    'total_events': len(log_events),
                    'processed_successfully': processed_count,
                    'processing_errors': error_count,
                    'skipped_entries': skipped_count,
                    'findings_sent_to_security_hub': len(findings)
                },
                'timestamp': datetime.datetime.now().isoformat()
            })
        }

    except Exception as e:
        logger.error(f"Critical Lambda error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Critical Lambda processing error',
                'message': str(e),
                'timestamp': datetime.datetime.now().isoformat()
            })
        }
