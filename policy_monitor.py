"""
AWS IAM Policy Monitor
Version: v1.0.0-beta.1
Author: Nick the Security Dude
Date: 12-22-2024
License: Creative Commons Attribution-NonCommercial (CC BY-NC)
Copyright (c) 2024 Nick the Security Dude

Feature: AWS IAM Policy Monitor
  As a security administrator
  I want to automatically monitor and enforce IAM policy restrictions
  So that I can prevent unauthorized access and maintain security compliance

  Background:
    Given the AWS IAM Policy Monitor is running
    And the monitor has access to IAM service

  Scenario: Allow non-restricted inline policies for users
    Given a user has an inline policy with non-restricted permissions
    When the policy monitor evaluates the policy
    Then the non-restricted inline policy should remain attached
    And the policy should be found in the user's policy list

  Scenario: Automatically remove restricted managed policies
    Given a user has the AdministratorAccess managed policy attached
    When the policy monitor detects the restricted policy
    Then the AdministratorAccess policy should be automatically removed
    And no managed policies should remain attached to the user

  Scenario: Prevent IAM-specific inline policies
    Given a user attempts to attach an inline policy with IAM permissions
    When the policy monitor evaluates the policy
    Then the IAM inline policy should be automatically removed
    And no IAM-related policies should remain attached

  Scenario: Allow policies for whitelisted roles
    Given a role with a whitelisted prefix exists
    When the role has CloudFront service permissions
    Then the policy should remain attached to the role
    And the policy monitor should not remove it

  Scenario: Remove policies with restricted actions
    Given a policy contains restricted actions like "iam:*"
    When the policy monitor evaluates the policy
    Then the policy should be automatically removed
    And attempts to recreate the policy should be blocked

This work is licensed under the Creative Commons Attribution-NonCommercial 4.0 
International License. To view a copy of this license, visit 
http://creativecommons.org/licenses/by-nc/4.0/ or send a letter to Creative 
Commons, PO Box 1866, Mountain View, CA 94042, USA.

You are free to:
- Share: copy and redistribute the material in any medium or format
- Adapt: remix, transform, and build upon the material

Under the following terms:
- Attribution: You must give appropriate credit, provide a link to the license, 
  and indicate if changes were made.
- NonCommercial: You may not use the material for commercial purposes.

You are free to:
- Share: copy and redistribute the material in any medium or format
- Adapt: remix, transform, and build upon the material

Under the following terms:
- Attribution: You must give appropriate credit, provide a link to the license, 
  and indicate if changes were made.
- NonCommercial: You may not use the material for commercial purposes.

Description: This Lambda function monitors and enforces IAM policy restrictions across an AWS account.

It automatically detects and removes potentially risky IAM policies, including those with overly 
permissive actions (*) or sensitive service access. The script handles both inline and managed 
policies attached to users, groups, and roles. Roles with prefixes 'abc-', 'AWSReservedSSO_', or 
'AWSServiceRoleFor' (case insensitive) are whitelisted.

Key features:
- Monitors IAM policy attachments, creations, and modifications in real-time
- Validates policies against predefined restricted actions and patterns
- Automatically removes non-compliant policies and policy versions
- Supports both inline and managed policy checks
- Prevents creation of policies with restricted actions
- Handles Unicode normalization for policy comparison
"""

import json
import boto3
import os
import inspect
import logging

# Configure logging for AWS Lambda environment
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
iam = boto3.client('iam')
sns = boto3.client('sns')

def has_restricted_actions(policy_doc):
    """
    Check if a policy document contains restricted actions.
    
    Args:
        policy_doc (dict): The IAM policy document to check
        
    Returns:
        bool: True if the policy contains restricted actions, False otherwise
        
    Description:
        Analyzes a policy document for potentially risky permissions including:
        - Wildcard (*) permissions
        - Full IAM access
        - Full Organizations access
        - Full STS access
        Handles Unicode normalization for consistent string comparison
    """
    import unicodedata
    
    restricted_actions = [
        '*',
        'iam:*',
        'organizations:*',
        'sts:*'
    ]
    
    def normalize_string(s):
        """Normalize unicode strings to their ASCII form."""
        # Normalize to NFKC form and then encode to ASCII, ignoring non-ASCII chars
        return unicodedata.normalize('NFKC', s).encode('ascii', 'ignore').decode('ascii').lower()
    
    # Normalize restricted actions
    normalized_restricted = [normalize_string(action) for action in restricted_actions]
    
    for statement in policy_doc.get('Statement', []):
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            # Normalize the action before comparison
            normalized_action = normalize_string(action)
            if normalized_action in normalized_restricted:
                return True
    return False

def check_inline_policies(entity_type, entity_name, policy_name):
    """
    Check and remove restricted inline policies from IAM entities.
    
    Args:
        entity_type (str): Type of IAM entity ('user', 'role', or 'group')
        entity_name (str): Name of the IAM entity
        policy_name (str): Name of the inline policy to check
        
    Returns:
        list: List of violation messages for any removed policies
        
    Description:
        Retrieves and analyzes inline policies attached to IAM entities.
        If a policy contains restricted actions, it is automatically removed
        and a violation message is recorded.
        Roles with names starting with 'abc-' (case insensitive) are whitelisted.
    """
    violations = []
    try:
        # Skip checks for whitelisted roles
        role_prefixes = ['abc-', 'AWSReservedSSO_', 'AWSServiceRoleFor']
        if entity_type == 'role' and any(entity_name.lower().startswith(prefix.lower()) for prefix in role_prefixes):
            return violations
        if entity_type == 'user':
            policy_response = iam.get_user_policy(
                UserName=entity_name,
                PolicyName=policy_name
            )
            policy_doc = policy_response['PolicyDocument']
            if has_restricted_actions(policy_doc):
                iam.delete_user_policy(UserName=entity_name, PolicyName=policy_name)
                violations.append(f"Removed restricted inline policy {policy_name} from user {entity_name}")
        elif entity_type == 'role':
            policy_response = iam.get_role_policy(
                RoleName=entity_name,
                PolicyName=policy_name
            )
            policy_doc = policy_response['PolicyDocument']
            if has_restricted_actions(policy_doc):
                iam.delete_role_policy(RoleName=entity_name, PolicyName=policy_name)
                violations.append(f"Removed restricted inline policy {policy_name} from role {entity_name}")
        elif entity_type == 'group':
            policy_response = iam.get_group_policy(
                GroupName=entity_name,
                PolicyName=policy_name
            )
            policy_doc = policy_response['PolicyDocument']
            if has_restricted_actions(policy_doc):
                iam.delete_group_policy(GroupName=entity_name, PolicyName=policy_name)
                violations.append(f"Removed restricted inline policy {policy_name} from group {entity_name}")
    except Exception as e:
        logger.error(f"[Line {inspect.currentframe().f_lineno}] Error checking inline policy {policy_name} for {entity_type} {entity_name}: {str(e)}")
    return violations

def is_restricted_managed_policy(policy_arn, entity_type):
    """
    Check if a managed policy is restricted based on ARN patterns and entity type.
    
    Args:
        policy_arn (str): The ARN of the managed policy to check
        entity_type (str): Type of IAM entity ('user', 'role', or 'group')
        
    Returns:
        bool: True if the policy is restricted, False otherwise
        
    Description:
        Evaluates managed policies against several criteria:
        - Matches against predefined restricted policy ARNs
        - Checks for 'ABC-' prefix in policy names
        - Identifies 'FullAccess' policies for users and groups
    """
    restricted_policies_role = [
        'arn:aws:iam::aws:policy/AdministratorAccess'
    ]
    
    # Check if policy starts with ABC- (case insensitive)
    if policy_arn.split('/')[-1].lower().startswith('abc-'):
        return True
        
    # Check if policy contains "FullAccess" for users and groups only
    if entity_type != 'role' and any(pattern.lower() in policy_arn.lower() for pattern in ['FullAccess', 'Admin', 'PowerUser', 'ReadOnlyAccess', 'ServiceRole']):
        return True
    
    restricted_policies_user_group = restricted_policies_role+[
        'arn:aws:iam::aws:policy/SecretsManagerReadWrite'
    ]
    
    if entity_type == 'role':
        return policy_arn in restricted_policies_role
    else:  # user or group
        return policy_arn in restricted_policies_user_group

def check_policy(policy_arn, principal_type='user'):
    """
    Comprehensive check for restricted policies by ARN and content analysis.
    
    Args:
        policy_arn (str): The ARN of the policy to check
        principal_type (str): Type of IAM principal ('user', 'role', or 'group')
        
    Returns:
        bool: True if the policy is restricted, False otherwise
        
    Description:
        Performs a two-step validation:
        1. Checks if the policy ARN matches restricted patterns
        2. If not restricted by ARN, analyzes the policy document content
           for restricted actions
    """
    try:
        # First check if it's a restricted managed policy
        if is_restricted_managed_policy(policy_arn, principal_type):
            return True
            
        # If not restricted managed policy, check the policy content
        policy = iam.get_policy(PolicyArn=policy_arn)
        version_id = policy['Policy']['DefaultVersionId']
        
        # Get the policy document
        policy_version = iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id
        )
        
        policy_doc = policy_version['PolicyVersion']['Document']
        return has_restricted_actions(policy_doc)
        
    except Exception as e:
        logger.error(f"[Line {inspect.currentframe().f_lineno}] Error checking policy {policy_arn}: {str(e)}")
        return False

def lambda_handler(event, context):
    """
    Main Lambda function handler for processing IAM policy events.
    
    Args:
        event (dict): AWS EventBridge event containing IAM policy changes
        context (LambdaContext): AWS Lambda context object
        
    Returns:
        dict: Response containing any policy violations and actions taken
        
    Description:
        Processes IAM policy-related events from EventBridge:
        - Handles policy attachments and modifications
        - Validates policies against security requirements
        - Removes non-compliant policies
        - Logs all actions and violations
    """
    logger.info(f"[Line {inspect.currentframe().f_lineno}] Processing new event: {json.dumps(event)}")
    try:
        # Extract event details
        detail = event['detail']
        event_name = detail['eventName']
        policy_arn = detail['requestParameters'].get('policyArn')
        logger.info(f"[Line {inspect.currentframe().f_lineno}] Event name: {event_name}, Policy ARN: {policy_arn}")
        
        violations = []
        entity_type = None
        entity_name = None
        policy_name = None
        
        # Determine entity type, name, and policy based on the event
        if event_name == 'CreatePolicy':
            policy_doc = detail['requestParameters']['policyDocument']
            if isinstance(policy_doc, str):
                policy_doc = json.loads(policy_doc)
            if has_restricted_actions(policy_doc):
                policy_arn = detail['responseElements']['policy']['arn']
                logger.warning(f"[Line {inspect.currentframe().f_lineno}] Detected restricted actions in new policy: {policy_arn}")
                try:
                    iam.delete_policy(PolicyArn=policy_arn)
                    logger.info(f"[Line {inspect.currentframe().f_lineno}] Successfully deleted non-compliant policy: {policy_arn}")
                    violations.append(f"Deleted new policy with restricted actions: {policy_arn}")
                except Exception as e:
                    logger.error(f"[Line {inspect.currentframe().f_lineno}] Error deleting policy {policy_arn}: {str(e)}")
                    
        elif event_name == 'CreatePolicyVersion':
            policy_doc = detail['requestParameters']['policyDocument']
            if isinstance(policy_doc, str):
                policy_doc = json.loads(policy_doc)
            if has_restricted_actions(policy_doc):
                policy_arn = detail['requestParameters']['policyArn']
                version_id = detail['responseElements']['policyVersion']['versionId']
                logger.warning(f"[Line {inspect.currentframe().f_lineno}] Detected restricted actions in new policy version: {policy_arn} (version {version_id})")
                try:
                    iam.delete_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=version_id
                    )
                    logger.info(f"[Line {inspect.currentframe().f_lineno}] Successfully deleted non-compliant policy version: {policy_arn} (version {version_id})")
                    violations.append(f"Deleted new policy version with restricted actions: {policy_arn} (version {version_id})")
                except Exception as e:
                    logger.error(f"[Line {inspect.currentframe().f_lineno}] Error deleting policy version {policy_arn} {version_id}: {str(e)}")
                    
        elif event_name == 'AttachUserPolicy':
            entity_type = 'user'
            entity_name = detail['requestParameters']['userName']
        elif event_name == 'AttachGroupPolicy':
            entity_type = 'group'
            entity_name = detail['requestParameters']['groupName']
        elif event_name == 'AttachRolePolicy':
            entity_type = 'role'
            entity_name = detail['requestParameters']['roleName']
        elif event_name == 'PutUserPolicy':
            entity_type = 'user'
            entity_name = detail['requestParameters']['userName']
            policy_name = detail['requestParameters']['policyName']
        elif event_name == 'PutRolePolicy':
            entity_type = 'role'
            entity_name = detail['requestParameters']['roleName']
            policy_name = detail['requestParameters']['policyName']
        elif event_name == 'PutGroupPolicy':
            entity_type = 'group'
            entity_name = detail['requestParameters']['groupName']
            policy_name = detail['requestParameters']['policyName']
        
        # Skip all checks for whitelisted roles
        if entity_type == 'role' and entity_name.lower().startswith('abc-'):
            return {'violations': violations}

        # Check managed policy if this is an attach event
        if policy_arn and check_policy(policy_arn):
            # Detach the restricted policy based on entity type
            if entity_type == 'user':
                iam.detach_user_policy(UserName=entity_name, PolicyArn=policy_arn)
            elif entity_type == 'group':
                iam.detach_group_policy(GroupName=entity_name, PolicyArn=policy_arn)
            elif entity_type == 'role':
                iam.detach_role_policy(RoleName=entity_name, PolicyArn=policy_arn)
            
            violations.append(f"Removed restricted policy {policy_arn} from {entity_type} {entity_name}")
        
        # Check specific inline policy if this is a put event
        if entity_type and entity_name and policy_name:
            inline_violations = check_inline_policies(entity_type, entity_name, policy_name)
            violations.extend(inline_violations)
        
        # Send notification if there were violations
        if violations:
            message = "Policy violations detected:\n" + "\n".join(violations)
            logger.warning(f"Policy violations detected: {violations}")
            sns.publish(
                TopicArn=os.environ['SNS_TOPIC_ARN'],
                Subject='IAM Policy Violation Alert',
                Message=message
            )
            logger.info("SNS notification sent successfully")
        
        response = {
            'statusCode': 200,
            'body': json.dumps({'violations': violations})
        }
        logger.info(f"Lambda execution completed successfully. Response: {json.dumps(response)}")
        return response
        
    except Exception as e:
        error_msg = f"Error in lambda_handler: {str(e)}"
        logger.error(error_msg)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }