"""
AWS IAM Policy Monitor Unit Tests
-------------------------------
Version: v1.0.0-beta.1
Author: Nick the Security Dude
Date: 2024-01-17

Feature: AWS IAM Policy Monitor Unit Tests
  As a developer
  I want to ensure the policy monitor works correctly through unit tests
  So that I can verify all security controls are functioning as expected

  Background:
    Given the policy monitor unit test environment is set up
    
  Scenario: Test restricted action detection
    Given a policy document with restricted IAM actions
    When the policy validation function runs
    Then it should identify the policy as restricted
    And return the appropriate validation result

  Scenario: Test whitelisted role handling
    Given a role name with a whitelisted prefix
    When the role validation function runs
    Then it should identify the role as whitelisted
    And allow the policy to remain attached

  Scenario: Test policy cleanup operations
    Given a list of non-compliant policies
    When the cleanup function executes
    Then it should remove all non-compliant policies
    And log the removal actions

  Scenario: Test policy validation edge cases
    Given policies with special characters and Unicode
    When the normalization and validation functions run
    Then they should handle the special cases correctly
    And maintain consistent validation results

  Scenario: Test actual AWS API interactions
    Given actual AWS IAM service responses
    When the monitor attempts to modify policies
    Then it should correctly handle API responses
    And perform appropriate error handling

License: Creative Commons Attribution-NonCommercial (CC BY-NC)
Copyright (c) 2024 Nick the Security Dude

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

Description: Unit tests for AWS IAM Policy Monitor that validates automatic enforcement of IAM 
policies, including specific tests for restricted actions (iam:*) and non-restricted actions 
(ec2:*) to verify proper handling of policy attachments and restrictions across users, groups,
roles, and standalone policies. Tests validate both attached policies and independent policy
objects to ensure comprehensive policy governance.

Test Coverage:
- Users:
  * Validation of allowed EC2 and ViewOnly inline policies
  * Validation of allowed managed policies
  * Automatic removal of restricted managed and inline policies
  * Prevention of IAM-related inline policies

- Groups:
  * Verification of EC2 and ViewOnly inline policy attachments
  * Validation of allowed managed policy associations
  * Automatic cleanup of restricted managed and inline policies
  * Blocking of IAM-related inline policies

- Roles:
  * Testing of permitted EC2 and ViewOnly inline policies
  * Validation of allowed managed policy attachments
  * Automatic removal of restricted managed and inline policies
  * Prevention of IAM-related inline policy assignments

- Standalone Policies:
  * Testing of restricted action policy automatic removal
  * Verification of non-restricted action policy retention
  * Validation of whitelisted role-specific policies (e.g., CloudFront)
"""

import unittest
import json
import time
import boto3
import policy_monitor
import uuid
import logging
import inspect

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class TestPolicyMonitorExtended(unittest.TestCase):
    """Test suite for the AWS IAM Policy Monitor functionality.
    
    This class contains comprehensive tests for validating the automatic policy monitoring
    and enforcement system. It tests various scenarios including:
    - Allowed policies (EC2-specific and ViewOnlyAccess)
    - Restricted policies (AdministratorAccess and wildcards)
    - Both inline and managed policies
    - Policy enforcement across users, groups, and roles
    """
    
    @classmethod
    def setUpClass(cls):
        """Set up test resources that will be shared across all test methods.
        
        Creates reusable policy documents and initializes AWS IAM client.
        All test resources are prefixed with 'test-' for easy identification.
        """
        # Create IAM client
        cls.iam = boto3.client('iam')
        # Use static names for resources
        cls.test_prefix = "test-static"
        cls.test_user = f"{cls.test_prefix}-user"
        cls.test_role = f"{cls.test_prefix}-role"
        cls.test_group = f"{cls.test_prefix}-group"

        # Create test policies for restricted/non-restricted actions
        cls.test_restricted_policy = f"{cls.test_prefix}-restricted-policy"
        cls.test_nonrestricted_policy = f"{cls.test_prefix}-nonrestricted-policy"
        
        # Create iam_policy_v2 with iam:* action
        cls.iam_policy_v2 = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:*",
                "Resource": "*"
            }]
        }
        
        # Create policy with restricted action (iam:*)
        restricted_policy_doc = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:*",
                "Resource": "*"
            }]
        }
        logging.info(f"[Line {inspect.currentframe().f_lineno}] Creating restricted policy: {cls.test_restricted_policy}")
        cls.iam.create_policy(
            PolicyName=cls.test_restricted_policy,
            PolicyDocument=json.dumps(restricted_policy_doc)
        )
        logging.info(f"[Line {inspect.currentframe().f_lineno}] Successfully created restricted policy: {cls.test_restricted_policy}")
        
        # Create policy with non-restricted action (ec2:*)
        nonrestricted_policy_doc = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "ec2:*",
                "Resource": "*"
            }]
        }
        logging.info(f"[Line {inspect.currentframe().f_lineno}] Creating non-restricted policy: {cls.test_nonrestricted_policy}")
        cls.iam.create_policy(
            PolicyName=cls.test_nonrestricted_policy,
            PolicyDocument=json.dumps(nonrestricted_policy_doc)
        )
        logging.info(f"[Line {inspect.currentframe().f_lineno}] Successfully created non-restricted policy: {cls.test_nonrestricted_policy}")

        # Create whitelisted role
        cls.whitelisted_role_name = "abc-test-role"
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudfront.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        cls.iam.create_role(
            RoleName=cls.whitelisted_role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )
        logging.info(f"[Line {inspect.currentframe().f_lineno}] Created whitelisted role: {cls.whitelisted_role_name}")

        cls.ec2_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["ec2:*"],
                    "Resource": "*"
                }
            ]
        }
        cls.iam_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["iam:passrole"],
                    "Resource": "*"
                }
            ]
        }
        
        # Create the shared resources
        try:
            # Create user
            cls.iam.create_user(UserName=cls.test_user)
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Created test user: {cls.test_user}")
            
            # Create group
            cls.iam.create_group(GroupName=cls.test_group)
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Created test group: {cls.test_group}")
            
            # Create role
            trust_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "ec2.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }
            cls.iam.create_role(
                RoleName=cls.test_role,
                AssumeRolePolicyDocument=json.dumps(trust_policy)
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Created test role: {cls.test_role}")
            
            # Wait for resources to be fully created
            time.sleep(10)
            
        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] Failed to create test resources: {str(e)}")
            raise
    
    def setUp(self):
        # Clean up any leftover policies from previous tests
        try:
            self.iam.delete_user_policy(UserName=self.test_user, PolicyName='test-ec2-inline-policy')
        except self.iam.exceptions.NoSuchEntityException:
            pass
        try:
            self.iam.delete_group_policy(GroupName=self.test_group, PolicyName='test-ec2-inline-policy')
        except self.iam.exceptions.NoSuchEntityException:
            pass
        try:
            self.iam.delete_role_policy(RoleName=self.test_role, PolicyName='test-ec2-inline-policy')
        except self.iam.exceptions.NoSuchEntityException:
            pass

    @classmethod
    def tearDownClass(cls):
        logging.info(f"[Line {inspect.currentframe().f_lineno}] Starting cleanup of test resources")
        # Clean up test policies
        logging.info(f"[Line {inspect.currentframe().f_lineno}] Cleaning up test policies")
        account_id = boto3.client('sts').get_caller_identity()['Account']
        
        # Delete restricted policy
        try:
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Deleting restricted policy: {cls.test_restricted_policy}")
            cls.iam.delete_policy(
                PolicyArn=f'arn:aws:iam::{account_id}:policy/{cls.test_restricted_policy}'
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Successfully deleted restricted policy: {cls.test_restricted_policy}")
        except Exception as e:
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Error (expected) deleting restricted policy {cls.test_restricted_policy}: {str(e)}")

        # Delete non-restricted policy
        try:
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Deleting non-restricted policy: {cls.test_nonrestricted_policy}")
            cls.iam.delete_policy(
                PolicyArn=f'arn:aws:iam::{account_id}:policy/{cls.test_nonrestricted_policy}'
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Successfully deleted non-restricted policy: {cls.test_nonrestricted_policy}")
        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] Error deleting non-restricted policy {cls.test_nonrestricted_policy}: {str(e)}")
        
        # Clean up all inline and attached policies, then delete IAM entities
        try:
            # Clean up whitelisted role
            try:
                logging.info(f"[Line {inspect.currentframe().f_lineno}] Cleaning up whitelisted role: {cls.whitelisted_role_name}")
                attached_policies = cls.iam.list_attached_role_policies(RoleName=cls.whitelisted_role_name)
                for policy in attached_policies['AttachedPolicies']:
                    cls.iam.detach_role_policy(
                        RoleName=cls.whitelisted_role_name,
                        PolicyArn=policy['PolicyArn']
                    )
                cls.iam.delete_role(RoleName=cls.whitelisted_role_name)
                logging.info(f"[Line {inspect.currentframe().f_lineno}] Successfully deleted whitelisted role: {cls.whitelisted_role_name}")
            except Exception as e:
                logging.error(f"[Line {inspect.currentframe().f_lineno}] Error cleaning up whitelisted role: {e}")

            logging.info(f"[Line {inspect.currentframe().f_lineno}] Starting cleanup of user policies")
            try:
                # List and detach all attached policies
                logging.info(f"[Line {inspect.currentframe().f_lineno}] Detaching all policies from user {cls.test_user}")
                policies = cls.iam.list_attached_user_policies(UserName=cls.test_user)
                for policy in policies['AttachedPolicies']:
                    policy_arn = policy['PolicyArn']
                    logging.info(f"[Line {inspect.currentframe().f_lineno}] Detaching policy {policy_arn} from user")
                    cls.iam.detach_user_policy(UserName=cls.test_user, PolicyArn=policy_arn)
                
                # List and delete all inline policies
                logging.info(f"[Line {inspect.currentframe().f_lineno}] Deleting all inline policies from user {cls.test_user}")
                inline_policies = cls.iam.list_user_policies(UserName=cls.test_user)
                for policy_name in inline_policies['PolicyNames']:
                    logging.info(f"[Line {inspect.currentframe().f_lineno}] Deleting inline policy {policy_name} from user")
                    cls.iam.delete_user_policy(UserName=cls.test_user, PolicyName=policy_name)
                
                # Delete the user
                logging.info(f"[Line {inspect.currentframe().f_lineno}] Deleting test user {cls.test_user}")
                cls.iam.delete_user(UserName=cls.test_user)
                logging.info(f"[Line {inspect.currentframe().f_lineno}] Successfully deleted test user {cls.test_user}")
            except cls.iam.exceptions.NoSuchEntityException:
                pass

            # Clean up role
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Starting cleanup of role resources")
            try:
                # List and detach all attached policies
                logging.info(f"[Line {inspect.currentframe().f_lineno}] Detaching all policies from role {cls.test_role}")
                policies = cls.iam.list_attached_role_policies(RoleName=cls.test_role)
                for policy in policies['AttachedPolicies']:
                    policy_arn = policy['PolicyArn']
                    logging.info(f"[Line {inspect.currentframe().f_lineno}] Detaching policy {policy_arn} from role")
                    cls.iam.detach_role_policy(RoleName=cls.test_role, PolicyArn=policy_arn)
                
                # List and delete all inline policies
                inline_policies = cls.iam.list_role_policies(RoleName=cls.test_role)
                for policy_name in inline_policies['PolicyNames']:
                    cls.iam.delete_role_policy(RoleName=cls.test_role, PolicyName=policy_name)
                
                # Delete the role
                cls.iam.delete_role(RoleName=cls.test_role)
            except cls.iam.exceptions.NoSuchEntityException:
                pass

            # Clean up group
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Starting cleanup of group resources")
            try:
                # List and detach all attached policies
                logging.info(f"[Line {inspect.currentframe().f_lineno}] Detaching all policies from group {cls.test_group}")
                policies = cls.iam.list_attached_group_policies(GroupName=cls.test_group)
                for policy in policies['AttachedPolicies']:
                    policy_arn = policy['PolicyArn']
                    logging.info(f"[Line {inspect.currentframe().f_lineno}] Detaching policy {policy_arn} from group")
                    cls.iam.detach_group_policy(GroupName=cls.test_group, PolicyArn=policy_arn)
                
                # List and delete all inline policies
                logging.info(f"[Line {inspect.currentframe().f_lineno}] Deleting all inline policies from group {cls.test_group}")
                inline_policies = cls.iam.list_group_policies(GroupName=cls.test_group)
                for policy_name in inline_policies['PolicyNames']:
                    logging.info(f"[Line {inspect.currentframe().f_lineno}] Deleting inline policy {policy_name} from group")
                    cls.iam.delete_group_policy(GroupName=cls.test_group, PolicyName=policy_name)
                
                # Delete the group
                logging.info(f"[Line {inspect.currentframe().f_lineno}] Deleting test group {cls.test_group}")
                cls.iam.delete_group(GroupName=cls.test_group)
                logging.info(f"[Line {inspect.currentframe().f_lineno}] Successfully deleted test group {cls.test_group}")
            except cls.iam.exceptions.NoSuchEntityException:
                pass
        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] Error during cleanup: {str(e)}")

    def test_user_ec2_inline_policy_allowed(self):
        """Verify that an inline policy with EC2-specific permissions is allowed on users.
        
        Test Steps:
        1. Create and attach an inline policy with ec2:* permissions to test user
        2. Wait 30 seconds to ensure policy monitor has time to evaluate
        3. Verify the policy remains attached (not removed by monitor)
        
        Expected Outcome:
        - The EC2 inline policy should remain attached as it's in the allowed policy list
        - The policy should be found in the user's policy list after the wait period
        """
        try:
            # Create an inline policy with ec2:* permissions
            self.iam.put_user_policy(
                UserName=self.test_user,
                PolicyName='test-ec2-inline-policy',
                PolicyDocument=json.dumps(self.ec2_policy)
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Added EC2 inline policy to user")
            
            # Wait to ensure the policy would have been removed if it was restricted
            time.sleep(20)
            
            # Verify the policy still exists
            inline_policies = self.iam.list_user_policies(UserName=self.test_user)
            self.assertEqual(len(inline_policies['PolicyNames']), 1, "EC2 inline policy was incorrectly removed")
            self.assertEqual(inline_policies['PolicyNames'][0], 'test-ec2-inline-policy')
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: EC2 inline policy was correctly retained")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] User EC2 policy test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")

    def test_user_viewonly_managed_policy_allowed(self):
        """Verify that ViewOnlyAccess managed policy is allowed to remain attached to users.
        
        Test Steps:
        1. Attach AWS managed ViewOnlyAccess policy to test user
        2. Wait 30 seconds for policy monitor evaluation period
        3. Verify the policy remains attached as it's in the allowed list
        
        Expected Outcome:
        - ViewOnlyAccess policy should remain attached to the user
        - Demonstrates that read-only policies are correctly allowed
        - Shows managed policy handling works as expected
        """
        try:
            
            # Attach ViewOnlyAccess managed policy
            self.iam.attach_user_policy(
                UserName=self.test_user,
                PolicyArn='arn:aws:iam::aws:policy/job-function/ViewOnlyAccess'
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Attached ViewOnlyAccess policy to user")
            
            # Wait to ensure the policy would have been removed if it was restricted
            time.sleep(20)
            
            # Verify the policy still exists
            attached_policies = self.iam.list_attached_user_policies(UserName=self.test_user)
            self.assertEqual(len(attached_policies['AttachedPolicies']), 1, "ViewOnlyAccess policy was incorrectly removed")
            self.assertEqual(attached_policies['AttachedPolicies'][0]['PolicyArn'], 
                           'arn:aws:iam::aws:policy/job-function/ViewOnlyAccess')
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: ViewOnlyAccess policy was correctly retained")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] User ViewOnlyAccess policy test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")

    def test_group_ec2_inline_policy_allowed(self):
        """Test group inline policy with EC2 permissions is allowed."""
        try:
            # Create an inline policy with ec2:* permissions
            self.iam.put_group_policy(
                GroupName=self.test_group,
                PolicyName='test-ec2-inline-policy',
                PolicyDocument=json.dumps(self.ec2_policy)
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Added EC2 inline policy to group")
            
            # Wait to ensure the policy would have been removed if it was restricted
            time.sleep(20)
            
            # Verify the policy still exists
            inline_policies = self.iam.list_group_policies(GroupName=self.test_group)
            self.assertEqual(len(inline_policies['PolicyNames']), 1, "EC2 inline policy was incorrectly removed")
            self.assertEqual(inline_policies['PolicyNames'][0], 'test-ec2-inline-policy')
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: EC2 inline policy was correctly retained")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] Group EC2 policy test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")

    def test_group_viewonly_managed_policy_allowed(self):
        """Test group with ViewOnlyAccess managed policy is allowed."""
        try:
            
            # Attach ViewOnlyAccess managed policy
            self.iam.attach_group_policy(
                GroupName=self.test_group,
                PolicyArn='arn:aws:iam::aws:policy/job-function/ViewOnlyAccess'
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Attached ViewOnlyAccess policy to group")
            
            # Wait to ensure the policy would have been removed if it was restricted
            time.sleep(20)
            
            # Verify the policy still exists
            attached_policies = self.iam.list_attached_group_policies(GroupName=self.test_group)
            self.assertEqual(len(attached_policies['AttachedPolicies']), 1, "ViewOnlyAccess policy was incorrectly removed")
            self.assertEqual(attached_policies['AttachedPolicies'][0]['PolicyArn'], 
                           'arn:aws:iam::aws:policy/job-function/ViewOnlyAccess')
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: ViewOnlyAccess policy was correctly retained")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] Group ViewOnlyAccess policy test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")

    def test_role_ec2_inline_policy_allowed(self):
        """Test role inline policy with EC2 permissions is allowed."""
        try:
            # Create an inline policy with ec2:* permissions
            self.iam.put_role_policy(
                RoleName=self.test_role,
                PolicyName='test-ec2-inline-policy',
                PolicyDocument=json.dumps(self.ec2_policy)
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Added EC2 inline policy to role")
            
            # Wait to ensure the policy would have been removed if it was restricted
            time.sleep(20)
            
            # Verify the policy still exists
            inline_policies = self.iam.list_role_policies(RoleName=self.test_role)
            self.assertEqual(len(inline_policies['PolicyNames']), 1, "EC2 inline policy was incorrectly removed")
            self.assertEqual(inline_policies['PolicyNames'][0], 'test-ec2-inline-policy')
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: EC2 inline policy was correctly retained")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] Role EC2 policy test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")

    def test_role_viewonly_managed_policy_allowed(self):
        """Test role with ViewOnlyAccess managed policy is allowed."""
        try:
            
            # Attach ViewOnlyAccess managed policy
            self.iam.attach_role_policy(
                RoleName=self.test_role,
                PolicyArn='arn:aws:iam::aws:policy/job-function/ViewOnlyAccess'
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Attached ViewOnlyAccess policy to role")
            
            # Wait to ensure the policy would have been removed if it was restricted
            time.sleep(20)
            
            # Verify the policy still exists
            attached_policies = self.iam.list_attached_role_policies(RoleName=self.test_role)
            self.assertEqual(len(attached_policies['AttachedPolicies']), 1, "ViewOnlyAccess policy was incorrectly removed")
            self.assertEqual(attached_policies['AttachedPolicies'][0]['PolicyArn'], 
                           'arn:aws:iam::aws:policy/job-function/ViewOnlyAccess')
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: ViewOnlyAccess policy was correctly retained")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] Role ViewOnlyAccess policy test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")

    def test_user_restricted_managed_policy_auto_removal(self):
        """Verify automatic removal of restricted managed policy (AdministratorAccess) from users.
        
        Test Steps:
        1. Attach AdministratorAccess managed policy to test user
        2. Wait 15 seconds for policy monitor to detect and evaluate
        3. Verify the restricted policy is automatically removed
        
        Expected Outcome:
        - The AdministratorAccess policy should be removed automatically
        - No managed policies should be attached to the user after removal
        - Demonstrates policy monitor's automatic enforcement capability
        """
        try:
            # Attach a restricted managed policy
            self.iam.attach_user_policy(
                UserName=self.test_user,
                PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Attached AdministratorAccess managed policy to user")
            
            # Wait to allow time for the automatic removal
            time.sleep(10)
            
            # Verify the policy has been removed
            attached_policies = self.iam.list_attached_user_policies(UserName=self.test_user)
            self.assertEqual(len(attached_policies['AttachedPolicies']), 0, "Restricted managed policy was not automatically removed")
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: Restricted managed policy was automatically removed")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] User restricted policy test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")

    def test_group_restricted_managed_policy_auto_removal(self):
        """Verify automatic removal of restricted managed policy (AdministratorAccess) from groups.
        
        Test Steps:
        1. Attach AdministratorAccess managed policy to test group
        2. Wait 15 seconds for policy monitor to detect and evaluate
        3. Verify the restricted policy is automatically removed
        
        Expected Outcome:
        - The AdministratorAccess policy should be removed automatically
        - No managed policies should be attached to the group after removal
        - Shows policy enforcement works consistently across IAM resource types
        """
        try:
            # Attach a restricted managed policy
            self.iam.attach_group_policy(
                GroupName=self.test_group,
                PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Attached AdministratorAccess managed policy to group")
            
            # Wait to allow time for the automatic removal
            time.sleep(10)
            
            # Verify the policy has been removed
            attached_policies = self.iam.list_attached_group_policies(GroupName=self.test_group)
            self.assertEqual(len(attached_policies['AttachedPolicies']), 0, "Restricted managed policy was not automatically removed")
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: Restricted managed policy was automatically removed")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] Group restricted policy test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")

    def test_user_restricted_inline_policy_auto_removal(self):
        """Test that restricted inline policy with '*' action is automatically removed from user."""
        try:
            # Create a policy with "*" action which should be restricted
            restricted_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*"
                    }
                ]
            }
            
            # Add the restricted inline policy
            self.iam.put_user_policy(
                UserName=self.test_user,
                PolicyName='test-restricted-inline-policy',
                PolicyDocument=json.dumps(restricted_policy)
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Added restricted inline policy to user")
            
            # Wait to allow time for the automatic removal
            time.sleep(10)
            
            # Verify the policy has been removed
            inline_policies = self.iam.list_user_policies(UserName=self.test_user)
            self.assertEqual(len(inline_policies['PolicyNames']), 0, "Restricted inline policy was not automatically removed")
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: Restricted inline policy was automatically removed")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] User restricted inline policy test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")

    def test_group_restricted_inline_policy_auto_removal(self):
        """Test that restricted inline policy with '*' action is automatically removed from group."""
        try:
            # Create a policy with "*" action which should be restricted
            restricted_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*"
                    }
                ]
            }
            
            # Add the restricted inline policy
            self.iam.put_group_policy(
                GroupName=self.test_group,
                PolicyName='test-restricted-inline-policy',
                PolicyDocument=json.dumps(restricted_policy)
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Added restricted inline policy to group")
            
            # Wait to allow time for the automatic removal
            time.sleep(10)
            
            # Verify the policy has been removed
            inline_policies = self.iam.list_group_policies(GroupName=self.test_group)
            self.assertEqual(len(inline_policies['PolicyNames']), 0, "Restricted inline policy was not automatically removed")
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: Restricted inline policy was automatically removed")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] Group restricted inline policy test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")

    def test_role_restricted_inline_policy_auto_removal(self):
        """Verify automatic removal of restricted inline policies with wildcard actions from roles.
        
        Test Steps:
        1. Create and attach an inline policy with "*" action to test role
        2. Wait 15 seconds for policy monitor detection
        3. Verify the restricted policy is automatically removed
        
        Expected Outcome:
        - The wildcard policy should be removed automatically
        - Demonstrates that policy restrictions work consistently across roles
        - Shows proper handling of dangerous wildcard permissions
        """
        try:
            # Create a policy with "*" action which should be restricted
            restricted_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*"
                    }
                ]
            }
            
            # Add the restricted inline policy
            self.iam.put_role_policy(
                RoleName=self.test_role,
                PolicyName='test-restricted-inline-policy',
                PolicyDocument=json.dumps(restricted_policy)
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Added restricted inline policy to role")
            
            # Wait to allow time for the automatic removal
            time.sleep(10)
            
            # Verify the policy has been removed
            inline_policies = self.iam.list_role_policies(RoleName=self.test_role)
            self.assertEqual(len(inline_policies['PolicyNames']), 0, "Restricted inline policy was not automatically removed")
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: Restricted inline policy was automatically removed")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] Role restricted inline policy test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")

    def test_user_iam_inline_policy_not_allowed(self):
        """Verify automatic removal of IAM-specific inline policies from users.
        
        Test Steps:
        1. Create and attach an inline policy with iam:* permissions to test user
        2. Wait 15 seconds for policy monitor to detect and evaluate
        3. Verify the IAM policy is automatically removed
        
        Expected Outcome:
        - The IAM inline policy should be removed automatically
        - No IAM-related policies should remain attached to the user
        - Demonstrates prevention of privilege escalation via IAM permissions
        """
        try:
            # Add the IAM inline policy
            self.iam.put_user_policy(
                UserName=self.test_user,
                PolicyName='test-iam-inline-policy',
                PolicyDocument=json.dumps(self.iam_policy)
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Added IAM inline policy to user")
            
            # Wait to allow time for the automatic removal
            time.sleep(10)
            
            # Verify the policy has been removed
            inline_policies = self.iam.list_user_policies(UserName=self.test_user)
            self.assertEqual(len(inline_policies['PolicyNames']), 0, "IAM inline policy was not automatically removed")
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: IAM inline policy was automatically removed")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] User IAM inline policy test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")

    def test_group_iam_inline_policy_not_allowed(self):
        """Verify automatic removal of IAM-specific inline policies from groups.
        
        Test Steps:
        1. Create and attach an inline policy with iam:* permissions to test group
        2. Wait 15 seconds for policy monitor to detect and evaluate
        3. Verify the IAM policy is automatically removed
        
        Expected Outcome:
        - The IAM inline policy should be removed automatically
        - No IAM-related policies should remain attached to the group
        - Shows consistent IAM permission restrictions across resource types
        """
        try:
            # Add the IAM inline policy
            self.iam.put_group_policy(
                GroupName=self.test_group,
                PolicyName='test-iam-inline-policy',
                PolicyDocument=json.dumps(self.iam_policy)
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Added IAM inline policy to group")
            
            # Wait to allow time for the automatic removal
            time.sleep(10)
            
            # Verify the policy has been removed
            inline_policies = self.iam.list_group_policies(GroupName=self.test_group)
            self.assertEqual(len(inline_policies['PolicyNames']), 0, "IAM inline policy was not automatically removed")
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: IAM inline policy was automatically removed")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] Group IAM inline policy test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")

    def test_role_iam_inline_policy_not_allowed(self):
        """Verify automatic removal of IAM-specific inline policies from roles.
        
        Test Steps:
        1. Create and attach an inline policy with iam:* permissions to test role
        2. Wait 15 seconds for policy monitor to detect and evaluate
        3. Verify the IAM policy is automatically removed
        
        Expected Outcome:
        - The IAM inline policy should be removed automatically
        - No IAM-related policies should remain attached to the role
        - Demonstrates consistent IAM permission restrictions across all resource types
        """
        try:
            # Add the IAM inline policy
            self.iam.put_role_policy(
                RoleName=self.test_role,
                PolicyName='test-iam-inline-policy',
                PolicyDocument=json.dumps(self.iam_policy)
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Added IAM inline policy to role")
            
            # Wait to allow time for the automatic removal
            time.sleep(10)
            
            # Verify the policy has been removed
            inline_policies = self.iam.list_role_policies(RoleName=self.test_role)
            self.assertEqual(len(inline_policies['PolicyNames']), 0, "IAM inline policy was not automatically removed")
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: IAM inline policy was automatically removed")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] Role IAM inline policy test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")

    def test_user_iam_inline_policy_v2_not_allowed(self):
        """Verify automatic removal of IAM-specific inline policy v2 from users.
        
        Test Steps:
        1. Create and attach an inline policy v2 with iam:* permissions to test user
        2. Wait 15 seconds for policy monitor to detect and evaluate
        3. Verify the IAM policy is automatically removed
        
        Expected Outcome:
        - The IAM inline policy v2 should be removed automatically
        - No IAM-related policies should remain attached to the user
        - Demonstrates prevention of privilege escalation via IAM permissions
        """
        try:
            # Add the IAM inline policy v2
            self.iam.put_user_policy(
                UserName=self.test_user,
                PolicyName='test-iam-inline-policy-v2',
                PolicyDocument=json.dumps(self.iam_policy_v2)
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Added IAM inline policy v2 to user")
            
            # Wait to allow time for the automatic removal
            time.sleep(10)
            
            # Verify the policy has been removed
            inline_policies = self.iam.list_user_policies(UserName=self.test_user)
            self.assertEqual(len(inline_policies['PolicyNames']), 0, "IAM inline policy v2 was not automatically removed")
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: IAM inline policy v2 was automatically removed")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] User IAM inline policy v2 test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")

    def test_group_iam_inline_policy_v2_not_allowed(self):
        """Verify automatic removal of IAM-specific inline policy v2 from groups.
        
        Test Steps:
        1. Create and attach an inline policy v2 with iam:* permissions to test group
        2. Wait 15 seconds for policy monitor to detect and evaluate
        3. Verify the IAM policy is automatically removed
        
        Expected Outcome:
        - The IAM inline policy v2 should be removed automatically
        - No IAM-related policies should remain attached to the group
        - Shows consistent IAM permission restrictions across resource types
        """
        try:
            # Add the IAM inline policy v2
            self.iam.put_group_policy(
                GroupName=self.test_group,
                PolicyName='test-iam-inline-policy-v2',
                PolicyDocument=json.dumps(self.iam_policy_v2)
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Added IAM inline policy v2 to group")
            
            # Wait to allow time for the automatic removal
            time.sleep(10)
            
            # Verify the policy has been removed
            inline_policies = self.iam.list_group_policies(GroupName=self.test_group)
            self.assertEqual(len(inline_policies['PolicyNames']), 0, "IAM inline policy v2 was not automatically removed")
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: IAM inline policy v2 was automatically removed")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] Group IAM inline policy v2 test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")

    def test_role_iam_inline_policy_v2_not_allowed(self):
        """Verify automatic removal of IAM-specific inline policy v2 from roles.
        
        Test Steps:
        1. Create and attach an inline policy v2 with iam:* permissions to test role
        2. Wait 15 seconds for policy monitor to detect and evaluate
        3. Verify the IAM policy is automatically removed
        
        Expected Outcome:
        - The IAM inline policy v2 should be removed automatically
        - No IAM-related policies should remain attached to the role
        - Demonstrates consistent IAM permission restrictions across all resource types
        """
        try:
            # Add the IAM inline policy v2
            self.iam.put_role_policy(
                RoleName=self.test_role,
                PolicyName='test-iam-inline-policy-v2',
                PolicyDocument=json.dumps(self.iam_policy_v2)
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Added IAM inline policy v2 to role")
            
            # Wait to allow time for the automatic removal
            time.sleep(10)
            
            # Verify the policy has been removed
            inline_policies = self.iam.list_role_policies(RoleName=self.test_role)
            self.assertEqual(len(inline_policies['PolicyNames']), 0, "IAM inline policy v2 was not automatically removed")
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: IAM inline policy v2 was automatically removed")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] Role IAM inline policy v2 test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")

    def test_whitelisted_role_cloudfront_policy_allowed(self):
        """Test that CloudFrontFullAccess managed policy is allowed on whitelisted role.
        
        Test Steps:
        1. Use whitelisted role created in setUpClass (prefix 'abc-')
        2. Attach CloudFrontFullAccess managed policy
        3. Wait 30 seconds for policy monitor evaluation
        4. Verify the policy remains attached (not removed)
        
        Expected Outcome:
        - CloudFrontFullAccess policy should remain attached to whitelisted role
        - Demonstrates whitelisted role policy exemption works
        """
        try:
            # Attach CloudFrontFullAccess managed policy to pre-created role
            self.iam.attach_role_policy(
                RoleName=self.whitelisted_role_name,
                PolicyArn='arn:aws:iam::aws:policy/CloudFrontFullAccess'
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Attached CloudFrontFullAccess policy to whitelisted role")
            
            # Wait to verify policy is not removed
            time.sleep(20)
            
            # Verify the policy still exists
            attached_policies = self.iam.list_attached_role_policies(RoleName=self.whitelisted_role_name)
            self.assertEqual(len(attached_policies['AttachedPolicies']), 1, "CloudFrontFullAccess policy was incorrectly removed")
            self.assertEqual(attached_policies['AttachedPolicies'][0]['PolicyArn'], 
                           'arn:aws:iam::aws:policy/CloudFrontFullAccess')
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: CloudFrontFullAccess policy was correctly retained on whitelisted role")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] Whitelisted role CloudFrontFullAccess policy test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")
        
    def test_restricted_action_policy_auto_removal(self):
        """Test automatic removal of a policy containing restricted actions (iam:*).
        
        Test Steps:
        1. Verify the policy with restricted action has been automatically removed by automation
        
        Expected Outcome:
        - The policy with iam:* action should not exist
        - Demonstrates policy monitor's automation has successfully removed restricted policies
        """
        try:
            account_id = boto3.client('sts').get_caller_identity()['Account']
            policy_arn = f'arn:aws:iam::{account_id}:policy/{self.test_restricted_policy}'
            
            # Verify the policy does not exist
            try:
                self.iam.get_policy(PolicyArn=policy_arn)
                self.fail("Policy with restricted action still exists")
            except self.iam.exceptions.NoSuchEntityException:
                logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: Policy with restricted action was automatically removed")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] Restricted action policy test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")

    def test_nonrestricted_action_policy_retention(self):
        """Test retention of a policy containing non-restricted actions (ec2:*).
        
        Test Steps:
        1. Verify the previously created non-restricted policy still exists
        2. Wait 15 seconds for policy monitor to evaluate
        3. Verify the policy with non-restricted action is retained
        
        Expected Outcome:
        - The policy with ec2:* action should still exist
        - Demonstrates policy monitor's ability to identify and retain non-restricted policies
        """
        try:
            account_id = boto3.client('sts').get_caller_identity()['Account']
            policy_arn = f'arn:aws:iam::{account_id}:policy/{self.test_nonrestricted_policy}'
            
            # Wait to allow time for potential (incorrect) removal
            time.sleep(10)
            
            # Verify the policy still exists
            try:
                policy = self.iam.get_policy(PolicyArn=policy_arn)
                self.assertIsNotNone(policy['Policy'],
                                 "Policy with non-restricted action was incorrectly removed")
                logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: Policy with non-restricted action was correctly retained")
            except self.iam.exceptions.NoSuchEntityException:
                self.fail("Policy with non-restricted action was incorrectly removed")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] Non-restricted action policy test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")

    def test_role_restricted_managed_policy_auto_removal(self):
        """Test that restricted managed policy (AdministratorAccess) is automatically removed from role."""
        try:
            # Attach a restricted managed policy
            self.iam.attach_role_policy(
                RoleName=self.test_role,
                PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
            )
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Attached AdministratorAccess managed policy to role")
            
            # Wait to allow time for the automatic removal
            time.sleep(10)
            
            # Verify the policy has been removed
            attached_policies = self.iam.list_attached_role_policies(RoleName=self.test_role)
            self.assertEqual(len(attached_policies['AttachedPolicies']), 0, "Restricted managed policy was not automatically removed")
            logging.info(f"[Line {inspect.currentframe().f_lineno}] Test passed: Restricted managed policy was automatically removed")

        except Exception as e:
            logging.error(f"[Line {inspect.currentframe().f_lineno}] Role restricted policy test failed: {str(e)}")
            self.fail(f"Test failed: {str(e)}")

if __name__ == '__main__':
    unittest.main()