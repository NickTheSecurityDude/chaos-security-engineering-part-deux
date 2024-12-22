# AWS IAM Policy Monitor

This project provides an automated solution for monitoring and enforcing AWS IAM policy compliance across your AWS organization. It helps prevent unauthorized privilege escalation and maintains security best practices by automatically detecting and removing non-compliant IAM policies.

## Overview

The IAM Policy Monitor is a serverless solution that:
- Continuously monitors IAM policy changes in your AWS account
- Automatically detects non-compliant policies (both inline and managed)
- Removes restricted actions and unauthorized policy attachments
- Notifies administrators about policy violations
- Supports monitoring of IAM users, groups, and roles

## Features

- Real-time monitoring of IAM policy changes via CloudWatch Events
- Automatic removal of restricted IAM actions
- Support for both inline and managed policies
- Customizable policy restrictions
- SNS notifications for policy violations
- Comprehensive unit testing suite
- CloudFormation templates for easy deployment

## Architecture

The solution consists of:
1. A Lambda function that processes IAM policy changes
2. CloudWatch Events rule to trigger the function
3. SNS topic for notifications
4. IAM roles and policies for necessary permissions
5. S3 bucket for storing logs and artifacts

## Prerequisites

- AWS Account
- AWS CLI installed and configured
- Python 3.x
- Appropriate IAM permissions to deploy CloudFormation stacks

## Installation

1. Clone this repository
2. Deploy the S3 bucket for automation:
   ```bash
   aws cloudformation deploy --template-file automation-bucket-template.yaml --stack-name policy-monitor-bucket
   ```
3. Deploy the main security automation stack:
   ```bash
   aws cloudformation deploy --template-file security_automation_template.yaml --stack-name policy-monitor
   ```

## Configuration

The solution can be customized by modifying the following:
- Restricted actions list in the Lambda function
- SNS topic subscribers
- CloudWatch Events rule schedule
- IAM role permissions

## Testing

The project includes a comprehensive test suite. To run the tests:

```
python -m unittest unittest_policy_monitor.py
```

## Disclaimer

This software is provided "as is" and any expressed or implied warranties, including, but not limited to, the implied warranties of merchantability and fitness for a particular purpose are disclaimed. In no event shall the authors or copyright holders be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, procurement of substitute goods or services; loss of use, data, or profits; or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this software, even if advised of the possibility of such damage.

## License

This work is licensed under the Creative Commons Attribution-NonCommercial (CC BY-NC) license.

You are free to:
- Share — copy and redistribute the material in any medium or format
- Adapt — remix, transform, and build upon the material

Under the following terms:
- Attribution — You must give appropriate credit, provide a link to the license, and indicate if changes were made.
- NonCommercial — You may not use the material for commercial purposes.

For more information about the license, visit: https://creativecommons.org/licenses/by-nc/4.0/