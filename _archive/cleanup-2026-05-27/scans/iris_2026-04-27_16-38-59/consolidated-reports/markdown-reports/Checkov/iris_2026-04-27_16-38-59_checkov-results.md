<!-- classification: INTERNAL USE ONLY -->
> **INTERNAL USE ONLY**

# Checkov Security Report

**Scan Type:** iris_2026-04-27_16-38-59_checkov-results  
**Generated:** Mon Apr 27 17:08:51 UTC 2026  

## Summary

**Total Items:** 6

```json
[
  {
    "check_type": "cloudformation",
    "results": {
      "passed_checks": [
        {
          "check_id": "CKV_AWS_24",
          "bc_check_id": null,
          "check_name": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
          "check_result": {
            "result": "PASSED",
            "evaluated_keys": [
              "Properties/SecurityGroupIngress"
            ]
          },
          "code_block": [
            [
              77,
              "  AlbSecurityGroup:\n"
            ],
            [
              78,
              "    Type: AWS::EC2::SecurityGroup\n"
            ],
            [
              79,
              "    Properties:\n"
            ],
            [
              80,
              "      GroupDescription: \"Allow 443 to ALB\"\n"
            ],
            [
              81,
              "      VpcId: !Ref DefaultVPC\n"
            ],
            [
              82,
              "      SecurityGroupIngress:\n"
            ],
            [
              83,
              "        - IpProtocol: tcp\n"
            ],
            [
              84,
              "          FromPort: 443\n"
            ],
            [
              85,
              "          ToPort: 443\n"
            ],
            [
              86,
              "          CidrIp: 0.0.0.0/0\n"
            ],
            [
              87,
              "      Tags:\n"
            ],
            [
              88,
              "        - Key: Name\n"
            ],
            [
              89,
              "          Value: !Sub \"iris-${AWS::StackName}-alb-sg\"\n"
            ]
          ],
          "file_path": "/deploy/aws/iris-stack.yaml",
          "file_abs_path": "/workspace/deploy/aws/iris-stack.yaml",
          "repo_file_path": "/workspace/deploy/aws/iris-stack.yaml",
          "file_line_range": [
            77,
            89
          ],
          "resource": "AWS::EC2::SecurityGroup.AlbSecurityGroup",
    
```


---

> **INTERNAL USE ONLY**
