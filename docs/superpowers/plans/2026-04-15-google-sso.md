# Google SSO for Bedrock Auth Stack — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Google Workspace as a supported OIDC identity provider for the Bedrock auth stack, with enforced hosted-domain restriction via the `hd` claim.

**Architecture:** New CloudFormation template mirrors `bedrock-auth-okta.yaml` exactly, replacing Okta-specific parameters with `GoogleClientId` and `HostedDomain`. Four targeted Python edits wire up auto-detection, a wizard prompt, and deploy dispatch. No existing IdP paths are modified.

**Tech Stack:** Python 3.10+, AWS CloudFormation (IAM OIDC Provider, IAM Roles, Cognito Identity Pool), Cleo CLI framework, questionary, pytest

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `deployment/infrastructure/bedrock-auth-google.yaml` | **Create** | Google OIDC CloudFormation stack |
| `source/claude_code_with_bedrock/config.py` | **Modify** | Add `google_hosted_domain` field; add `accounts.google.com` detection |
| `source/claude_code_with_bedrock/cli/commands/init.py` | **Modify** | Add Google detection + hosted domain wizard prompt + save to profile |
| `source/claude_code_with_bedrock/cli/commands/deploy.py` | **Modify** | Add `"google"` to `template_map`; add Google params branch |
| `source/tests/test_config.py` | **Modify** | Tests for `google_hosted_domain` field and detection |
| `source/tests/test_url_validation_security.py` | **Modify** | Tests for Google domain detection |
| `source/tests/cli/commands/test_deploy_quota.py` | **Modify** | Test Google template dispatch |

---

## Task 1: CloudFormation Template

**Files:**
- Create: `deployment/infrastructure/bedrock-auth-google.yaml`

There are no unit tests for CloudFormation YAML — validation happens via `cfn-lint` (run in pre-commit). Write the template, lint it, commit.

- [ ] **Step 1: Create `bedrock-auth-google.yaml`**

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Claude Code with Bedrock - Google Workspace Authentication Stack'

Parameters:
  FederationType:
    Type: String
    Default: direct
    AllowedValues:
      - direct
      - cognito
    Description: Authentication mode - Direct IAM or Cognito Identity Pool

  GoogleClientId:
    Type: String
    Description: OAuth 2.0 client ID from Google Cloud Console
    AllowedPattern: '^[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com$'
    ConstraintDescription: Must be a valid Google OAuth client ID (ends in .apps.googleusercontent.com)

  HostedDomain:
    Type: String
    Description: Google Workspace domain to restrict access to (e.g., yourcompany.com)
    AllowedPattern: '^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}$'
    ConstraintDescription: Must be a valid domain name (e.g., yourcompany.com)

  IdentityPoolName:
    Type: String
    Default: claude-code-google
    Description: Name for the Cognito Identity Pool (used in cognito mode)
    AllowedPattern: '^[\w\s+=,.@-]+$'
    MaxLength: 128

  FederatedRoleName:
    Type: String
    Default: BedrockGoogleFederatedRole
    Description: Name for the IAM role used for federation
    AllowedPattern: '^[a-zA-Z][a-zA-Z0-9-_]*$'
    MaxLength: 64

  AllowedBedrockRegions:
    Type: CommaDelimitedList
    Default: 'us-east-1,us-west-2'
    Description: Comma-delimited list of AWS regions where Bedrock access is allowed

  EnableMonitoring:
    Type: String
    Default: 'true'
    AllowedValues:
      - 'true'
      - 'false'
    Description: Enable CloudWatch monitoring for Bedrock usage

Conditions:
  UseDirectIAM: !Equals [!Ref FederationType, direct]
  UseCognitoIdentity: !Equals [!Ref FederationType, cognito]
  MonitoringEnabled: !Equals [!Ref EnableMonitoring, 'true']
  # Partition-aware conditions for Cognito Identity service principals
  IsGovCloudWest: !Equals [!Ref 'AWS::Region', 'us-gov-west-1']
  IsGovCloudEast: !Equals [!Ref 'AWS::Region', 'us-gov-east-1']
  IsGovCloud: !Or [!Condition IsGovCloudWest, !Condition IsGovCloudEast]

Resources:
  # ===============================================
  # OIDC Provider for Google
  # ===============================================

  GoogleOIDCProvider:
    Type: AWS::IAM::OIDCProvider
    Properties:
      Url: 'https://accounts.google.com'
      ClientIdList:
        - !Ref GoogleClientId
      ThumbprintList:
        - 08745487e891c19e3078c1f2a07e452950ef36f6  # Google Trust Services root CA
      Tags:
        - Key: Purpose
          Value: Claude Code Google Workspace Authentication
        - Key: Provider
          Value: Google

  # ===============================================
  # Bedrock Access Policy (Shared)
  # ===============================================

  BedrockAccessPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      Description: Policy for accessing Bedrock services
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowBedrockInvokeRegional
            Effect: Allow
            Action:
              - 'bedrock:InvokeModel'
              - 'bedrock:InvokeModelWithResponseStream'
              - 'bedrock-runtime:InvokeModel'
              - 'bedrock-runtime:InvokeModelWithResponseStream'
              - 'bedrock-runtime:ConverseStream'
              - 'bedrock-runtime:Converse'
            Resource:
              - !Sub 'arn:${AWS::Partition}:bedrock:*::foundation-model/*'
              - !Sub 'arn:${AWS::Partition}:bedrock:*:*:inference-profile/*'
            Condition:
              StringEquals:
                'aws:RequestedRegion': !Ref AllowedBedrockRegions
          - Sid: AllowBedrockInvokeGlobal
            Effect: Allow
            Action:
              - 'bedrock:InvokeModel'
              - 'bedrock:InvokeModelWithResponseStream'
              - 'bedrock-runtime:InvokeModel'
              - 'bedrock-runtime:InvokeModelWithResponseStream'
              - 'bedrock-runtime:ConverseStream'
              - 'bedrock-runtime:Converse'
            Resource:
              - !Sub 'arn:${AWS::Partition}:bedrock:::foundation-model/*'
          - Sid: AllowBedrockListRegional
            Effect: Allow
            Action:
              - 'bedrock:ListFoundationModels'
              - 'bedrock:GetFoundationModel'
              - 'bedrock:GetFoundationModelAvailability'
              - 'bedrock:ListInferenceProfiles'
              - 'bedrock:GetInferenceProfile'
            Resource: '*'
            Condition:
              StringEquals:
                'aws:RequestedRegion': !Ref AllowedBedrockRegions
          - Sid: AllowBedrockListGlobal
            Effect: Allow
            Action:
              - 'bedrock:ListFoundationModels'
              - 'bedrock:GetFoundationModel'
              - 'bedrock:GetFoundationModelAvailability'
              - 'bedrock:ListInferenceProfiles'
              - 'bedrock:GetInferenceProfile'
            Resource: '*'
          - !If
            - MonitoringEnabled
            - Sid: AllowCloudWatchMetrics
              Effect: Allow
              Action:
                - 'cloudwatch:PutMetricData'
              Resource: '*'
              Condition:
                StringEquals:
                  'cloudwatch:namespace':
                    - 'ClaudeCode/Bedrock/Usage'
                    - 'AWS/Bedrock'
            - !Ref 'AWS::NoValue'

  # ===============================================
  # Direct IAM Resources (when FederationType=direct)
  # ===============================================

  DirectIAMRole:
    Type: AWS::IAM::Role
    Condition: UseDirectIAM
    Properties:
      RoleName: !Ref FederatedRoleName
      Description: Direct IAM role for Google Workspace users accessing Bedrock
      MaxSessionDuration: 43200  # 12 hours
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Federated: !GetAtt GoogleOIDCProvider.Arn
            Action:
              - 'sts:AssumeRoleWithWebIdentity'
              - 'sts:TagSession'
            Condition:
              StringEquals:
                'accounts.google.com:aud': !Ref GoogleClientId
                'accounts.google.com:hd': !Ref HostedDomain
      ManagedPolicyArns:
        - !Ref BedrockAccessPolicy
      Tags:
        - Key: Purpose
          Value: Claude Code Direct IAM Authentication
        - Key: Provider
          Value: Google
        - Key: FederationType
          Value: direct

  # ===============================================
  # Cognito Identity Pool Resources (when FederationType=cognito)
  # ===============================================

  CognitoIdentityPool:
    Type: AWS::Cognito::IdentityPool
    Condition: UseCognitoIdentity
    Properties:
      IdentityPoolName: !Ref IdentityPoolName
      AllowUnauthenticatedIdentities: false
      AllowClassicFlow: false
      OpenIdConnectProviderARNs:
        - !GetAtt GoogleOIDCProvider.Arn

  CognitoAuthenticatedRole:
    Type: AWS::IAM::Role
    Condition: UseCognitoIdentity
    Properties:
      Description: Role for authenticated Cognito Identity Pool users
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Federated: !If
                - IsGovCloudWest
                - cognito-identity-us-gov.amazonaws.com
                - !If
                  - IsGovCloudEast
                  - cognito-identity.us-gov-east-1.amazonaws.com
                  - cognito-identity.amazonaws.com
            Action:
              - 'sts:AssumeRoleWithWebIdentity'
            Condition:
              StringEquals:
                !If
                  - IsGovCloudWest
                  - 'cognito-identity-us-gov.amazonaws.com:aud': !Ref CognitoIdentityPool
                  - !If
                    - IsGovCloudEast
                    - 'cognito-identity.us-gov-east-1.amazonaws.com:aud': !Ref CognitoIdentityPool
                    - 'cognito-identity.amazonaws.com:aud': !Ref CognitoIdentityPool
              'ForAnyValue:StringLike':
                !If
                  - IsGovCloudWest
                  - 'cognito-identity-us-gov.amazonaws.com:amr': authenticated
                  - !If
                    - IsGovCloudEast
                    - 'cognito-identity.us-gov-east-1.amazonaws.com:amr': authenticated
                    - 'cognito-identity.amazonaws.com:amr': authenticated
      ManagedPolicyArns:
        - !Ref BedrockAccessPolicy
      Tags:
        - Key: Purpose
          Value: Claude Code Cognito Authentication
        - Key: Provider
          Value: Google

  CognitoUnauthenticatedRole:
    Type: AWS::IAM::Role
    Condition: UseCognitoIdentity
    Properties:
      Description: Role for unauthenticated Cognito Identity Pool users (restricted)
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Federated: !If
                - IsGovCloudWest
                - cognito-identity-us-gov.amazonaws.com
                - !If
                  - IsGovCloudEast
                  - cognito-identity.us-gov-east-1.amazonaws.com
                  - cognito-identity.amazonaws.com
            Action:
              - 'sts:AssumeRoleWithWebIdentity'
            Condition:
              StringEquals:
                !If
                  - IsGovCloudWest
                  - 'cognito-identity-us-gov.amazonaws.com:aud': !Ref CognitoIdentityPool
                  - !If
                    - IsGovCloudEast
                    - 'cognito-identity.us-gov-east-1.amazonaws.com:aud': !Ref CognitoIdentityPool
                    - 'cognito-identity.amazonaws.com:aud': !Ref CognitoIdentityPool
              'ForAnyValue:StringLike':
                !If
                  - IsGovCloudWest
                  - 'cognito-identity-us-gov.amazonaws.com:amr': unauthenticated
                  - !If
                    - IsGovCloudEast
                    - 'cognito-identity.us-gov-east-1.amazonaws.com:amr': unauthenticated
                    - 'cognito-identity.amazonaws.com:amr': unauthenticated
      Policies:
        - PolicyName: DenyAll
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Deny
                Action: '*'
                Resource: '*'
      Tags:
        - Key: Purpose
          Value: Claude Code Cognito Unauthenticated Role
        - Key: Provider
          Value: Google

  CognitoIdentityPoolRoleAttachment:
    Type: AWS::Cognito::IdentityPoolRoleAttachment
    Condition: UseCognitoIdentity
    Properties:
      IdentityPoolId: !Ref CognitoIdentityPool
      Roles:
        authenticated: !GetAtt CognitoAuthenticatedRole.Arn
        unauthenticated: !GetAtt CognitoUnauthenticatedRole.Arn

  # Principal Tag Mapping for Session Tags
  IdentityPoolPrincipalTag:
    Type: AWS::Cognito::IdentityPoolPrincipalTag
    Condition: UseCognitoIdentity
    DeletionPolicy: Delete
    Properties:
      IdentityPoolId: !Ref CognitoIdentityPool
      IdentityProviderName: 'accounts.google.com'
      UseDefaults: false
      PrincipalTags:
        UserEmail: email
        UserId: sub
        UserName: name

  # ===============================================
  # Optional Monitoring Resources
  # ===============================================

  BedrockAccessLogGroup:
    Type: AWS::Logs::LogGroup
    Condition: MonitoringEnabled
    Properties:
      LogGroupName: !Sub '/aws/bedrock/claude-code-${AWS::StackName}'
      RetentionInDays: 30

Outputs:
  FederationType:
    Description: Current federation type configuration
    Value: !Ref FederationType
    Export:
      Name: !Sub '${AWS::StackName}-FederationType'

  OIDCProviderArn:
    Description: ARN of the Google OIDC Provider
    Value: !GetAtt GoogleOIDCProvider.Arn
    Export:
      Name: !Sub '${AWS::StackName}-OIDCProviderArn'

  FederatedRoleArn:
    Description: ARN of the federated role for Google users
    Value: !If
      - UseDirectIAM
      - !GetAtt DirectIAMRole.Arn
      - !GetAtt CognitoAuthenticatedRole.Arn
    Export:
      Name: !Sub '${AWS::StackName}-FederatedRoleArn'

  DirectSTSRoleArn:
    Description: Direct STS federated role ARN (when using direct IAM)
    Condition: UseDirectIAM
    Value: !GetAtt DirectIAMRole.Arn
    Export:
      Name: !Sub '${AWS::StackName}-DirectSTSRoleArn'

  BedrockRoleArn:
    Description: IAM Role ARN for Bedrock access (for backward compatibility)
    Value: !If
      - UseDirectIAM
      - !GetAtt DirectIAMRole.Arn
      - !GetAtt CognitoAuthenticatedRole.Arn
    Export:
      Name: !Sub '${AWS::StackName}-BedrockRoleArn'

  IdentityPoolId:
    Description: Cognito Identity Pool ID (if using Cognito mode)
    Condition: UseCognitoIdentity
    Value: !Ref CognitoIdentityPool
    Export:
      Name: !Sub '${AWS::StackName}-IdentityPoolId'

  BedrockPolicyArn:
    Description: ARN of the Bedrock access policy
    Value: !Ref BedrockAccessPolicy
    Export:
      Name: !Sub '${AWS::StackName}-BedrockPolicyArn'

  ConfigurationJson:
    Description: Configuration JSON for CLI tool
    Value: !If
      - UseDirectIAM
      - !Sub |
        {
          "federation_type": "direct",
          "provider_type": "google",
          "provider_domain": "accounts.google.com",
          "client_id": "${GoogleClientId}",
          "federated_role_arn": "${DirectIAMRole.Arn}",
          "aws_region": "${AWS::Region}",
          "max_session_duration": 43200
        }
      - !Sub |
        {
          "federation_type": "cognito",
          "provider_type": "google",
          "provider_domain": "accounts.google.com",
          "client_id": "${GoogleClientId}",
          "identity_pool_id": "${CognitoIdentityPool}",
          "federated_role_arn": "${CognitoAuthenticatedRole.Arn}",
          "aws_region": "${AWS::Region}"
        }
```

- [ ] **Step 2: Lint the template**

Run from the repo root:
```bash
cfn-lint deployment/infrastructure/bedrock-auth-google.yaml
```
Expected: no errors or warnings. If cfn-lint is not installed globally, run `pip install cfn-lint` first.

- [ ] **Step 3: Commit**

```bash
git add deployment/infrastructure/bedrock-auth-google.yaml
git commit -m "feat: add bedrock-auth-google CloudFormation template"
```

---

## Task 2: `config.py` — `google_hosted_domain` field and detection

**Files:**
- Modify: `source/claude_code_with_bedrock/config.py`
- Test: `source/tests/test_config.py`

- [ ] **Step 1: Write failing tests**

Add to the end of `source/tests/test_config.py`:

```python
class TestGoogleProviderSupport:
    """Tests for Google Workspace provider type support."""

    def test_google_hosted_domain_field_exists(self):
        """Test that google_hosted_domain field is available in Profile."""
        profile = Profile(
            name="test",
            provider_domain="accounts.google.com",
            client_id="123456789-abc.apps.googleusercontent.com",
            credential_storage="session",
            aws_region="us-east-1",
            identity_pool_name="test-pool",
            google_hosted_domain="mycompany.com",
        )

        assert profile.google_hosted_domain == "mycompany.com"
        assert "google_hosted_domain" in profile.to_dict()

    def test_google_hosted_domain_defaults_to_none(self):
        """Test that google_hosted_domain defaults to None."""
        profile = Profile(
            name="test",
            provider_domain="test.okta.com",
            client_id="test-client",
            credential_storage="session",
            aws_region="us-east-1",
            identity_pool_name="test-pool",
        )

        assert profile.google_hosted_domain is None

    def test_from_dict_detects_google_provider(self):
        """Test that accounts.google.com is auto-detected as google provider type."""
        data = {
            "name": "test",
            "provider_domain": "accounts.google.com",
            "client_id": "123456789-abc.apps.googleusercontent.com",
            "credential_storage": "session",
            "aws_region": "us-east-1",
            "identity_pool_name": "test-pool",
            "allowed_bedrock_regions": ["us-east-1"],
            "monitoring_enabled": True,
            "analytics_enabled": True,
            "google_hosted_domain": "mycompany.com",
        }

        profile = Profile.from_dict(data)

        assert profile.provider_type == "google"
        assert profile.google_hosted_domain == "mycompany.com"

    def test_from_dict_preserves_google_hosted_domain(self):
        """Test that google_hosted_domain is preserved through from_dict round-trip."""
        data = {
            "name": "test",
            "provider_domain": "accounts.google.com",
            "client_id": "123456789-abc.apps.googleusercontent.com",
            "credential_storage": "session",
            "aws_region": "us-east-1",
            "identity_pool_name": "test-pool",
            "allowed_bedrock_regions": ["us-east-1"],
            "monitoring_enabled": True,
            "analytics_enabled": True,
            "provider_type": "google",
            "google_hosted_domain": "acme.com",
        }

        profile = Profile.from_dict(data)

        assert profile.google_hosted_domain == "acme.com"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd source && poetry run pytest tests/test_config.py::TestGoogleProviderSupport -v
```
Expected: FAIL — `Profile.__init__() got an unexpected keyword argument 'google_hosted_domain'`

- [ ] **Step 3: Add `google_hosted_domain` field to `Profile`**

In `source/claude_code_with_bedrock/config.py`, add after the `cognito_user_pool_id` field (line ~39):

```python
    google_hosted_domain: str | None = None  # Google Workspace domain for hd claim enforcement (e.g., "yourcompany.com")
```

- [ ] **Step 4: Add Google detection in `from_dict`**

In `source/claude_code_with_bedrock/config.py`, inside the `from_dict` provider detection block, add after the `windows.net` azure check (after line ~141):

```python
                        elif hostname_lower == "accounts.google.com":
                            data["provider_type"] = "google"
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd source && poetry run pytest tests/test_config.py::TestGoogleProviderSupport -v
```
Expected: 4 tests PASS

- [ ] **Step 6: Commit**

```bash
git add source/claude_code_with_bedrock/config.py source/tests/test_config.py
git commit -m "feat: add google_hosted_domain field and Google provider detection to config"
```

---

## Task 3: `test_url_validation_security.py` — Google domain detection tests

**Files:**
- Test: `source/tests/test_url_validation_security.py`

The detection logic tested here is the standalone `detect_provider_type_secure` function defined at the top of the test file. It mirrors the logic in `config.py` and `init.py`. Adding Google there documents the expected detection behaviour and guards against regressions.

- [ ] **Step 1: Write the failing tests**

Add to `TestURLValidationSecurity` in `source/tests/test_url_validation_security.py`:

```python
    def test_valid_google_domains(self):
        """Test legitimate Google domains are correctly identified."""
        valid_domains = [
            "accounts.google.com",
            "https://accounts.google.com",
            "https://accounts.google.com/.well-known/openid-configuration",
        ]

        for domain in valid_domains:
            assert detect_provider_type_secure(domain) == "google", f"Failed for {domain}"

    def test_attack_google_bypass(self):
        """Test that subdomain/path attacks against accounts.google.com are blocked."""
        attack_domains = [
            "accounts.google.com.evil.com",
            "evil.com/accounts.google.com",
            "notaccounts.google.com",
            "https://evil.com/accounts.google.com",
        ]

        for domain in attack_domains:
            result = detect_provider_type_secure(domain)
            assert result != "google", f"Should not detect as google: {domain}"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd source && poetry run pytest tests/test_url_validation_security.py::TestURLValidationSecurity::test_valid_google_domains -v
```
Expected: FAIL — `assert 'oidc' == 'google'`

- [ ] **Step 3: Add Google detection to `detect_provider_type_secure` in the test file**

In `source/tests/test_url_validation_security.py`, update `detect_provider_type_secure` — add after the `windows.net` check:

```python
        elif hostname_lower == "accounts.google.com":
            return "google"
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd source && poetry run pytest tests/test_url_validation_security.py -v
```
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add source/tests/test_url_validation_security.py
git commit -m "test: add Google domain detection tests"
```

---

## Task 4: `init.py` — Google detection and hosted domain prompt

**Files:**
- Modify: `source/claude_code_with_bedrock/cli/commands/init.py`

No isolated unit test is possible for the questionary prompt (it is interactive). The detection logic is covered by Task 3 tests. Manually verify wizard behaviour after this task.

- [ ] **Step 1: Add Google to domain detection block**

In `source/claude_code_with_bedrock/cli/commands/init.py`, inside the provider detection `try` block (around line ~347, after the `windows.net` azure check), add:

```python
                    elif hostname_lower == "accounts.google.com":
                        provider_type = "google"
```

- [ ] **Step 2: Add hosted domain prompt for Google**

In `init.py`, after the Cognito User Pool ID prompt block (around line ~389, just before the `client_id` prompt), add:

```python
            # For Google, ask for the Workspace hosted domain
            google_hosted_domain = None
            if provider_type == "google":
                google_hosted_domain = questionary.text(
                    "Enter your Google Workspace domain:",
                    validate=lambda x: bool(x and re.match(r"^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}$", x))
                    or "Must be a valid domain (e.g., yourcompany.com)",
                    instruction="(e.g., yourcompany.com)",
                    default=config.get("google_hosted_domain", ""),
                ).ask()

                if not google_hosted_domain:
                    return None
```

- [ ] **Step 3: Persist `google_hosted_domain` in config dict**

In `init.py`, in the block that saves OIDC config to `config` (around line ~424, after `config["provider_type"] = provider_type`), add:

```python
            if google_hosted_domain:
                config["google_hosted_domain"] = google_hosted_domain
```

- [ ] **Step 4: Update domain prompt example text**

In `init.py`, find the `instruction` kwarg on the `provider_domain` questionary prompt (around line ~303). Update it to include `accounts.google.com` as an example:

Replace:
```python
                instruction=(
                    "(e.g., company.okta.com, company.auth0.com, "
                    "login.microsoftonline.com/{tenant-id}/v2.0, "
                    "my-app.auth.us-east-1.amazoncognito.com, or "
                    "my-app.auth-fips.us-gov-west-1.amazoncognito.com for GovCloud)"
                ),
```

With:
```python
                instruction=(
                    "(e.g., company.okta.com, company.auth0.com, "
                    "login.microsoftonline.com/{tenant-id}/v2.0, "
                    "accounts.google.com, "
                    "my-app.auth.us-east-1.amazoncognito.com, or "
                    "my-app.auth-fips.us-gov-west-1.amazoncognito.com for GovCloud)"
                ),
```

- [ ] **Step 5: Wire `google_hosted_domain` into `_save_configuration`**

In `init.py`, in the `_save_configuration` method, inside the `Profile(...)` constructor call (around line ~1510, after the `cognito_user_pool_id=` line), add:

```python
            google_hosted_domain=config_data.get("google_hosted_domain"),
```

- [ ] **Step 6: Run existing init tests to confirm no regressions**

```bash
cd source && poetry run pytest tests/cli/commands/test_init.py tests/cli/commands/test_init_models.py -v
```
Expected: all existing tests PASS

- [ ] **Step 7: Commit**

```bash
git add source/claude_code_with_bedrock/cli/commands/init.py
git commit -m "feat: add Google provider detection and hosted domain prompt to init wizard"
```

---

## Task 5: `deploy.py` — Template dispatch for Google

**Files:**
- Modify: `source/claude_code_with_bedrock/cli/commands/deploy.py`
- Test: `source/tests/cli/commands/test_deploy_quota.py`

- [ ] **Step 1: Write the failing test**

Open `source/tests/cli/commands/test_deploy_quota.py` and add at the end:

```python
class TestGoogleTemplateDispatch:
    """Test that the Google provider type dispatches to the correct template."""

    def test_google_in_template_map(self):
        """Verify 'google' is a key in the deploy template_map."""
        # Read deploy.py source and verify the mapping is present
        import re
        from pathlib import Path

        deploy_src = (
            Path(__file__).parent.parent.parent.parent
            / "claude_code_with_bedrock/cli/commands/deploy.py"
        ).read_text()

        assert '"google": "bedrock-auth-google.yaml"' in deploy_src, (
            "deploy.py must map provider_type 'google' to 'bedrock-auth-google.yaml'"
        )

    def test_google_params_branch_present(self):
        """Verify GoogleClientId and HostedDomain params are set for Google provider."""
        from pathlib import Path

        deploy_src = (
            Path(__file__).parent.parent.parent.parent
            / "claude_code_with_bedrock/cli/commands/deploy.py"
        ).read_text()

        assert "GoogleClientId=" in deploy_src, "deploy.py must set GoogleClientId param"
        assert "HostedDomain=" in deploy_src, "deploy.py must set HostedDomain param"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd source && poetry run pytest tests/cli/commands/test_deploy_quota.py::TestGoogleTemplateDispatch -v
```
Expected: FAIL — assertion errors on missing `"google"` key and params

- [ ] **Step 3: Add Google to `template_map`**

In `source/claude_code_with_bedrock/cli/commands/deploy.py`, in the `template_map` dict (lines ~355–361), add `"google"`:

```python
                template_map = {
                    "okta": "bedrock-auth-okta.yaml",
                    "auth0": "bedrock-auth-auth0.yaml",
                    "azure": "bedrock-auth-azure.yaml",
                    "cognito": "bedrock-auth-cognito-pool.yaml",
                    "google": "bedrock-auth-google.yaml",
                }
```

- [ ] **Step 4: Add Google params branch**

In `deploy.py`, after the `elif provider_type == "cognito":` block (after line ~430, before the shared `params.extend` call), add:

```python
                elif provider_type == "google":
                    params.extend(
                        [
                            f"GoogleClientId={profile.client_id}",
                            f"HostedDomain={profile.google_hosted_domain}",
                        ]
                    )
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd source && poetry run pytest tests/cli/commands/test_deploy_quota.py::TestGoogleTemplateDispatch -v
```
Expected: 2 tests PASS

- [ ] **Step 6: Run full test suite**

```bash
cd source && poetry run pytest -v
```
Expected: all tests PASS

- [ ] **Step 7: Commit**

```bash
git add source/claude_code_with_bedrock/cli/commands/deploy.py source/tests/cli/commands/test_deploy_quota.py
git commit -m "feat: add Google provider dispatch to deploy command"
```

---

## Task 6: Push branch

- [ ] **Step 1: Push to remote**

```bash
git push emo feat/google-sso
```

- [ ] **Step 2: Verify on GitHub**

Check that `EMOTechnologies/guidance-for-claude-code-with-amazon-bedrock/tree/feat/google-sso` contains all 5 commits.
