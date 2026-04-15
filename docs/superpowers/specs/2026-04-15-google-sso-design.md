# Google SSO for Bedrock Auth Stack

**Date:** 2026-04-15
**Scope:** Bedrock auth stack only (not distribution landing page)

## Summary

Add Google Workspace as a supported OIDC identity provider for the Bedrock auth stack. Restricted to a specific Google Workspace hosted domain (`hd` claim) enforced at the IAM trust policy level.

## Files Changed

| File | Change |
|------|--------|
| `deployment/infrastructure/bedrock-auth-google.yaml` | New CloudFormation template |
| `source/claude_code_with_bedrock/config.py` | Add `google_hosted_domain` field; add `accounts.google.com` detection |
| `source/claude_code_with_bedrock/cli/commands/init.py` | Add Google detection + hosted domain prompt |
| `source/claude_code_with_bedrock/cli/commands/deploy.py` | Add Google to `template_map`; add Google params branch |

## CloudFormation Template (`bedrock-auth-google.yaml`)

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `GoogleClientId` | String | OAuth 2.0 client ID from Google Cloud Console |
| `HostedDomain` | String | Google Workspace domain to enforce (e.g., `yourcompany.com`) |
| `FederationType` | String | `direct` or `cognito` (same as all other templates) |
| `IdentityPoolName` | String | Cognito Identity Pool name (cognito mode only) |
| `FederatedRoleName` | String | IAM role name, default `BedrockGoogleFederatedRole` |
| `AllowedBedrockRegions` | CommaDelimitedList | Regions where Bedrock access is allowed |
| `EnableMonitoring` | String | `true`/`false` |

### OIDC Provider

- URL: `https://accounts.google.com` (static — Google has no per-tenant OIDC endpoint)
- Thumbprint: `08745487e891c19e3078c1f2a07e452950ef36f6` (Google Trust Services root CA)
- `ClientIdList`: `[!Ref GoogleClientId]`

### Direct IAM Trust Policy Conditions

Both conditions are required and enforced simultaneously:

```yaml
StringEquals:
  'accounts.google.com:aud': !Ref GoogleClientId   # binds to this app only
  'accounts.google.com:hd': !Ref HostedDomain       # restricts to Workspace domain
```

### Cognito Path

- `IdentityPoolPrincipalTag.IdentityProviderName`: hardcoded to `accounts.google.com` (Google's OIDC issuer is not per-org, unlike Okta/Auth0)
- Everything else mirrors the Okta template exactly (same GovCloud-aware service principal logic, same role structure)

### `ConfigurationJson` Output

```json
{
  "provider_type": "google",
  "provider_domain": "accounts.google.com",
  "client_id": "<GoogleClientId>",
  ...
}
```

## Python Changes

### `config.py` — `Profile` dataclass

New field:
```python
google_hosted_domain: str | None = None  # Google Workspace domain (e.g., "yourcompany.com")
```

New detection block in `from_dict` (after the `windows.net` azure check):
```python
elif hostname_lower == "accounts.google.com":
    data["provider_type"] = "google"
```

### `init.py`

1. Same `elif hostname_lower == "accounts.google.com": provider_type = "google"` detection block added to the wizard's domain parsing.
2. After detection, when `provider_type == "google"`, prompt for hosted domain:
   ```
   "Enter your Google Workspace domain (e.g., yourcompany.com):"
   ```
   Stored as `config["google_hosted_domain"]`. Validation: non-empty, basic domain format.
3. Update OIDC domain prompt instruction text to include `accounts.google.com` as an example.
4. Save to profile in `_save_configuration`: `google_hosted_domain=config_data.get("google_hosted_domain")`.

### `deploy.py`

`template_map` addition:
```python
"google": "bedrock-auth-google.yaml",
```

New params branch:
```python
elif provider_type == "google":
    params.extend([
        f"GoogleClientId={profile.client_id}",
        f"HostedDomain={profile.google_hosted_domain}",
    ])
```

## Out of Scope

- Distribution landing page (`landing-page-distribution.yaml`) — no changes
- `distribute.py`, `package.py` — no changes
- GovCloud support for Google — Google OIDC is not available in GovCloud partitions; the template targets commercial AWS only

## Testing Notes

- Unit tests: add `"google"` to provider detection tests in `test_models.py` / wherever `provider_type` detection is tested
- The `HostedDomain` IAM condition can be verified by deploying the stack and attempting to assume the role with a token that has a mismatched `hd` claim
