# Secret management

## Local development

Offline tests and the deterministic reasoner need no secret. For an explicitly authorized live OpenAI run, place only `OPENAI_API_KEY` in `.env.local`. The file is matched by `.gitignore` and `.dockerignore`; restrict it to the local user with `chmod 600 .env.local`. Do not print, log, commit, copy into an image, put on a command line, or include the value in tests, reports, screenshots, or support material.

The application reads the secret through typed settings as `SecretStr`, excludes it from settings serialization, and passes it only to the provider adapter. If exposure is suspected, revoke it through the provider and privately report the incident.

## Intended Azure production design

Azure deployment is not implemented in M12A. The intended runtime flow is:

```text
Azure workload
  -> Managed Identity
  -> Azure Key Vault
  -> OPENAI_API_KEY in the process environment
  -> typed application configuration
  -> OpenAI adapter
```

The workload identity receives narrowly scoped Key Vault read access. No key belongs in Git, the container image, deployment templates, image-build arguments, or a long-lived Azure client secret. Secret retrieval/injection belongs to the deployment boundary; application/domain code remains independent of the Azure SDK. Rotation should replace the Key Vault value and restart or safely reload the workload according to the future deployment design.

