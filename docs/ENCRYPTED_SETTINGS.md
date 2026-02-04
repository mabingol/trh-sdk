# Settings Encryption Guide

TRH-SDK encrypts your deployment settings to protect sensitive data.

## Quick Start

### Encrypt Existing Settings
```bash
./trh-sdk encrypt-settings
# Set password: ********
# Confirm password: ********
# ✅ Settings encrypted
```

### Deploy with Encrypted Settings
```bash
./trh-sdk deploy
# Enter password: ********
# ✅ Deploying...
```

---

## Password Options

| Method | Command |
|--------|---------|
| **Interactive** | `./trh-sdk deploy` (prompts for password) |
| **Environment** | `TRH_SETTINGS_PASSWORD="..." ./trh-sdk deploy` |
| **Secrets Manager** | See CI/CD section below |

---

## CI/CD Integration

### GitHub Actions
```yaml
- name: Deploy
  env:
    TRH_SETTINGS_PASSWORD: ${{ secrets.TRH_PASSWORD }}
  run: ./trh-sdk deploy
```

### AWS Secrets Manager
```bash
export TRH_SETTINGS_PASSWORD=$(aws secretsmanager get-secret-value \
  --secret-id trh-sdk/password --query SecretString --output text)
./trh-sdk deploy
```

---

## AWS Fresh Deployment

1. **On local machine** - Deploy contracts and encrypt settings
   ```bash
   ./trh-sdk deploy-contracts
   # Set encryption password when prompted
   ```

2. **Upload to S3**
   ```bash
   aws s3 cp settings.json s3://your-bucket/deployments/
   ```

3. **On fresh EC2** - Download and deploy
   ```bash
   aws s3 cp s3://your-bucket/deployments/settings.json ./
   ./trh-sdk deploy
   # Enter password when prompted
   ```

---

## FAQ

**Q: I forgot my password**  
A: You'll need to redeploy contracts or restore from backup. Keep passwords in a password manager.

**Q: Can I change my password?**  
A: Run `./trh-sdk encrypt-settings` again with a new password.

**Q: Is the password stored anywhere?**  
A: No. The password is only used to derive an encryption key and is never saved.
