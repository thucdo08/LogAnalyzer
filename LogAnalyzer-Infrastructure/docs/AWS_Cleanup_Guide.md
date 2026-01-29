# AWS Resource Cleanup Guide

**Purpose**: Xóa tất cả AWS resources để tránh chi phí hàng tháng  
**Estimated savings**: ~$57/month

⚠️ **WARNING**: Sau khi xóa, ứng dụng sẽ không còn accessible. Đảm bảo đã:
- ✅ Lưu screenshots/demo videos
- ✅ Code đã push lên GitHub
- ✅ Docker images đã push lên Docker Hub
- ✅ Documentation đã hoàn thành

---

## 📋 Quick Cleanup Checklist

- [ ] Backup data (if needed)
- [ ] Verify GitHub code is up-to-date
- [ ] Delete EC2 instances via Terraform
- [ ] Release Elastic IPs
- [ ] Delete Security Groups
- [ ] Delete VPC resources
- [ ] Verify all resources deleted
- [ ] Check AWS billing

---

## 🔧 Method 1: Terraform Destroy (Recommended)

**Fastest and cleanest way - deletes everything automatically.**

### **Step 1: Navigate to Terraform Directory**

```powershell
cd d:\CV\LogAnalyzer\LogAnalyzer-Infrastructure\terraform
```

---

### **Step 2: Preview What Will Be Deleted**

```powershell
terraform plan -destroy
```

**This will show:**
- 2 EC2 instances (Jenkins, App Server)
- 2 Elastic IPs
- 2 Security Groups
- 1 VPC
- 1 Subnet
- 1 Internet Gateway
- Route tables
- Network interfaces

---

### **Step 3: Destroy All Resources**

```powershell
terraform destroy
```

**When prompted:**
```
Do you really want to destroy all resources?
  Enter a value: yes
```

**Wait ~2-3 minutes** for completion.

**Expected output:**
```
Destroy complete! Resources: 11 destroyed.
```

---

### **Step 4: Verify Deletion**

**Check AWS Console:**
1. EC2 Dashboard → Instances → Should be empty (or terminating)
2. EC2 → Elastic IPs → Should be empty
3. VPC Dashboard → Your VPCs → Only default VPC remains

**Or via AWS CLI:**
```powershell
# Check EC2 instances
aws ec2 describe-instances --region ap-southeast-1 --query "Reservations[*].Instances[*].[InstanceId,State.Name,Tags[?Key=='Name'].Value|[0]]" --output table

# Check Elastic IPs
aws ec2 describe-addresses --region ap-southeast-1

# Check VPCs
aws ec2 describe-vpcs --region ap-southeast-1
```

---

## 🔧 Method 2: Manual Cleanup (If Terraform Fails)

**Use this if `terraform destroy` has errors.**

### **Step 1: Terminate EC2 Instances**

**Via AWS Console:**
1. Go to: https://console.aws.amazon.com/ec2/
2. Select region: **ap-southeast-1** (Singapore)
3. Click **Instances** (left sidebar)
4. Select both instances:
   - Jenkins Server (t3.small)
   - App Server (t3.medium)
5. **Instance State** → **Terminate instance**
6. Confirm termination

**Or via AWS CLI:**
```powershell
# List instance IDs
aws ec2 describe-instances --region ap-southeast-1 --filters "Name=tag:Project,Values=loganalyzer" --query "Reservations[*].Instances[*].InstanceId" --output text

# Terminate instances (replace with your IDs)
aws ec2 terminate-instances --region ap-southeast-1 --instance-ids i-xxxxx i-yyyyy
```

**Wait 2-3 minutes** for termination to complete.

---

### **Step 2: Release Elastic IPs**

⚠️ **IMPORTANT**: Elastic IPs cost $3.65/month if not attached to running instances!

**Via AWS Console:**
1. EC2 → **Elastic IPs** (left sidebar)
2. Select each Elastic IP (54.254.0.207, 54.254.11.86)
3. **Actions** → **Release Elastic IP addresses**
4. Confirm release

**Or via AWS CLI:**
```powershell
# List Elastic IPs
aws ec2 describe-addresses --region ap-southeast-1

# Release Elastic IPs (replace with your allocation IDs)
aws ec2 release-address --region ap-southeast-1 --allocation-id eipalloc-xxxxx
aws ec2 release-address --region ap-southeast-1 --allocation-id eipalloc-yyyyy
```

---

### **Step 3: Delete Security Groups**

**Via AWS Console:**
1. EC2 → **Security Groups**
2. Select:
   - `loganalyzer-jenkins-sg`
   - `loganalyzer-app-sg`
3. **Actions** → **Delete security groups**

**Or via AWS CLI:**
```powershell
# List security groups
aws ec2 describe-security-groups --region ap-southeast-1 --filters "Name=tag:Project,Values=loganalyzer"

# Delete security groups (replace with your IDs)
aws ec2 delete-security-group --region ap-southeast-1 --group-id sg-xxxxx
aws ec2 delete-security-group --region ap-southeast-1 --group-id sg-yyyyy
```

---

### **Step 4: Delete VPC and Associated Resources**

**Via AWS Console:**
1. VPC Dashboard → **Your VPCs**
2. Select VPC: `10.0.0.0/16` (loganalyzer-vpc)
3. **Actions** → **Delete VPC**
4. This will also delete:
   - Subnets
   - Route tables
   - Internet Gateway
   - Network ACLs

**Or via AWS CLI:**
```powershell
# List VPCs
aws ec2 describe-vpcs --region ap-southeast-1 --filters "Name=tag:Project,Values=loganalyzer"

# Delete VPC (will cascade delete associated resources)
aws ec2 delete-vpc --region ap-southeast-1 --vpc-id vpc-xxxxx
```

---

## 📊 Resources That Don't Cost Money

**These are FREE - no need to delete:**

✅ **IAM User** (`terraform-user`)
- No cost
- Can keep for future projects

✅ **SSH Key Pair** (local `~/.ssh/loganalyzer-aws`)
- No cost
- Stored locally

✅ **GitHub Repository**
- No cost
- Keep for portfolio!

✅ **Docker Hub Images**
- Free tier (unlimited public repos)
- Keep for verification!

✅ **MongoDB Atlas**
- Free tier (512MB)
- Can keep or delete

✅ **Domain Name** (`dofuta.site`)
- Annual cost (already paid)
- Will expire naturally

---

## 💰 Cost Breakdown (What You're Saving)

| Resource | Cost/Month | After Deletion |
|----------|------------|----------------|
| EC2 t3.medium (App) | ~$30 | ✅ $0 |
| EC2 t3.small (Jenkins) | ~$15 | ✅ $0 |
| Elastic IPs (2) | ~$7 | ✅ $0 |
| Data Transfer | ~$5 | ✅ $0 |
| **Total Savings** | **~$57** | **✅ $0** |

---

## ✅ Verification Checklist

After cleanup, verify ZERO charges:

### **AWS Console Checks:**

**1. EC2 Dashboard**
```
✅ Instances: 0 running
✅ Elastic IPs: 0 allocated
✅ Volumes: 0 (or only unused)
```

**2. VPC Dashboard**
```
✅ VPCs: Only default VPC
✅ Subnets: Only default subnets
✅ Internet Gateways: Only default (if any)
```

**3. Billing Dashboard**
```
✅ Current month charges: Minimal (<$1)
✅ Cost Explorer: Verify EC2 charges stop
```

---

### **AWS CLI Verification:**

```powershell
# Check running instances
aws ec2 describe-instances --region ap-southeast-1 --filters "Name=instance-state-name,Values=running" --query "Reservations[*].Instances[*].[InstanceId,InstanceType]" --output table
# Expected: Empty table

# Check Elastic IPs
aws ec2 describe-addresses --region ap-southeast-1 --query "Addresses[*].[PublicIp,AllocationId]" --output table
# Expected: Empty table

# Check non-default VPCs
aws ec2 describe-vpcs --region ap-southeast-1 --filters "Name=isDefault,Values=false" --query "Vpcs[*].[VpcId,CidrBlock]" --output table
# Expected: Empty table
```

---

## 📧 Set Up Billing Alerts (Recommended)

**To avoid unexpected charges in future:**

1. AWS Console → Billing Dashboard
2. **Billing preferences**
3. ✅ Enable: "Receive Billing Alerts"
4. CloudWatch → Alarms → Create Alarm
5. Metric: Billing → Total Estimated Charge
6. Threshold: $5 USD
7. Email notification

---

## 🔄 If You Need to Redeploy Later

**All your code is safe:**
- ✅ GitHub: Infrastructure code (Terraform)
- ✅ GitHub: Application code (frontend, backend)
- ✅ Docker Hub: Built images

**To redeploy:**
```powershell
cd d:\CV\LogAnalyzer\LogAnalyzer-Infrastructure\terraform
terraform init
terraform apply
# Then follow Phase 3-6 from complete_deployment_guide.md
```

---

## 🚨 Common Issues

### **Issue 1: "Resource has dependencies"**

**Problem**: Can't delete VPC because security groups still attached

**Solution**: Delete in order:
1. EC2 instances first
2. Release Elastic IPs
3. Delete security groups
4. Delete VPC

---

### **Issue 2: "Elastic IP still allocated"**

**Problem**: Forgotten to release Elastic IPs

**Solution**:
```powershell
aws ec2 describe-addresses --region ap-southeast-1
# Note allocation IDs, then:
aws ec2 release-address --region ap-southeast-1 --allocation-id eipalloc-xxxxx
```

---

### **Issue 3: "Volume still exists"**

**Problem**: EBS volumes not auto-deleted

**Solution**:
```powershell
# List volumes
aws ec2 describe-volumes --region ap-southeast-1 --filters "Name=status,Values=available"

# Delete volume
aws ec2 delete-volume --region ap-southeast-1 --volume-id vol-xxxxx
```

---

## 📝 Final Steps

**After cleanup:**

1. ✅ Wait 24 hours
2. ✅ Check AWS Billing Dashboard
3. ✅ Verify $0 ongoing charges
4. ✅ Keep GitHub repo for portfolio
5. ✅ Update CV with project links

**Your project is preserved on:**
- 🔗 GitHub: Full source code
- 🔗 Docker Hub: Published images
- 📄 CV: Project description
- 📸 Screenshots: (if you took any)

---

## ⏱️ Estimated Time to Complete

- **Method 1 (Terraform)**: 5-10 minutes
- **Method 2 (Manual)**: 15-20 minutes
- **Verification**: 5 minutes

**Total**: ~30 minutes maximum

---

## 💡 Pro Tips

1. **Screenshot before deletion**: Capture running application
2. **Test locally**: Keep Docker images to run locally
3. **Export billing data**: For cost analysis learning
4. **Document for portfolio**: This deployment experience is valuable!

---

**🎉 Cleanup complete! You've successfully deployed and learned AWS infrastructure management without ongoing costs!**
