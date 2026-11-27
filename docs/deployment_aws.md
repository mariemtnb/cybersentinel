# AWS deployment plan (prepared, not executed)

> **Status: nothing has been created on AWS.** This document and `.github/workflows/deploy.yml`
> are ready for the team to review. Creating resources costs money and needs the team's own AWS
> account and explicit approval.

## Target

Smallest deployment that keeps the local architecture unchanged:

| Local (Docker Compose) | AWS |
|---|---|
| SeaweedFS (S3 API) | **S3 bucket** `cybersentinel-lake-<team>` — only `S3_ENDPOINT_URL` is removed |
| `cybersentinel:local` image | Image in **GHCR** (built by CI) or Amazon ECR |
| `pipeline` + `prefect-server` + `dashboard` containers | One **EC2 t3.small** running the same `docker compose` file (simplest), or ECS Fargate later |
| `cs-data` volume (DuckDB files) | EBS volume of that instance (DuckDB needs a local file system) |
| `.env` | GitHub Secrets → written to the instance by the deploy job; AWS SSM Parameter Store as an option |

Why EC2 + Compose and not ECS/Fargate first: the DuckDB warehouse is a single local file shared by
the pipeline and the dashboard; one instance with a volume reproduces exactly what is tested
locally. Fargate would need EFS for the shared file — more moving parts for a student project.

## The three AWS rules of the brief

1. **No access key in the repository.** CI authenticates with GitHub → AWS OIDC (an IAM role trusted
   for this repository and the `main` branch), so no long-lived key exists at all. If OIDC is not
   possible, store `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` as **GitHub Secrets**, never in files.
2. **Budget alert on day one.** Before anything else:
   ```bash
   aws budgets create-budget --account-id <ACCOUNT_ID> \
     --budget '{"BudgetName":"cybersentinel","BudgetLimit":{"Amount":"10","Unit":"USD"},"TimeUnit":"MONTHLY","BudgetType":"COST"}' \
     --notifications-with-subscribers '[{"Notification":{"NotificationType":"ACTUAL","ComparisonOperator":"GREATER_THAN","Threshold":80},"Subscribers":[{"SubscriptionType":"EMAIL","Address":"<team-email>"}]}]'
   ```
3. **Everything is deleted at the end** — see Clean-up below.

## Expected cost (eu-west-3, on-demand, indicative)

t3.small ≈ 0.023 USD/h (~17 USD/month if always on; stop it outside demos), 20 GB gp3 ≈ 1.6 USD/month,
S3 < 1 GB ≈ 0.03 USD/month. A 10 USD monthly budget with an 80 % alert is a reasonable guard.

## Steps (when the team is ready)

1. Create the budget alert (above).
2. Create the S3 bucket (block public access ON, versioning optional) and an IAM role for the EC2
   instance with `s3:GetObject/PutObject/ListBucket` on that bucket only.
3. Create the OIDC deploy role for GitHub Actions (trust: `repo:<org>/<repo>:ref:refs/heads/main`),
   allowed to use SSM `SendCommand` on the instance only.
4. Launch the EC2 instance (Amazon Linux 2023, Docker + Compose plugin, instance role from step 2,
   security group: no inbound except SSM; reach the dashboard through SSM port forwarding or an
   authenticated reverse proxy — the dashboard has no login and must not be public).
5. Set GitHub repository variables/secrets: `AWS_DEPLOY_ENABLED=true` (variable), `AWS_ROLE_ARN`,
   `AWS_REGION`, `EC2_INSTANCE_ID`, `NVD_API_KEY`, `S3_BUCKET` (secrets/variables).
6. Run the `deploy` workflow manually (it is `workflow_dispatch` only). It builds and pushes the image
   to GHCR, then asks the instance (via SSM) to pull and `docker compose up -d` with
   `RAW_STORAGE=s3`, no `S3_ENDPOINT_URL`.

## Clean-up (end of project)

```bash
aws ec2 terminate-instances --instance-ids <id>
aws s3 rb s3://cybersentinel-lake-<team> --force
aws iam delete-role --role-name <roles created>   # after detaching policies
aws budgets delete-budget --account-id <ACCOUNT_ID> --budget-name cybersentinel
```
Delete the GHCR package from the repository settings. Check Cost Explorer the next day.
