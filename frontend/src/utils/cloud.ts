export interface CloudClassification {
  provider: string;
  service: string;
}

const CLOUD_HOST_PATTERNS: [RegExp, string, string][] = [
  [/(^|\.)s3([.-][a-z0-9-]+)?\.amazonaws\.com$/, "aws", "s3"],
  [/\.s3-website[.-][a-z0-9.-]+\.amazonaws\.com$/, "aws", "s3-website"],
  [/(^|\.)cloudfront\.net$/, "aws", "cloudfront"],
  [/\.compute(?:-1)?\.amazonaws\.com$/, "aws", "ec2"],
  [/\.elasticbeanstalk\.com$/, "aws", "elastic-beanstalk"],
  [/\.amplifyapp\.com$/, "aws", "amplify"],
  [/\.execute-api\.[a-z0-9-]+\.amazonaws\.com$/, "aws", "api-gateway"],
  [/\.elb\.[a-z0-9-]+\.amazonaws\.com$/, "aws", "elb"],
  [/\.rds\.amazonaws\.com$/, "aws", "rds"],
  [/\.amazonaws\.com$/, "aws", "aws-service"],
  [/(^|\.)storage\.googleapis\.com$/, "gcp", "cloud-storage"],
  [/\.storage\.googleapis\.com$/, "gcp", "cloud-storage"],
  [/\.appspot\.com$/, "gcp", "app-engine"],
  [/\.run\.app$/, "gcp", "cloud-run"],
  [/\.cloudfunctions\.net$/, "gcp", "cloud-functions"],
  [/\.firebaseapp\.com$/, "gcp", "firebase-hosting"],
  [/\.web\.app$/, "gcp", "firebase-hosting"],
  [/\.googleapis\.com$/, "gcp", "google-api"],
  [/\.blob\.core\.windows\.net$/, "azure", "blob-storage"],
  [/\.(file|queue|table)\.core\.windows\.net$/, "azure", "azure-storage"],
  [/\.azurewebsites\.net$/, "azure", "app-service"],
  [/\.cloudapp\.azure\.com$/, "azure", "cloud-app"],
  [/\.trafficmanager\.net$/, "azure", "traffic-manager"],
  [/\.azurecontainer\.io$/, "azure", "container-instances"],
  [/\.azurecr\.io$/, "azure", "container-registry"],
  [/\.vault\.azure\.net$/, "azure", "key-vault"],
  [/\.r2\.dev$/, "cloudflare", "r2"],
  [/\.workers\.dev$/, "cloudflare", "workers"],
  [/\.pages\.dev$/, "cloudflare", "pages"],
  [/\.jsdelivr\.net$/, "cloudflare", "jsdelivr"],
  [/\.unpkg\.com$/, "cloudflare", "unpkg"],
  [/\.digitaloceanspaces\.com$/, "digitalocean", "spaces"],
  [/\.ondigitalocean\.app$/, "digitalocean", "app-platform"],
  [/\.backblazeb2\.com$/, "backblaze", "b2"],
  [/\.wasabisys\.com$/, "wasabi", "object-storage"],
  [/\.linodeobjects\.com$/, "linode", "object-storage"],
  [/\.vultrobjects\.com$/, "vultr", "object-storage"],
  [/\.scw\.cloud$/, "scaleway", "cloud"],
  [/\.oraclecloud\.com$/, "oracle", "oci"],
  [/\.aliyuncs\.com$/, "alibaba", "aliyun"],
];

export function classifyCloudHost(host: string): CloudClassification | null {
  const normalized = String(host || "").toLowerCase().trim().replace(/\.$/, "");
  if (!normalized) return null;
  for (const [pattern, provider, service] of CLOUD_HOST_PATTERNS) {
    if (pattern.test(normalized)) return { provider, service };
  }
  return null;
}
