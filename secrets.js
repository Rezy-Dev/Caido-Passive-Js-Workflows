async function l({ request: f, response: A }, r) { var i; if (!A) return; const s = (i = A.getBody()) == null ? void 0 : i.toText(); if (!s) return; const a = [
  { regex: /(A3T[A-Z0-9]{13}|AKIA[0-9A-Z]{16}|AGPA[0-9A-Z]{16}|AIDA[0-9A-Z]{16}|AROA[0-9A-Z]{16}|AIPA[0-9A-Z]{16}|ANPA[0-9A-Z]{16}|ANVA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})/g, title: "AWS API Key" },
  { regex: /(xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})/g, title: "Slack Token" },

  // all of the following are from https://blogs.jsmon.sh/100-regex-patterns/ exact copy paste!
  
  // 1. AWS Access Key ID
  { regex: /\bAKIA[0-9A-Z]{16}\b/g, title: "AWS Access Key ID" },

  // 2. AWS Secret Access Key (converted from (?i)...(?-i) to JS /i
  { regex: /aws(.{0,20})?['"][0-9a-zA-Z\/+]{40}['"]/gi, title: "AWS Secret Access Key" },

  // 3. Google API Key
  { regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g, title: "Google API Key" },

  // 4. Firebase Secret
  { regex: /\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b/g, title: "Firebase Secret" },

  // 5. GitHub Token (classic)
  { regex: /\bghp_[0-9a-zA-Z]{36}\b/g, title: "GitHub Token" },

  // 6. GitLab Token
  { regex: /\bglpat-[0-9a-zA-Z-_]{20}\b/g, title: "GitLab Token" },

  // 7. Slack Token (generic)
  { regex: /\bxox[baprs]-([0-9a-zA-Z]{10,48})?\b/g, title: "Slack Token (Generic)" },

  // 8. Stripe Secret Key
  { regex: /\bsk_live_[0-9a-zA-Z]{24}\b/g, title: "Stripe Secret Key" },

  // 9. Stripe Publishable Key
  { regex: /\bpk_live_[0-9a-zA-Z]{24}\b/g, title: "Stripe Publishable Key" },

  // 10. Twilio API Key
  { regex: /\bSK[0-9a-fA-F]{32}\b/g, title: "Twilio API Key" },

  // 11. SendGrid API Key
  { regex: /\bSG\.[\w\d\-_]{22}\.[\w\d\-_]{43}\b/g, title: "SendGrid API Key" },

  // 12. Mailgun API Key
  { regex: /\bkey-[0-9a-zA-Z]{32}\b/g, title: "Mailgun API Key" },

  // 13. Dropbox Access Token
  { regex: /\bsl\.[A-Za-z0-9_-]{20,100}\b/g, title: "Dropbox Access Token" },

  // 14. Shopify Access Token
  { regex: /\bshpat_[0-9a-fA-F]{32}\b/g, title: "Shopify Access Token" },

  // 15. Facebook Access Token
  { regex: /\bEAACEdEose0cBA[0-9A-Za-z]+\b/g, title: "Facebook Access Token" },

  // 16. Heroku API Key (your list had [hH]eroku"....)
  { regex: /[hH]eroku['"][0-9a-f]{32}['"]/g, title: "Heroku API Key" },

  // 17. DigitalOcean Token
  { regex: /\bdop_v1_[a-z0-9]{64}\b/g, title: "DigitalOcean Token" },

  // 18. Asana Personal Access Token
  { regex: /\b0\/[0-9a-z]{32}\b/g, title: "Asana Personal Access Token" },

  // 19. Linear API Key
  { regex: /\blin_api_[a-zA-Z0-9]{40}\b/g, title: "Linear API Key" },

  // 20. Telegram Bot Token
  { regex: /\b\d{9}:[a-zA-Z0-9_-]{35}\b/g, title: "Telegram Bot Token" },

  // 21. OAuth Client Secret
  { regex: /client_secret['"\s:=]+[a-zA-Z0-9\-_.~]{10,100}/gi, title: "OAuth Client Secret" },

  // 22. OAuth Client ID
  { regex: /client_id['"\s:=]+[a-zA-Z0-9\-_.~]{10,100}/gi, title: "OAuth Client ID" },

  // 23. JWT Token
  { regex: /\beyJ[A-Za-z0-9-_=]+?\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b/g, title: "JWT Token" },

  // 24. Azure Client Secret (converted to JS /i)
  { regex: /azure(.{0,20})?client\.secret(.{0,20})?['"][a-zA-Z0-9._%+-]{32,}['"]/gi, title: "Azure Client Secret" },

  // 25. Microsoft Teams Webhook
  { regex: /https:\/\/[a-z]+\.webhook\.office\.com\/webhookb2\/[a-zA-Z0-9@\-]+\/.*/g, title: "Microsoft Teams Webhook" },

  // 26. Basic Auth String
  { regex: /(username|user|email)['"\s:=]+[^\s'"@]{1,100}['"].*?(password|pwd)['"\s:=]+[^\s'"]{4,100}/gi, title: "Basic Auth String" },

  // 27. Password Assignment
  { regex: /(password|pwd|pass)['"\s:=]+[^\s'"]{4,100}/gi, title: "Password Assignment" },

  // 28. API Key in Variable
  { regex: /(api[_-]?key)['"\s:=]+[a-zA-Z0-9\-_.]{8,100}/gi, title: "API Key in Variable" },

  // 29. Secret in Variable
  { regex: /(secret|token)['"\s:=]+[a-zA-Z0-9\-_.]{8,100}/gi, title: "Secret in Variable" },

  // 30. Authorization Bearer Token
  { regex: /Bearer\s+[a-zA-Z0-9\-._~+/]+=*/g, title: "Authorization Bearer Token" },

  // 31. MongoDB Connection URI
  { regex: /mongodb(\+srv)?:\/\/[^\s'"]+/g, title: "MongoDB Connection URI" },

  // 32. PostgreSQL URI
  { regex: /postgres(?:ql)?:\/\/[^\s'"]+/g, title: "PostgreSQL URI" },

  // 33. MySQL URI
  { regex: /mysql:\/\/[^\s'"]+/g, title: "MySQL URI" },

  // 34. Redis URI
  { regex: /redis:\/\/[^\s'"]+/g, title: "Redis URI" },

  // 35. Elasticsearch URI
  { regex: /elasticsearch:\/\/[^\s'"]+/g, title: "Elasticsearch URI" },

  // 36. Supabase DB Key (as provided)
  { regex: /supabase\.co\/[a-z0-9]{15,}/g, title: "Supabase DB Key" },

  // 37. Firebase URL
  { regex: /https:\/\/[a-z0-9-]+\.firebaseio\.com/g, title: "Firebase URL" },

  // 38. JDBC URL
  { regex: /jdbc:\w+:\/\/[^\s'"]+/g, title: "JDBC URL" },

  // 39. AWS RDS Hostname
  { regex: /\b[a-z0-9-]+\.rds\.amazonaws\.com\b/g, title: "AWS RDS Hostname" },

  // 40. Cloud SQL URI (GCP)
  { regex: /googleapis\.com\/sql\/v1beta4\/projects\//g, title: "Cloud SQL URI (GCP)" },

  // 41. Algolia API Key (context)
  { regex: /(algolia|application)_?key['"\s:=]+[a-zA-Z0-9]{10,}/gi, title: "Algolia API Key" },

  // 42. Firebase API Key in firebaseConfig
  { regex: /firebaseConfig\s*=\s*{[^}]*apiKey\s*:\s*['"][^'"]+['"]/g, title: "Firebase API Key (firebaseConfig)" },

  // 43. Cloudinary URL
  { regex: /cloudinary:\/\/[0-9]{15}:[a-zA-Z0-9]+@[a-zA-Z]+/g, title: "Cloudinary URL" },

  // 44. Sentry DSN
  { regex: /https:\/\/[a-zA-Z0-9]+@[a-z]+\.ingest\.sentry\.io\/\d+/g, title: "Sentry DSN" },

  // 45. Netlify Token
  { regex: /netlifyAuthToken\s*=\s*['"][a-z0-9]{40}['"]/g, title: "Netlify Token" },

  // 46. GitHub OAuth App Secret (VERY generic)
  { regex: /\b[a-f0-9]{40}\b/g, title: "GitHub OAuth App Secret (Generic)" },

  // 47. Segment API Key (context)
  { regex: /segment(.{0,20})?key['"\s:=]+[a-zA-Z0-9]{10,}/gi, title: "Segment API Key" },

  // 48. Intercom Access Token (context)
  { regex: /intercom(.{0,20})?token['"\s:=]+[a-zA-Z0-9-_]{20,}/gi, title: "Intercom Access Token" },

  // 49. Amplitude API Key (apiKey: "...")
  { regex: /apiKey['"]?\s*:\s*['"][a-z0-9\-]{32,64}['"]/g, title: "Amplitude API Key" },

  // 50. Plaid Client Secret (context)
  { regex: /plaid(.{0,20})?(client)?secret['"\s:=]+[a-z0-9-_]{30,}/gi, title: "Plaid Client Secret" },

  // 51. Docker Hub Password (context)
  { regex: /docker(.{0,20})?password['"\s:=]+[^\s'"]{8,}/gi, title: "Docker Hub Password" },

  // 52. AWS IAM Role ARN
  { regex: /arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9_+=,.@\-_/]+/g, title: "AWS IAM Role ARN" },

  // 53. AWS S3 Bucket URL
  { regex: /s3:\/\/[a-z0-9\-\.]{3,63}/g, title: "AWS S3 Bucket URL" },

  // 54. Kubernetes Secret Name
  { regex: /secretName:\s*['"]?[a-z0-9\-]+['"]?/gi, title: "Kubernetes secretName" },

  // 55. Helm Secret Value
  { regex: /secret\s*:\s*['"][^'"]+['"]/gi, title: "Helm Secret Value" },

  // 56. GitHub Actions Secret Reference
  { regex: /secrets\.[A-Z0-9_]+/g, title: "GitHub Actions Secret Reference" },

  // 57. GitHub Actions Encrypted Value
  { regex: /encrypted_value:\s*['"][a-zA-Z0-9+/=]{10,}['"]/g, title: "GitHub Actions Encrypted Value" },

  // 58. K8s Service Account Token (header)
  { regex: /eyJhbGciOiJSUzI1NiIsImtpZCI6/g, title: "K8s Service Account Token (Header)" },

  // 59. Vault Token
  { regex: /\bs\.[a-zA-Z0-9]{8,}\b/g, title: "Vault Token" },

  // 60. Hashicorp Vault URL
  { regex: /https:\/\/vault\.[a-z0-9\-_\.]+\.com/g, title: "Hashicorp Vault URL" },

  // 61. CircleCI Token
  { regex: /circle-token=[a-z0-9]{40}/g, title: "CircleCI Token" },

  // 62. Travis CI Token (context)
  { regex: /travis(.{0,20})?token['"\s:=]+[a-z0-9]{30,}/gi, title: "Travis CI Token" },

  // 63. Jenkins Crumb Token
  { regex: /Jenkins-Crumb:\s*[a-z0-9]{30,}/g, title: "Jenkins Crumb Token" },

  // 64. Azure DevOps Token (very generic)
  { regex: /\b[a-z0-9]{52}\b/g, title: "Azure DevOps Token (Generic)" },

  // 65. GitHub Personal Access Token (duplicate of #5 but keep)
  { regex: /\bghp_[a-zA-Z0-9]{36}\b/g, title: "GitHub Personal Access Token" },

  // 66. GitHub Fine-Grained Token
  { regex: /\bgithub_pat_[0-9a-zA-Z_]{20,}\b/g, title: "GitHub Fine-Grained Token" },

  // 67. Bitbucket OAuth Key (context)
  { regex: /bitbucket(.{0,20})?key['"\s:=]+[a-zA-Z0-9]{20,}/gi, title: "Bitbucket OAuth Key" },

  // 68. Bitbucket OAuth Secret (context)
  { regex: /bitbucket(.{0,20})?secret['"\s:=]+[a-zA-Z0-9]{20,}/gi, title: "Bitbucket OAuth Secret" },

  // 69. GitLab Runner Token
  { regex: /\bglrt-[a-zA-Z0-9_-]{20}\b/g, title: "GitLab Runner Token" },

  // 70. Netlify Access Token (duplicate of #45 but keep)
  { regex: /netlifyAuthToken\s*=\s*['"][a-z0-9]{40}['"]/g, title: "Netlify Access Token" },

  // 71. Bugsnag API Key (very generic)
  { regex: /\b[a-f0-9]{32}\b/g, title: "Bugsnag API Key (Generic)" },

  // 72. Datadog API Key (very generic)
  { regex: /\b[a-z0-9]{32}\b/g, title: "Datadog API Key (Generic)" },

  // 73. Loggly Token
  { regex: /\b[a-z0-9]{30}-[a-z0-9]{10}\b/g, title: "Loggly Token" },

  // 74. New Relic Key
  { regex: /\bNRII-[a-zA-Z0-9]{20,}\b/g, title: "New Relic Key" },

  // 75. Mixpanel Token (context)
  { regex: /mixpanel(.{0,20})?token['"\s:=]+[a-z0-9]{32}/gi, title: "Mixpanel Token" },

  // 76. Heap Analytics App ID
  { regex: /heapSettings\.appId\s*=\s*['"][a-z0-9]{8,12}['"]/g, title: "Heap Analytics App ID" },

  // 77. Keen IO Project ID
  { regex: /projectId['"]?\s*:\s*['"][a-f0-9]{24}['"]/g, title: "Keen IO Project ID" },

  // 78. Keen IO Write Key
  { regex: /writeKey['"]?\s*:\s*['"][a-zA-Z0-9]{64}['"]/g, title: "Keen IO Write Key" },

  // 79. Snyk Token
  { regex: /snyk_token\s*=\s*[a-f0-9\-]{36}/g, title: "Snyk Token" },

  // 80. Rollbar Access Token
  { regex: /access_token['"]?\s*:\s*['"][a-z0-9]{32}['"]/g, title: "Rollbar Access Token" },

  // 81. Twitch API Key (context)
  { regex: /twitch(.{0,20})?key['"\s:=]+[a-zA-Z0-9]{20,}/gi, title: "Twitch API Key" },

  // 82. Discord Bot Token
  { regex: /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/g, title: "Discord Bot Token" },

  // 83. Discord Webhook URL
  { regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+/g, title: "Discord Webhook URL" },

  // 84. Steam Web API Key (context)
  { regex: /steam(.{0,20})?key['"\s:=]+[a-zA-Z0-9]{32}/gi, title: "Steam Web API Key" },

  // 85. Riot Games API Key
  { regex: /RGAPI-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g, title: "Riot Games API Key" },

  // 86. Private IP (Internal)
  { regex: /\b(10\.\d{1,3}|\b192\.168|\b172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b/g, title: "Private IP (Internal)" },

  // 87. Localhost Reference
  { regex: /localhost:[0-9]{2,5}/g, title: "Localhost Reference" },

  // 88. Dev/Stage URL
  { regex: /(dev|staging|test)\.[a-z0-9.-]+\.(com|net|io)/g, title: "Dev/Stage URL" },

  // 89. Internal Subdomain URL
  { regex: /https?:\/\/[a-z0-9.-]+\.internal\.[a-z]{2,}/g, title: "Internal Subdomain URL" },

  // 90. Preprod URLs
  { regex: /https:\/\/preprod\.[a-z0-9-]+\.[a-z]{2,}/g, title: "Preprod URL" },

  // 91. Private Key Block
  { regex: /-----BEGIN (RSA|DSA|EC|OPENSSH)? PRIVATE KEY-----/g, title: "Private Key Block" },

  // 92. PEM Certificate
  { regex: /-----BEGIN CERTIFICATE-----/g, title: "PEM Certificate" },

  // 93. PGP Private Key Block
  { regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g, title: "PGP Private Key Block" },

  // 94. Base64 High Entropy String
  { regex: /['"][A-Za-z0-9+\/]{40,}={0,2}['"]/g, title: "Base64 High Entropy String" },

  // 95. API Key Generic Detector
  { regex: /(apikey|api_key|secret|token)['"\s:=]+[a-zA-Z0-9\-._]{8,}/gi, title: "API Key Generic Detector" },

  // 96. Bearer Token Generic
  { regex: /authorization:\s*Bearer\s+[a-zA-Z0-9\-._~+/]+=*/gi, title: "Bearer Token Generic" },

  // 97. Session ID
  { regex: /(sessionid|session_id)['"\s:=]+[a-zA-Z0-9]{10,}/gi, title: "Session ID" },

  // 98. Cookie Name Generic
  { regex: /set-cookie:\s*[a-zA-Z0-9_-]+=/gi, title: "Cookie Name Generic" },

  // 99. CSRF Token
  { regex: /csrf(token)?['"\s:=]+[a-zA-Z0-9-_]{8,}/gi, title: "CSRF Token" },

  // 100. JWT in Local Storage
  { regex: /localStorage\.setItem\(['"]token['"],\s*['"]eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+['"]\)/g, title: "JWT in Local Storage" },

  // Extra from https://github.com/h33tlit/secret-regex-list
  { regex: /cloudinary:\/\/.*/g, title: "Cloudinary (Any)" },
  { regex: /.*firebaseio\.com/g, title: "Firebase URL (Any)" },
  { regex: /-----BEGIN RSA PRIVATE KEY-----/g, title: "RSA private key" },
  { regex: /-----BEGIN DSA PRIVATE KEY-----/g, title: "SSH (DSA) private key" },
  { regex: /-----BEGIN EC PRIVATE KEY-----/g, title: "SSH (EC) private key" },
  { regex: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, title: "Amazon MWS Auth Token" },
  { regex: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g, title: "Google OAuth Client ID" },
  { regex: /"type":\s*"service_account"/g, title: "Google (GCP) Service-account" },
  { regex: /ya29\.[0-9A-Za-z\-_]+/g, title: "Google OAuth Access Token" },
  { regex: /[hH]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/g, title: "Heroku API Key (UUID)" },
  { regex: /[a-zA-Z]{3,10}:\/\/[^\/\s:@]{3,20}:[^\/\s:@]{3,20}@.{1,100}["'\s]/g, title: "Password in URL" },
  { regex: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g, title: "PayPal Braintree Access Token" },
  { regex: /sq0atp-[0-9A-Za-z\-_]{22}/g, title: "Square Access Token" },
  { regex: /sq0csp-[0-9A-Za-z\-_]{43}/g, title: "Square OAuth Secret" },
  { regex: /Jenkins-Crumb:\s*[a-z0-9]{30,}/g, title: "Jenkins Crumb Token (dup)" }
], t = {}; a.forEach(({ regex: n, title: e }) => { const o = s.match(n); if (o && o.length > 0) { const c = [...new Set(o)], g = `Sniffed ${e}: ${c.join(` `)}`; t[e] = { title: e, reporter: "SecretSniffer", request: f, description: g, dedupeKey: c.join(""), severity: "high" }; } else r.console.log(`No matches found for ${e}`); }); for (const n in t) if (t.hasOwnProperty(n)) { const e = t[n]; await r.findings.create(e); } } export { l as run };
