async function l({ request: f, response: A }, r) {
  if (!A) return;

  const body = A.getBody()?.toText();
  if (!body) return;

  // Limit displayed hits per detector to avoid giant findings
  const MAX_HITS_PER_RULE = 20;

  /**
   * Helper: run regex globally, return unique matches (up to limit).
   * Uses matchAll so it works reliably across engines.
   */
  function findMatches(text, regex, limit = MAX_HITS_PER_RULE) {
    const out = [];
    const seen = new Set();

    // Ensure global flag so matchAll iterates all
    const flags = regex.flags.includes("g") ? regex.flags : regex.flags + "g";
    const re = new RegExp(regex.source, flags);

    for (const m of text.matchAll(re)) {
      const hit = m[0];
      if (!seen.has(hit)) {
        seen.add(hit);
        out.push(hit);
        if (out.length >= limit) break;
      }
    }
    return out;
  }

  // ---- Detectors (combined + normalized) ----
  // NOTE: Use RegExp literals where possible. For patterns coming as strings, compile them.
  const detectors = [
    // API Keys & Tokens
    { title: "AWS Access Key ID", severity: "high", regex: /\bAKIA[0-9A-Z]{16}\b/g },
    { title: "AWS Access Key ID (Alt Prefixes)", severity: "high", regex: /\b(A3T[A-Z0-9]{13}|AGPA[0-9A-Z]{16}|AIDA[0-9A-Z]{16}|AROA[0-9A-Z]{16}|AIPA[0-9A-Z]{16}|ANPA[0-9A-Z]{16}|ANVA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b/g },

    { title: "AWS Secret Access Key (Context)", severity: "high", regex: /(?i)aws(.{0,20})?(?-i)['"][0-9a-zA-Z\/+]{40}['"]/g },

    { title: "Google API Key", severity: "high", regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
    { title: "Firebase Secret", severity: "high", regex: /\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b/g },

    { title: "GitHub Token (Classic)", severity: "high", regex: /\bghp_[0-9a-zA-Z]{36}\b/g },
    { title: "GitHub Token (Fine-grained)", severity: "high", regex: /\bgithub_pat_[0-9A-Za-z_]{20,}\b/g },

    { title: "GitLab Token (PAT)", severity: "high", regex: /\bglpat-[0-9A-Za-z\-_]{20}\b/g },
    { title: "GitLab Runner Token", severity: "high", regex: /\bglrt-[0-9A-Za-z\-_]{20}\b/g },

    { title: "Slack Token (Generic)", severity: "high", regex: /\bxox[baprs]-([0-9a-zA-Z]{10,48})?\b/g },
    { title: "Slack Token (Strict)", severity: "high", regex: /\b(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})\b/g },
    { title: "Slack Webhook", severity: "high", regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}/g },

    { title: "Stripe Secret Key", severity: "high", regex: /\bsk_live_[0-9a-zA-Z]{24}\b/g },
    { title: "Stripe Publishable Key", severity: "medium", regex: /\bpk_live_[0-9a-zA-Z]{24}\b/g },
    { title: "Stripe Restricted Key", severity: "high", regex: /\brk_live_[0-9a-zA-Z]{24}\b/g },

    { title: "Twilio API Key", severity: "high", regex: /\bSK[0-9a-fA-F]{32}\b/g },
    { title: "SendGrid API Key", severity: "high", regex: /\bSG\.[\w\d\-_]{22}\.[\w\d\-_]{43}\b/g },
    { title: "Mailgun API Key", severity: "high", regex: /\bkey-[0-9a-zA-Z]{32}\b/g },
    { title: "Dropbox Access Token", severity: "high", regex: /\bsl\.[A-Za-z0-9_-]{20,100}\b/g },
    { title: "Shopify Access Token", severity: "high", regex: /\bshpat_[0-9a-fA-F]{32}\b/g },
    { title: "Facebook Access Token", severity: "high", regex: /\bEAACEdEose0cBA[0-9A-Za-z]+\b/g },
    { title: "DigitalOcean Token", severity: "high", regex: /\bdop_v1_[a-z0-9]{64}\b/g },
    { title: "Asana Personal Access Token", severity: "high", regex: /\b0\/[0-9a-z]{32}\b/g },
    { title: "Linear API Key", severity: "high", regex: /\blin_api_[a-zA-Z0-9]{40}\b/g },
    { title: "Telegram Bot Token", severity: "high", regex: /\b\d{9}:[a-zA-Z0-9_-]{35}\b/g },

    // OAuth & JWT
    { title: "OAuth Client Secret", severity: "high", regex: /(?i)client_secret['"\s:=]+[a-zA-Z0-9\-_.~]{10,100}/g },
    { title: "OAuth Client ID", severity: "medium", regex: /(?i)client_id['"\s:=]+[a-zA-Z0-9\-_.~]{10,100}/g },
    { title: "JWT Token", severity: "medium", regex: /\beyJ[A-Za-z0-9-_=]+?\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b/g },
    { title: "Azure Client Secret (Context)", severity: "high", regex: /(?i)azure(.{0,20})?client\.secret(.{0,20})?['"][a-zA-Z0-9._%+-]{32,}['"]/g },
    { title: "Microsoft Teams Webhook", severity: "high", regex: /https:\/\/[a-z]+\.webhook\.office\.com\/webhookb2\/[a-zA-Z0-9@\-]+\/.*/g },

    // Credentials & Passwords (very FP-prone → keep medium)
    { title: "Basic Auth String (user+pass)", severity: "medium", regex: /(?i)(username|user|email)['"\s:=]+[^\s'"@]{1,100}['"].*?(password|pwd)['"\s:=]+[^\s'"]{4,100}/g },
    { title: "Password Assignment", severity: "medium", regex: /(?i)(password|pwd|pass)['"\s:=]+[^\s'"]{4,100}/g },
    { title: "API Key in Variable", severity: "medium", regex: /(?i)(api[_-]?key)['"\s:=]+[a-zA-Z0-9\-_.]{8,100}/g },
    { title: "Secret/Token in Variable", severity: "medium", regex: /(?i)(secret|token)['"\s:=]+[a-zA-Z0-9\-_.]{8,100}/g },
    { title: "Authorization Bearer Token", severity: "medium", regex: /\bBearer\s+[a-zA-Z0-9\-._~+/]+=*\b/g },

    // Database URLs
    { title: "MongoDB Connection URI", severity: "high", regex: /mongodb(\+srv)?:\/\/[^\s'"]+/g },
    { title: "PostgreSQL URI", severity: "high", regex: /postgres(?:ql)?:\/\/[^\s'"]+/g },
    { title: "MySQL URI", severity: "high", regex: /mysql:\/\/[^\s'"]+/g },
    { title: "Redis URI", severity: "high", regex: /redis:\/\/[^\s'"]+/g },
    { title: "Elasticsearch URI", severity: "high", regex: /elasticsearch:\/\/[^\s'"]+/g },
    { title: "JDBC URL", severity: "high", regex: /jdbc:\w+:\/\/[^\s'"]+/g },
    { title: "AWS RDS Hostname", severity: "medium", regex: /\b[a-z0-9-]+\.rds\.amazonaws\.com\b/g },
    { title: "Cloud SQL URI (GCP)", severity: "medium", regex: /googleapis\.com\/sql\/v1beta4\/projects\//g },
    { title: "Supabase (Domain-ish)", severity: "medium", regex: /supabase\.co\/[a-z0-9]{15,}/g },
    { title: "Firebase URL", severity: "medium", regex: /https:\/\/[a-z0-9-]+\.firebaseio\.com/g },

    // Other Service Credentials
    { title: "Algolia Key (Context)", severity: "high", regex: /(?i)(algolia|application)_?key['"\s:=]+[a-zA-Z0-9]{10,}/g },
    { title: "Firebase API Key in Config Block", severity: "high", regex: /firebaseConfig\s*=\s*{[^}]*apiKey\s*:\s*['"][^'"]+['"]/g },
    { title: "Cloudinary URL", severity: "high", regex: /cloudinary:\/\/[0-9]{15}:[a-zA-Z0-9]+@[a-zA-Z]+/g },
    { title: "Sentry DSN", severity: "high", regex: /https:\/\/[a-zA-Z0-9]+@[a-z]+\.ingest\.sentry\.io\/\d+/g },
    { title: "Netlify Token", severity: "high", regex: /netlifyAuthToken\s*=\s*['"][a-z0-9]{40}['"]/g },
    { title: "Segment API Key (Context)", severity: "high", regex: /(?i)segment(.{0,20})?key['"\s:=]+[a-zA-Z0-9]{10,}/g },
    { title: "Intercom Token (Context)", severity: "high", regex: /(?i)intercom(.{0,20})?token['"\s:=]+[a-zA-Z0-9-_]{20,}/g },
    { title: "Amplitude API Key", severity: "high", regex: /apiKey['"]?\s*:\s*['"][a-z0-9\-]{32,64}['"]/g },
    { title: "Plaid Client Secret (Context)", severity: "high", regex: /plaid(.{0,20})?(client)?secret['"\s:=]+[a-z0-9-_]{30,}/g },

    // Container & Deployment Secrets
    { title: "Docker Password (Context)", severity: "high", regex: /(?i)docker(.{0,20})?password['"\s:=]+[^\s'"]{8,}/g },
    { title: "AWS IAM Role ARN", severity: "medium", regex: /\barn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9_+=,.@\-_/]+\b/g },
    { title: "AWS S3 Bucket URL", severity: "medium", regex: /\bs3:\/\/[a-z0-9\-\.]{3,63}\b/g },
    { title: "Kubernetes secretName", severity: "low", regex: /(?i)secretName:\s*['"]?[a-z0-9\-]+['"]?/g },
    { title: "Helm Secret Value (very generic)", severity: "low", regex: /(?i)secret\s*:\s*['"][^'"]+['"]/g },
    { title: "GitHub Actions Secret Ref", severity: "low", regex: /secrets\.[A-Z0-9_]+/g },
    { title: "GitHub Actions Encrypted Value", severity: "low", regex: /encrypted_value:\s*['"][a-zA-Z0-9+/=]{10,}['"]/g },
    { title: "K8s Service Account Token (JWT header)", severity: "medium", regex: /eyJhbGciOiJSUzI1NiIsImtpZCI6/g },
    { title: "Vault Token", severity: "high", regex: /\bs\.[a-zA-Z0-9]{8,}\b/g },
    { title: "Vault URL", severity: "medium", regex: /https:\/\/vault\.[a-z0-9\-_\.]+\.com/g },

    // DevOps & CI/CD Credentials
    { title: "CircleCI Token", severity: "high", regex: /circle-token=[a-z0-9]{40}/g },
    { title: "Travis Token (Context)", severity: "high", regex: /(?i)travis(.{0,20})?token['"\s:=]+[a-z0-9]{30,}/g },
    { title: "Jenkins Crumb Token (Header)", severity: "medium", regex: /Jenkins-Crumb:\s*[a-z0-9]{30,}/g },
    { title: "Azure DevOps Token (very FP)", severity: "low", regex: /\b[a-z0-9]{52}\b/g },

    // SDKs & Tooling Keys
    { title: "Bugsnag API Key (very FP)", severity: "low", regex: /\b[a-f0-9]{32}\b/g },
    { title: "Datadog API Key (very FP)", severity: "low", regex: /\b[a-z0-9]{32}\b/g },
    { title: "Loggly Token", severity: "medium", regex: /\b[a-z0-9]{30}-[a-z0-9]{10}\b/g },
    { title: "New Relic Key", severity: "high", regex: /\bNRII-[a-zA-Z0-9]{20,}\b/g },
    { title: "Mixpanel Token (Context)", severity: "medium", regex: /(?i)mixpanel(.{0,20})?token['"\s:=]+[a-z0-9]{32}/g },
    { title: "Heap App ID", severity: "medium", regex: /heapSettings\.appId\s*=\s*['"][a-z0-9]{8,12}['"]/g },
    { title: "Keen Project ID", severity: "medium", regex: /projectId['"]?\s*:\s*['"][a-f0-9]{24}['"]/g },
    { title: "Keen Write Key", severity: "high", regex: /writeKey['"]?\s*:\s*['"][a-zA-Z0-9]{64}['"]/g },
    { title: "Snyk Token", severity: "high", regex: /snyk_token\s*=\s*[a-f0-9\-]{36}/g },
    { title: "Rollbar Access Token", severity: "high", regex: /access_token['"]?\s*:\s*['"][a-z0-9]{32}['"]/g },

    // App & Game APIs
    { title: "Twitch Key (Context)", severity: "medium", regex: /(?i)twitch(.{0,20})?key['"\s:=]+[a-zA-Z0-9]{20,}/g },
    { title: "Discord Bot Token", severity: "high", regex: /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/g },
    { title: "Discord Webhook URL", severity: "high", regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+/g },
    { title: "Riot Games API Key", severity: "high", regex: /RGAPI-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g },

    // URL Leaks & Internal Endpoints
    { title: "Private IP (Internal)", severity: "low", regex: /\b(10\.\d{1,3}|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b/g },
    { title: "Localhost Reference", severity: "low", regex: /localhost:[0-9]{2,5}/g },
    { title: "Dev/Stage URL", severity: "low", regex: /\b(dev|staging|test)\.[a-z0-9.-]+\.(com|net|io)\b/g },
    { title: "Internal Subdomain URL", severity: "low", regex: /https?:\/\/[a-z0-9.-]+\.internal\.[a-z]{2,}/g },
    { title: "Preprod URL", severity: "low", regex: /https:\/\/preprod\.[a-z0-9-]+\.[a-z]{2,}/g },

    // Misc
    { title: "Private Key Block", severity: "high", regex: /-----BEGIN (RSA|DSA|EC|OPENSSH)? PRIVATE KEY-----/g },
    { title: "PEM Certificate Block", severity: "medium", regex: /-----BEGIN CERTIFICATE-----/g },
    { title: "PGP Private Key Block", severity: "high", regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g },
    { title: "Base64 High Entropy String (Generic)", severity: "low", regex: /['"][A-Za-z0-9+\/]{40,}={0,2}['"]/g },
    { title: "Generic API Key Detector", severity: "low", regex: /(?i)(apikey|api_key|secret|token)['"\s:=]+[a-zA-Z0-9\-._]{8,}/g },
    { title: "Generic Bearer (Header-like)", severity: "low", regex: /(?i)authorization:\s*Bearer\s+[a-zA-Z0-9\-._~+/]+=*/g },
    { title: "Session ID", severity: "low", regex: /(?i)(sessionid|session_id)['"\s:=]+[a-zA-Z0-9]{10,}/g },
    { title: "Set-Cookie Generic", severity: "low", regex: /(?i)set-cookie:\s*[a-zA-Z0-9_-]+=/g },
    { title: "CSRF Token", severity: "low", regex: /(?i)csrf(token)?['"\s:=]+[a-zA-Z0-9-_]{8,}/g },
    { title: "JWT in Local Storage", severity: "medium", regex: /localStorage\.setItem\(['"]token['"],\s*['"]eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+['"]\)/g },

    // --- Extra patterns from your JSON-map (string patterns) ---
    { title: "Amazon MWS Auth Token", severity: "high", regex: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g },
    { title: "Google OAuth Access Token (ya29.)", severity: "high", regex: /ya29\.[0-9A-Za-z\-_]+/g },
    { title: "GCP OAuth Client ID (googleusercontent)", severity: "medium", regex: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g },
    { title: "GCP Service Account Marker", severity: "high", regex: /"type":\s*"service_account"/g },
    { title: "Heroku API Key (UUID style)", severity: "high", regex: /[hH]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/g },
    { title: "Password in URL", severity: "high", regex: /[a-zA-Z]{3,10}:\/\/[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["'\s]/g },
    { title: "PayPal Braintree Access Token", severity: "high", regex: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g },
    { title: "Square Access Token", severity: "high", regex: /sq0atp-[0-9A-Za-z\-_]{22}/g },
    { title: "Square OAuth Secret", severity: "high", regex: /sq0csp-[0-9A-Za-z\-_]{43}/g },
    { title: "Twitter Access Token (Context)", severity: "medium", regex: /[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}/g },
    { title: "Facebook OAuth (Context)", severity: "medium", regex: /[fF][aA][cC][eE][bB][oO][oO][kK].*['"][0-9a-f]{32}['"]/g },
    { title: "GitHub OAuth App Secret (FP prone)", severity: "low", regex: /\b[a-f0-9]{40}\b/g },
    { title: "Generic API Key (32-45 in quotes)", severity: "low", regex: /[aA][pP][iI]_?[kK][eE][yY].*['"][0-9a-zA-Z]{32,45}['"]/g },
    { title: "Generic Secret (32-45 in quotes)", severity: "low", regex: /[sS][eE][cC][rR][eE][tT].*['"][0-9a-zA-Z]{32,45}['"]/g },
  ];

  // ---- Run detectors & build findings ----
  const findings = {};

  for (const { title, regex, severity } of detectors) {
    const hits = findMatches(body, regex);

    if (hits.length > 0) {
      const description = `Sniffed ${title}:\n\n${hits.join("\n")}${
        hits.length >= MAX_HITS_PER_RULE ? `\n\n(Showing first ${MAX_HITS_PER_RULE} unique matches)` : ""
      }`;

      // Dedupe key should be stable and not huge
      const dedupeKey = `${title}:${hits.join("|")}`.slice(0, 5000);

      findings[title] = {
        title,
        reporter: "SecretSniffer",
        request: f,
        description,
        dedupeKey,
        severity,
      };
    } else {
      // keep logs light (optional)
      // r.console.log(`No matches found for ${title}`);
    }
  }

  // ---- Create findings ----
  for (const key in findings) {
    if (Object.prototype.hasOwnProperty.call(findings, key)) {
      await r.findings.create(findings[key]);
    }
  }
}

export { l as run };
