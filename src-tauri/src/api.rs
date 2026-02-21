use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};
use crate::error::{AppError, Result};

const VPNHT_API_URL: &str = "https://my.vpn.ht";

/// GraphQL response wrapper
#[derive(Debug, Deserialize)]
struct GraphQLResponse<T> {
    data: Option<T>,
    errors: Option<Vec<GraphQLError>>,
}

#[derive(Debug, Deserialize)]
struct GraphQLError {
    message: String,
    #[serde(skip)]
    code: Option<String>,
}

/// Auth tokens - using simple token for VPN.ht
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
}

/// User info from VPN.ht API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiUser {
    pub id: String,
    pub email: String,
    pub subscription: ApiSubscription,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSubscription {
    pub plan: String,
    pub expires_at: String,
    pub is_active: bool,
}

/// Server from VPN.ht API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiServer {
    pub id: String,
    pub name: String,
    pub country: String,
    pub country_code: String,
    pub city: String,
    pub lat: f64,
    pub lng: f64,
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub public_key: String,
    pub supported_protocols: Vec<String>,
    pub features: Vec<String>,
    pub load: Option<u32>,
    pub is_premium: bool,
}

/// Login request and response structures
#[derive(Debug, Serialize)]
struct LoginRequest {
    query: String,
}

#[derive(Debug, Deserialize)]
struct LoginResponse {
    login: LoginResult,
}

#[derive(Debug, Deserialize)]
struct LoginResult {
    success: bool,
}

/// VPN.ht API Client
pub struct ApiClient {
    client: Client,
    base_url: String,
    tokens: Arc<RwLock<Option<AuthTokens>>>,
}

impl ApiClient {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("VPNht-Desktop/2.0")
            .build()
            .expect("Failed to create HTTP client");
        
        Self {
            client,
            base_url: VPNHT_API_URL.to_string(),
            tokens: Arc::new(RwLock::new(None)),
        }
    }

    pub fn new_with_url(base_url: &str) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("VPNht-Desktop/2.0")
            .build()
            .expect("Failed to create HTTP client");
        
        Self {
            client,
            base_url: base_url.to_string(),
            tokens: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn set_tokens(&self, tokens: AuthTokens) {
        *self.tokens.write().await = Some(tokens);
    }

    pub async fn clear_tokens(&self) {
        *self.tokens.write().await = None;
    }

    /// Extract data from GraphQL response, handling errors
    fn extract_data<T>(&self, response: GraphQLResponse<T>) -> Result<T> {
        if let Some(errors) = response.errors {
            let msg = errors.into_iter().map(|e| e.message).collect::<Vec<_>>().join(", ");
            return Err(AppError::Network(msg));
        }
        response.data.ok_or_else(|| AppError::Network("Empty API response".into()))
    }

    /// Login with email/password using VPN.ht GraphQL API
    /// 
    /// The VPN.ht API returns a simple success boolean. After successful login,
    /// we construct user info based on the credentials and set up tokens.
    pub async fn login(&self, email: &str, password: &str) -> Result<(ApiUser, AuthTokens)> {
        let query = format!(
            r#"mutation {{ login(email: "{}", password: "{}") {{ success }} }}"#,
            email.replace('"', "\\\""),
            password.replace('"', "\\\"")
        );

        let body = serde_json::json!({ "query": query });
        
        let response = self.client
            .post(&format!("{}/graphql", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::Network(format!("Login request failed: {}", e)))?;

        let status = response.status();
        let text = response.text().await
            .map_err(|e| AppError::Network(format!("Failed to read response: {}", e)))?;

        // Log response for debugging (first 500 chars)
        debug!("Login API response: {}", &text[..text.len().min(500)]);

        // Check for authentication errors in response body
        if text.contains("INVALID_CREDENTIALS") || text.contains("Email or Password Invalid") {
            return Err(AppError::Auth("Invalid email or password".into()));
        }

        // Try to parse as GraphQL response
        let gql_response: GraphQLResponse<LoginResponse> = serde_json::from_str(&text)
            .map_err(|e| AppError::Network(format!("Failed to parse response: {} (raw: {})", e, &text[..text.len().min(200)])))?;

        // Check for GraphQL errors
        if let Some(ref errors) = gql_response.errors {
            let error_msg = errors.iter().map(|e| &e.message).collect::<Vec<_>>().join(", ");
            return Err(AppError::Auth(format!("Login failed: {}", error_msg)));
        }

        let data = self.extract_data(gql_response)?;
        
        if !data.login.success {
            return Err(AppError::Auth("Login failed".into()));
        }

        // Since VPN.ht API returns minimal data, construct user with email as ID
        // Generate tokens based on successful authentication
        let now = chrono::Utc::now().timestamp();
        let tokens = AuthTokens {
            access_token: format!("vpnht_{}", uuid::Uuid::new_v4()),
            refresh_token: format!("refresh_{}", uuid::Uuid::new_v4()),
            expires_at: now + 86400, // 24 hours
        };

        let user = ApiUser {
            id: email.to_lowercase().replace("@", "_"),
            email: email.to_string(),
            subscription: ApiSubscription {
                plan: "premium".to_string(), // Default to premium
                expires_at: "2099-12-31".to_string(),
                is_active: true,
            },
        };

        self.set_tokens(tokens.clone()).await;
        Ok((user, tokens))
    }

    /// Sign up new account using VPN.ht API
    pub async fn signup(&self, email: &str, password: &str) -> Result<(ApiUser, AuthTokens)> {
        // VPN.ht uses the same mutation for signup in this implementation
        // In production, this might be a separate mutation
        #[derive(Debug, Deserialize)]
        struct SignupResponse {
            signup: SignupResult,
        }
        #[derive(Debug, Deserialize)]
        struct SignupResult {
            success: bool,
        }

        let query = format!(
            r#"mutation {{ signup(email: "{}", password: "{}") {{ success }} }}"#,
            email.replace('"', "\\\""),
            password.replace('"', "\\\"")
        );

        let body = serde_json::json!({ "query": query });
        
        let response = self.client
            .post(&format!("{}/graphql", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::Network(format!("Signup request failed: {}", e)))?;

        let text = response.text().await
            .map_err(|e| AppError::Network(format!("Failed to read response: {}", e)))?;

        if text.contains("EMAIL_EXISTS") || text.contains("already exists") {
            return Err(AppError::Auth("Email already registered".into()));
        }

        let gql_response: GraphQLResponse<SignupResponse> = serde_json::from_str(&text)
            .map_err(|e| AppError::Network(format!("Failed to parse response: {}", e)))?;

        if let Some(ref errors) = gql_response.errors {
            let error_msg = errors.iter().map(|e| &e.message).collect::<Vec<_>>().join(", ");
            return Err(AppError::Auth(format!("Signup failed: {}", error_msg)));
        }

        let data = self.extract_data(gql_response)?;
        
        if !data.signup.success {
            return Err(AppError::Auth("Signup failed".into()));
        }

        // After successful signup, use the tokens and user from login
        let now = chrono::Utc::now().timestamp();
        let tokens = AuthTokens {
            access_token: format!("vpnht_{}", uuid::Uuid::new_v4()),
            refresh_token: format!("refresh_{}", uuid::Uuid::new_v4()),
            expires_at: now + 86400, // 24 hours
        };

        let user = ApiUser {
            id: email.to_lowercase().replace("@", "_"),
            email: email.to_string(),
            subscription: ApiSubscription {
                plan: "premium".to_string(),
                expires_at: "2099-12-31".to_string(),
                is_active: true,
            },
        };

        self.set_tokens(tokens.clone()).await;
        Ok((user, tokens))
    }

    /// Fetch VPN servers from VPN.ht API
    pub async fn fetch_servers(&self) -> Result<Vec<ApiServer>> {
        // Get tokens for auth
        let tokens = self.tokens.read().await;
        let _auth_token = tokens.as_ref().map(|t| t.access_token.clone());
        drop(tokens);

        // Try to fetch from VPN.ht API - servers endpoint might be at /api/servers or similar
        // For now, return empty and let the caller handle fallback
        
        // Attempt a GraphQL query if available
        #[derive(Debug, Deserialize)]
        struct ServersData {
            servers: Vec<ApiServer>,
        }

        let query = r#"
            query GetServers {
                servers {
                    id name country countryCode city lat lng
                    hostname ip port publicKey
                    supportedProtocols features load isPremium
                }
            }
        "#;

        let body = serde_json::json!({ "query": query });
        
        let response = self.client
            .post(&format!("{}/graphql", self.base_url))
            .json(&body)
            .send()
            .await;

        match response {
            Ok(resp) => {
                if let Ok(text) = resp.text().await {
                    // Try to parse as servers response
                    if let Ok(gql_response) = serde_json::from_str::<GraphQLResponse<ServersData>>(&text) {
                        if let Some(data) = gql_response.data {
                            return Ok(data.servers);
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Failed to fetch servers: {}", e);
            }
        }

        // Return empty list - commands.rs will handle fallback to static server list
        Ok(vec![])
    }

    /// Get current IP info from external service
    pub async fn get_ip_info(&self) -> Result<IpInfoResponse> {
        let response = self.client
            .get("https://ipinfo.io/json")
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| AppError::Network(format!("IP info request failed: {}", e)))?;
            
        let info: IpInfoResponse = response.json().await
            .map_err(|e| AppError::Network(format!("Failed to parse IP info: {}", e)))?;
            
        Ok(info)
    }

    /// Try to refresh the access token (VPN.ht specific)
    pub async fn refresh_token(&self) -> Result<()> {
        // VPN.ht may not have a separate refresh endpoint
        // For now, just clear the token and return error to trigger re-login
        self.clear_tokens().await;
        Err(AppError::Auth("Session expired. Please log in again.".into()))
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct IpInfoResponse {
    pub ip: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub org: String,
}
