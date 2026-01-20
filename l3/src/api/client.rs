//! HTTP client for the crypto challenge API

use once_cell::sync::OnceCell;
use reqwest::blocking::Client;
use std::time::Duration;

use super::error::ApiError;
use super::types::*;

/// Base URL for the crypto challenge service
pub const API_BASE_URL: &str = "https://crypto25.random-oracle.xyz";

/// HTTP client for interacting with the crypto challenge service
pub struct CryptoApiClient {
    client: Client,
    base_url: String,
    // Cached parameters to avoid redundant HTTP calls
    modp_params: OnceCell<ModPParams>,
    f2m_params: OnceCell<F2mParams>,
    fpk_params: OnceCell<FpkParams>,
    ecp_params: OnceCell<ECPParams>,
    ec2m_params: OnceCell<EC2mParams>,
    ecpk_params: OnceCell<ECPkParams>,
}

impl CryptoApiClient {
    /// Create a new API client with default settings
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            base_url: API_BASE_URL.to_string(),
            modp_params: OnceCell::new(),
            f2m_params: OnceCell::new(),
            fpk_params: OnceCell::new(),
            ecp_params: OnceCell::new(),
            ec2m_params: OnceCell::new(),
            ecpk_params: OnceCell::new(),
        }
    }

    /// Create with custom base URL (for testing)
    pub fn with_base_url(base_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            base_url: base_url.to_string(),
            modp_params: OnceCell::new(),
            f2m_params: OnceCell::new(),
            fpk_params: OnceCell::new(),
            ecp_params: OnceCell::new(),
            ec2m_params: OnceCell::new(),
            ecpk_params: OnceCell::new(),
        }
    }

    /// Test basic connectivity
    pub fn test_connection(&self) -> Result<BaseResponse, ApiError> {
        let url = format!("{}/", self.base_url);
        let response = self.client.get(&url).send()?;
        let body: BaseResponse = response.json()?;
        Ok(body)
    }

    // ========================================================================
    // Parameter Endpoints
    // ========================================================================

    /// Get test parameters for a challenge type
    pub fn get_test_params(
        &self,
        challenge_type: ChallengeType,
    ) -> Result<ParamResponse, ApiError> {
        let url = format!("{}/test/param/{}", self.base_url, challenge_type);
        let response = self.client.get(&url).send()?;
        let body: ParamResponse = response.json()?;
        Ok(body)
    }

    /// Get ModP parameters (cached)
    pub fn get_modp_params(&self) -> Result<&ModPParams, ApiError> {
        self.modp_params.get_or_try_init(|| {
            let resp = self.get_test_params(ChallengeType::Modp)?;
            let params: ModPParams = serde_json::from_value(resp.params)?;
            Ok(params)
        })
    }

    /// Get F2m parameters (cached)
    pub fn get_f2m_params(&self) -> Result<&F2mParams, ApiError> {
        self.f2m_params.get_or_try_init(|| {
            let resp = self.get_test_params(ChallengeType::F2m)?;
            let params: F2mParams = serde_json::from_value(resp.params)?;
            Ok(params)
        })
    }

    /// Get Fpk parameters (cached)
    pub fn get_fpk_params(&self) -> Result<&FpkParams, ApiError> {
        self.fpk_params.get_or_try_init(|| {
            let resp = self.get_test_params(ChallengeType::Fpk)?;
            let params: FpkParams = serde_json::from_value(resp.params)?;
            Ok(params)
        })
    }

    /// Get ECP parameters (cached)
    pub fn get_ecp_params(&self) -> Result<&ECPParams, ApiError> {
        self.ecp_params.get_or_try_init(|| {
            let resp = self.get_test_params(ChallengeType::Ecp)?;
            let params: ECPParams = serde_json::from_value(resp.params)?;
            Ok(params)
        })
    }

    /// Get EC2m parameters (cached)
    pub fn get_ec2m_params(&self) -> Result<&EC2mParams, ApiError> {
        self.ec2m_params.get_or_try_init(|| {
            let resp = self.get_test_params(ChallengeType::Ec2m)?;
            let params: EC2mParams = serde_json::from_value(resp.params)?;
            Ok(params)
        })
    }

    /// Get ECPk parameters (cached)
    pub fn get_ecpk_params(&self) -> Result<&ECPkParams, ApiError> {
        self.ecpk_params.get_or_try_init(|| {
            let resp = self.get_test_params(ChallengeType::Ecpk)?;
            let params: ECPkParams = serde_json::from_value(resp.params)?;
            Ok(params)
        })
    }

    // ========================================================================
    // Test DH Endpoints
    // ========================================================================

    /// Test DH for ModP
    pub fn test_dh_modp(&self, client_public: &str) -> Result<TestDHModPResponse, ApiError> {
        let url = format!("{}/test/dh/modp", self.base_url);
        let request = TestDHModPRequest {
            client_public: client_public.to_string(),
        };
        let response = self.client.post(&url).json(&request).send()?;
        let body: TestDHModPResponse = response.json()?;
        Ok(body)
    }

    /// Test DH for F2m
    pub fn test_dh_f2m(&self, client_public: &str) -> Result<TestDHF2mResponse, ApiError> {
        let url = format!("{}/test/dh/f2m", self.base_url);
        let request = TestDHF2mRequest {
            client_public: client_public.to_string(),
        };
        let response = self.client.post(&url).json(&request).send()?;
        let body: TestDHF2mResponse = response.json()?;
        Ok(body)
    }

    /// Test DH for Fpk
    pub fn test_dh_fpk(&self, client_public: Vec<String>) -> Result<TestDHFpkResponse, ApiError> {
        let url = format!("{}/test/dh/fpk", self.base_url);
        let request = TestDHFpkRequest { client_public };
        let response = self.client.post(&url).json(&request).send()?;
        let body: TestDHFpkResponse = response.json()?;
        Ok(body)
    }

    /// Test DH for ECP
    pub fn test_dh_ecp(
        &self,
        client_public: ECPPoint,
    ) -> Result<TestDHECResponse<ECPPoint>, ApiError> {
        let url = format!("{}/test/dh/ecp", self.base_url);
        let request = TestDHECRequest { client_public };
        let response = self.client.post(&url).json(&request).send()?;
        let body: TestDHECResponse<ECPPoint> = response.json()?;
        Ok(body)
    }

    /// Test DH for EC2m
    pub fn test_dh_ec2m(
        &self,
        client_public: EC2mPoint,
    ) -> Result<TestDHECResponse<EC2mPoint>, ApiError> {
        let url = format!("{}/test/dh/ec2m", self.base_url);
        let request = TestDHECRequest { client_public };
        let response = self.client.post(&url).json(&request).send()?;
        let body: TestDHECResponse<EC2mPoint> = response.json()?;
        Ok(body)
    }

    /// Test DH for ECPk
    pub fn test_dh_ecpk(
        &self,
        client_public: ECPkPoint,
    ) -> Result<TestDHECResponse<ECPkPoint>, ApiError> {
        let url = format!("{}/test/dh/ecpk", self.base_url);
        let request = TestDHECRequest { client_public };
        let response = self.client.post(&url).json(&request).send()?;
        let body: TestDHECResponse<ECPkPoint> = response.json()?;
        Ok(body)
    }

    // ========================================================================
    // Test Signature Endpoints
    // ========================================================================

    /// Test signature for a challenge type
    pub fn test_signature(
        &self,
        challenge_type: ChallengeType,
        message: &str,
    ) -> Result<TestSignatureResponse, ApiError> {
        let url = format!("{}/test/sign/{}", self.base_url, challenge_type);
        let request = TestSignatureRequest {
            message: message.to_string(),
        };
        let response = self.client.post(&url).json(&request).send()?;
        let body: TestSignatureResponse = response.json()?;
        Ok(body)
    }
}

impl Default for CryptoApiClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection() {
        let client = CryptoApiClient::new();
        match client.test_connection() {
            Ok(resp) => {
                println!("Connection test: {}", resp.status);
                assert_eq!(resp.status, "success");
            }
            Err(e) => {
                println!("Connection test failed (may be network issue): {}", e);
            }
        }
    }
}
