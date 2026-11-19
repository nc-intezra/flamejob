//! flamejob-client: a typed async HTTP client over the flamejob-api DTOs.
//! The CLI, and later the TUI, call these methods so every client stays in
//! lock-step with the server contract.
use anyhow::{Context, Result};
use flamejob_api::*;
use reqwest::{Client as HttpClient, Method, RequestBuilder};
use uuid::Uuid;

pub struct Client {
    base: String,
    http: HttpClient,
    token: Option<String>,
}

impl Client {
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            http: HttpClient::new(),
            token: None,
        }
    }

    pub fn with_token(mut self, token: Option<String>) -> Self {
        self.token = token;
        self
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        let mut rb = self.http.request(method, format!("{}{}", self.base, path));
        if let Some(t) = &self.token {
            rb = rb.bearer_auth(t);
        }
        rb
    }

    pub async fn login(&self, req: &LoginRequest) -> Result<LoginResponse> {
        let resp = self
            .request(Method::POST, "/auth/login")
            .json(req)
            .send()
            .await?
            .error_for_status()
            .context("login failed")?;
        Ok(resp.json().await?)
    }

    pub async fn me(&self) -> Result<MeResponse> {
        Ok(self
            .request(Method::GET, "/auth/me")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn list_jobs(&self) -> Result<Vec<JobView>> {
        Ok(self
            .request(Method::GET, "/jobs")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn create_job(&self, req: &JobCreate) -> Result<JobView> {
        Ok(self
            .request(Method::POST, "/jobs")
            .json(req)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn get_job(&self, id: Uuid) -> Result<JobView> {
        Ok(self
            .request(Method::GET, &format!("/jobs/{id}"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn job_action(&self, id: Uuid, action: &str) -> Result<()> {
        self.request(Method::POST, &format!("/jobs/{id}/{action}"))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn set_priority(&self, id: Uuid, priority: i32) -> Result<()> {
        self.request(Method::PATCH, &format!("/jobs/{id}"))
            .json(&serde_json::json!({ "priority": priority }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn list_hashlists(&self) -> Result<Vec<HashlistView>> {
        Ok(self
            .request(Method::GET, "/hashlists")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn create_hashlist(&self, req: &HashlistCreate) -> Result<HashlistView> {
        Ok(self
            .request(Method::POST, "/hashlists")
            .json(req)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
    pub async fn list_cracked(&self, hashlist_id: Uuid) -> Result<Vec<CrackedHash>> {
        Ok(self
            .request(Method::GET, &format!("/hashlists/{hashlist_id}/cracked"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}
