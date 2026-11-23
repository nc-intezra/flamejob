//! Assembles the served OpenAPI document.
//!
//! The wire DTOs (schemas) live in `flamejob-api`; the operation annotations
//! (`#[utoipa::path]`) live next to their handlers in this crate. This module
//! merges the two — the api crate's schemas plus this crate's paths and the
//! bearer security scheme — into the single document served at `/openapi.json`.
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    modifiers(&SecurityAddon),
    components(schemas(crate::routes::PatchJob, crate::routes::PinRequest)),
    tags(
        (name = "auth", description = "Login and identity"),
        (name = "jobs", description = "Job queue and control"),
        (name = "hashlists", description = "Hashlists and cracked results"),
        (name = "files", description = "Wordlist / rule / mask uploads"),
        (name = "telemetry", description = "Device metrics"),
        (name = "agents", description = "Distributed worker fleet"),
        (name = "meta", description = "Health and events"),
    ),
    paths(
        crate::routes::login,
        crate::routes::me,
        crate::routes::create_api_key,
        crate::routes::list_api_keys,
        crate::routes::revoke_api_key,
        crate::routes::list_jobs,
        crate::routes::create_job,
        crate::routes::clear_finished_jobs,
        crate::routes::list_job_history,
        crate::routes::get_job,
        crate::routes::patch_job,
        crate::routes::list_job_tasks,
        crate::routes::pause_job,
        crate::routes::resume_job,
        crate::routes::cancel_job,
        crate::routes::pin_job,
        crate::routes::unpin_job,
        crate::routes::list_hashlists,
        crate::routes::create_hashlist,
        crate::routes::list_cracked,
        crate::routes::import_hashes,
        crate::routes::list_files,
        crate::routes::upload_file,
        crate::routes::delete_file,
        crate::routes::events,
        crate::routes::create_user,
        crate::settings::get_site_settings,
        crate::settings::put_site_settings,
        crate::routes::list_devices,
        crate::routes::device_history,
        crate::agent::list_agents,
        crate::agent::create_claim,
        crate::agent::enroll,
    )
)]
struct Paths;

/// The merged OpenAPI document served at `/openapi.json`.
pub fn document() -> utoipa::openapi::OpenApi {
    let mut base = flamejob_api::ApiDoc::openapi();
    let mut paths = Paths::openapi();
    base.paths = paths.paths;
    if let Some(src) = paths.components.take() {
        let dst = base.components.get_or_insert_with(Default::default);
        dst.schemas.extend(src.schemas);
        dst.security_schemes.extend(src.security_schemes);
    }
    // Stamp the live crate version so the served API version always matches the
    // release instead of drifting from a hand-maintained literal.
    base.info.version = env!("CARGO_PKG_VERSION").to_string();
    base
}
