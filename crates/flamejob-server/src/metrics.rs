use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

pub fn recorder() -> anyhow::Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| anyhow::anyhow!("metrics recorder: {e}"))?;
    Ok(handle)
}
