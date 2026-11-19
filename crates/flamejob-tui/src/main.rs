//! flamejob-tui: live ratatui dashboard. Polls the API via flamejob-client.
use std::io::stdout;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use flamejob_client::Client;
use flamejob_tui::{app, model::Dashboard, ui};

fn load_token() -> Option<String> {
    if let Ok(t) = std::env::var("FJ_TOKEN") {
        return Some(t);
    }
    let home = std::env::var("HOME").ok()?;
    std::fs::read_to_string(format!("{home}/.config/flamejob/token"))
        .ok()
        .map(|s| s.trim().to_string())
}

fn empty(server: &str) -> Dashboard {
    Dashboard {
        server: server.to_string(),
        now: chrono::Utc::now(),
        jobs: Vec::new(),
        selected: 0,
        chunks: Vec::new(),
        devices: Vec::new(),
        telemetry_live: false,
    }
}

fn refresh(
    rt: &tokio::runtime::Runtime,
    client: &Client,
    server: &str,
    selected: usize,
    dash: &mut Dashboard,
) {
    if let Ok(d) = rt.block_on(app::fetch_dashboard(client, server, selected)) {
        *dash = d;
    }
}

fn run(
    term: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    rt: &tokio::runtime::Runtime,
    client: &Client,
    server: &str,
) -> Result<()> {
    let mut selected = 0usize;
    let mut dash = rt
        .block_on(app::fetch_dashboard(client, server, selected))
        .unwrap_or_else(|_| empty(server));
    let mut last = Instant::now();
    loop {
        term.draw(|f| ui::render(f, &dash))?;
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(k) = event::read()? {
                match k.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Down | KeyCode::Char('j') => {
                        selected = selected
                            .saturating_add(1)
                            .min(dash.jobs.len().saturating_sub(1));
                        refresh(rt, client, server, selected, &mut dash);
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        selected = selected.saturating_sub(1);
                        refresh(rt, client, server, selected, &mut dash);
                    }
                    KeyCode::Char('r') => refresh(rt, client, server, selected, &mut dash),
                    KeyCode::Char('p') => {
                        if let Some(j) = dash.jobs.get(selected) {
                            let _ = rt.block_on(client.job_action(j.id, "pause"));
                        }
                    }
                    KeyCode::Char('c') => {
                        if let Some(j) = dash.jobs.get(selected) {
                            let _ = rt.block_on(client.job_action(j.id, "cancel"));
                        }
                    }
                    _ => {}
                }
            }
        }
        if last.elapsed() >= Duration::from_secs(1) {
            refresh(rt, client, server, selected, &mut dash);
            last = Instant::now();
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let server = std::env::var("FJ_SERVER").unwrap_or_else(|_| "http://localhost:8443".into());
    let client = Client::new(&server).with_token(load_token());
    let rt = tokio::runtime::Runtime::new()?;

    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(stdout()))?;

    let res = run(&mut term, &rt, &client, &server);

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    res
}
