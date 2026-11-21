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
use flamejob_core::{roles_have, Capability};
use flamejob_tui::{app, model::Dashboard, model::UiState, ui};

fn load_token() -> Option<String> {
    if let Ok(t) = std::env::var("FJ_TOKEN") {
        return Some(t);
    }
    let home = std::env::var("HOME").ok()?;
    std::fs::read_to_string(format!("{home}/.config/flamejob/token"))
        .ok()
        .map(|s| s.trim().to_string())
}

fn empty(server: &str, can_submit: bool) -> Dashboard {
    Dashboard {
        server: server.to_string(),
        now: chrono::Utc::now(),
        jobs: Vec::new(),
        selected: 0,
        chunks: Vec::new(),
        devices: Vec::new(),
        agents: Vec::new(),
        telemetry_live: false,
        hide_finished: false,
        can_submit,
        total_jobs: 0,
    }
}

struct View {
    selected: usize,
    hide_finished: bool,
    can_submit: bool,
}

fn refresh(
    rt: &tokio::runtime::Runtime,
    client: &Client,
    server: &str,
    v: &mut View,
    dash: &mut Dashboard,
) {
    if let Ok(d) = rt.block_on(app::fetch_dashboard(
        client,
        server,
        v.selected,
        v.hide_finished,
        v.can_submit,
    )) {
        v.selected = d.selected;
        *dash = d;
    }
}

fn run(
    term: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    rt: &tokio::runtime::Runtime,
    client: &Client,
    server: &str,
    can_submit: bool,
) -> Result<()> {
    let mut v = View {
        selected: 0,
        hide_finished: false,
        can_submit,
    };
    let mut st = UiState::default();
    let mut dash = rt
        .block_on(app::fetch_dashboard(client, server, 0, false, can_submit))
        .unwrap_or_else(|_| empty(server, can_submit));
    v.selected = dash.selected;
    let mut last = Instant::now();
    loop {
        term.draw(|f| ui::render(f, &dash, &mut st))?;
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(k) = event::read()? {
                match k.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Down | KeyCode::Char('j') => {
                        v.selected = v
                            .selected
                            .saturating_add(1)
                            .min(dash.jobs.len().saturating_sub(1));
                        refresh(rt, client, server, &mut v, &mut dash);
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        v.selected = v.selected.saturating_sub(1);
                        refresh(rt, client, server, &mut v, &mut dash);
                    }
                    KeyCode::Char('r') => refresh(rt, client, server, &mut v, &mut dash),
                    KeyCode::Char('f') => {
                        v.hide_finished = !v.hide_finished;
                        v.selected = 0;
                        refresh(rt, client, server, &mut v, &mut dash);
                    }
                    KeyCode::Char('C') if can_submit => {
                        let _ = rt.block_on(client.clear_finished_jobs());
                        v.selected = 0;
                        refresh(rt, client, server, &mut v, &mut dash);
                    }
                    KeyCode::Char('p') if can_submit => {
                        if let Some(j) = dash.jobs.get(v.selected) {
                            let _ = rt.block_on(client.job_action(j.id, "pause"));
                        }
                    }
                    KeyCode::Char('c') if can_submit => {
                        if let Some(j) = dash.jobs.get(v.selected) {
                            let _ = rt.block_on(client.job_action(j.id, "cancel"));
                        }
                    }
                    _ => {}
                }
            }
        }
        if last.elapsed() >= Duration::from_secs(1) {
            refresh(rt, client, server, &mut v, &mut dash);
            last = Instant::now();
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let server = std::env::var("FJ_SERVER").unwrap_or_else(|_| "http://localhost:8443".into());
    let client = Client::new(&server).with_token(load_token());
    let rt = tokio::runtime::Runtime::new()?;

    // Resolve the signed-in user's capabilities once, to gate job controls and
    // the "clear results" action (SubmitJobs: superadmin and operator).
    let can_submit = rt
        .block_on(client.me())
        .map(|me| roles_have(&me.roles, Capability::SubmitJobs))
        .unwrap_or(false);

    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(stdout()))?;

    let res = run(&mut term, &rt, &client, &server, can_submit);

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    res
}
