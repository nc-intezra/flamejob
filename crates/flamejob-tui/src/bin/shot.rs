//! Render the dashboard to an off-screen buffer and dump it as JSON cells
//! for turning into a PNG. `tui-shot` renders sample data; `tui-shot live`
//! renders real data from the server named by FJ_SERVER (token from FJ_TOKEN
//! or ~/.config/flamejob/token).
use ratatui::{backend::TestBackend, style::Modifier, Terminal};

use flamejob_tui::{model::Dashboard, model::UiState, ui};

fn live_token() -> Option<String> {
    if let Ok(t) = std::env::var("FJ_TOKEN") {
        return Some(t);
    }
    let home = std::env::var("HOME").ok()?;
    std::fs::read_to_string(format!("{home}/.config/flamejob/token"))
        .ok()
        .map(|s| s.trim().to_string())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let live = args.iter().any(|a| a == "live");
    let (w, h): (u16, u16) = (150, 42);

    let d = if live {
        let server = std::env::var("FJ_SERVER").expect("FJ_SERVER");
        let client = flamejob_client::Client::new(&server).with_token(live_token());
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(flamejob_tui::app::fetch_dashboard(
            &client, &server, 0, false, true,
        ))
        .expect("fetch dashboard")
    } else {
        Dashboard::sample()
    };

    let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
    let mut st = UiState::default();
    term.draw(|f| ui::render(f, &d, &mut st)).unwrap();
    let buf = term.backend().buffer().clone();
    let mut grid = Vec::new();
    for y in 0..h {
        let mut line = Vec::new();
        for x in 0..w {
            let c = &buf[(x, y)];
            let (fr, fg, fb) = ui::rgb(c.fg, false);
            let (br, bg, bb) = ui::rgb(c.bg, true);
            let bold = c.modifier.contains(Modifier::BOLD);
            line.push(
                serde_json::json!({"s": c.symbol(), "f":[fr,fg,fb], "b":[br,bg,bb], "bold": bold}),
            );
        }
        grid.push(line);
    }
    println!("{}", serde_json::json!({"w": w, "h": h, "rows": grid}));
}
