use chrono::{DateTime, Utc};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Cell, Padding, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table,
    },
    Frame,
};

use crate::model::{Dashboard, Device, JobRow, UiState};

// One Dark-ish palette.
const BG: Color = Color::Rgb(24, 25, 30);
const PANEL: Color = Color::Rgb(33, 35, 42);
const INK: Color = Color::Rgb(205, 210, 220);
const DIM: Color = Color::Rgb(120, 126, 140);
const ACCENT: Color = Color::Rgb(97, 175, 239);
const GOOD: Color = Color::Rgb(152, 195, 121);
const WARN: Color = Color::Rgb(229, 192, 123);
const BAD: Color = Color::Rgb(224, 108, 117);
const BUSY: Color = Color::Rgb(224, 163, 94);
const SEL: Color = Color::Rgb(45, 50, 64);
const TRACK: Color = Color::Rgb(55, 58, 68);

pub fn render(f: &mut Frame, d: &Dashboard, st: &mut UiState) {
    let area = f.area();
    f.render_widget(Block::default().style(Style::default().bg(BG)), area);

    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(area);

    header(f, rows[0], d);

    let body =
        Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)]).split(rows[1]);
    jobs_table(f, body[0], d, st);

    let right = Layout::vertical([
        Constraint::Percentage(44),
        Constraint::Percentage(31),
        Constraint::Percentage(25),
    ])
    .split(body[1]);
    job_detail(f, right[0], d, st);
    devices(f, right[1], d);
    agents(f, right[2], d);

    footer(f, rows[2], d);
}

/// Draw a vertical scrollbar on the right border of `area` when `total` rows
/// exceed the `visible` row budget. `pos` is the index to point at.
fn scrollbar(f: &mut Frame, area: Rect, total: usize, visible: usize, pos: usize) {
    if total <= visible {
        return;
    }
    let mut sbs = ScrollbarState::new(total.saturating_sub(visible).max(1))
        .position(pos.min(total.saturating_sub(1)));
    let sb = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(None)
        .end_symbol(None)
        .track_symbol(Some("│"))
        .thumb_symbol("█")
        .style(Style::default().fg(DIM))
        .thumb_style(Style::default().fg(ACCENT));
    f.render_stateful_widget(sb, area.inner(Margin::new(0, 1)), &mut sbs);
}

fn header(f: &mut Frame, area: Rect, d: &Dashboard) {
    let running = d.jobs.iter().filter(|j| j.state == "running").count();
    let queued = d.jobs.iter().filter(|j| j.state == "queued").count();
    let clock = d.now.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let left = Line::from(vec![
        Span::styled(
            "flamejob",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  queue dashboard", Style::default().fg(DIM)),
        Span::styled(format!("   {running} running"), Style::default().fg(GOOD)),
        Span::styled(format!("  {queued} queued",), Style::default().fg(DIM)),
    ]);
    let right = Line::from(vec![
        Span::styled(format!("{}  ", d.server), Style::default().fg(DIM)),
        Span::styled(clock, Style::default().fg(INK)),
    ])
    .alignment(Alignment::Right);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(PANEL))
        .padding(Padding::horizontal(1));
    let inner = block.inner(area);
    f.render_widget(block, area);
    f.render_widget(Paragraph::new(left), inner);
    f.render_widget(Paragraph::new(right), inner);
}

fn jobs_table(f: &mut Frame, area: Rect, d: &Dashboard, st: &mut UiState) {
    let header = Row::new(["JOB", "STATE", "PROGRESS", "SPEED", "ETA", "CRACKED"])
        .style(Style::default().fg(DIM).add_modifier(Modifier::BOLD));
    let bar_w = 14usize;
    let rows = d.jobs.iter().map(|j| {
        Row::new(vec![
            Cell::from(j.name.clone()).style(Style::default().fg(INK)),
            Cell::from(state_label(&j.state)),
            Cell::from(progress_bar(j.progress, bar_w, &j.state)),
            Cell::from(fmt_speed(j.speed)).style(Style::default().fg(if j.speed > 0 {
                INK
            } else {
                DIM
            })),
            Cell::from(fmt_eta(j.eta, d.now)).style(Style::default().fg(if j.eta.is_some() {
                WARN
            } else {
                DIM
            })),
            Cell::from(format!("{}/{}", j.cracked, j.total))
                .style(Style::default().fg(crack_color(j))),
        ])
    });
    let widths = [
        Constraint::Min(16),
        Constraint::Length(11),
        Constraint::Length(bar_w as u16 + 6),
        Constraint::Length(11),
        Constraint::Length(8),
        Constraint::Length(9),
    ];
    let hidden = d.total_jobs.saturating_sub(d.jobs.len());
    let title = if d.hide_finished && hidden > 0 {
        format!("Jobs · {} shown · {hidden} finished hidden", d.jobs.len())
    } else {
        format!("Jobs · {}", d.jobs.len())
    };
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .block(panel(&title))
        .row_highlight_style(Style::default().bg(SEL));
    if d.jobs.is_empty() {
        st.jobs.select(None);
    } else {
        st.jobs.select(Some(d.selected.min(d.jobs.len() - 1)));
    }
    f.render_stateful_widget(table, area, &mut st.jobs);
    // Data rows visible = inner height (area minus borders) minus the header row.
    let visible = (area.height as usize).saturating_sub(3);
    scrollbar(f, area, d.jobs.len(), visible, d.selected);
}

fn job_detail(f: &mut Frame, area: Rect, d: &Dashboard, st: &mut UiState) {
    let title = match d.selected_job() {
        Some(j) => format!("Job · {}", j.name),
        None => "Job".into(),
    };
    let block = panel(&title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let parts = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(0),
        Constraint::Length(2),
    ])
    .split(inner);
    if let Some(j) = d.selected_job() {
        let summary = Line::from(vec![
            state_label(&j.state),
            Span::styled(
                format!("   {:.0}% ", j.progress * 100.0),
                Style::default().fg(INK),
            ),
            Span::styled(
                format!("· {} ", fmt_speed(j.speed)),
                Style::default().fg(DIM),
            ),
            Span::styled(
                format!("· ETA {} ", fmt_eta(j.eta, d.now)),
                Style::default().fg(WARN),
            ),
            Span::styled(
                format!("· {}/{} cracked", j.cracked, j.total),
                Style::default().fg(crack_color(j)),
            ),
        ]);
        f.render_widget(Paragraph::new(summary), parts[0]);
    }

    let header = Row::new(["CHUNK", "KEYSPACE", "PROGRESS", "SPEED", "STATE"])
        .style(Style::default().fg(DIM).add_modifier(Modifier::BOLD));
    let rows = d.chunks.iter().enumerate().map(|(i, c)| {
        Row::new(vec![
            Cell::from(format!("#{}", i + 1)).style(Style::default().fg(DIM)),
            Cell::from(format!(
                "{}..{}",
                short_num(c.offset),
                short_num(c.offset + c.len)
            ))
            .style(Style::default().fg(INK)),
            Cell::from(progress_bar(c.progress, 10, &c.state)),
            Cell::from(fmt_speed(c.speed)).style(Style::default().fg(if c.speed > 0 {
                INK
            } else {
                DIM
            })),
            Cell::from(state_label(&c.state)),
        ])
    });
    let widths = [
        Constraint::Length(5),
        Constraint::Length(13),
        Constraint::Length(14),
        Constraint::Length(10),
        Constraint::Length(9),
    ];
    // Keep the first running chunk in view as the list scrolls (up to
    // max_chunks chunks now run, so a long parallel job overflows the pane).
    if d.chunks.is_empty() {
        st.chunks.select(None);
    } else {
        let active = d
            .chunks
            .iter()
            .position(|c| c.state == "running")
            .or_else(|| d.chunks.iter().position(|c| c.state == "pending"))
            .unwrap_or(0);
        st.chunks.select(Some(active.min(d.chunks.len() - 1)));
    }
    f.render_stateful_widget(
        Table::new(rows, widths).header(header).column_spacing(1),
        parts[1],
        &mut st.chunks,
    );
    let visible = (parts[1].height as usize).saturating_sub(1);
    scrollbar(
        f,
        parts[1],
        d.chunks.len(),
        visible,
        st.chunks.selected().unwrap_or(0),
    );

    // Aggregate keyspace + per-job ETA, computed across the job's chunks.
    let total: i64 = d.chunks.iter().map(|c| c.len).sum();
    let done: f64 = d
        .chunks
        .iter()
        .map(|c| {
            if c.state == "done" {
                c.len as f64
            } else {
                c.progress * c.len as f64
            }
        })
        .sum();
    let eta_rel = fmt_eta(d.selected_job().and_then(|j| j.eta), d.now);
    let agg = if total > 0 {
        Line::from(vec![
            Span::styled("keyspace ", Style::default().fg(DIM)),
            Span::styled(
                format!("{} / {} ", short_num(done as i64), short_num(total)),
                Style::default().fg(INK),
            ),
            Span::styled(
                format!("· {} left ", short_num(total - done as i64)),
                Style::default().fg(DIM),
            ),
            Span::styled(
                format!("· ETA {eta_rel}"),
                Style::default().fg(WARN).add_modifier(Modifier::BOLD),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled("ETA ", Style::default().fg(DIM)),
            Span::styled(
                eta_rel,
                Style::default().fg(WARN).add_modifier(Modifier::BOLD),
            ),
        ])
    };
    let sep = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(PANEL));
    f.render_widget(sep, parts[2]);
    let agg_area = Rect {
        x: parts[2].x,
        y: parts[2].y + 1,
        width: parts[2].width,
        height: 1,
    };
    f.render_widget(Paragraph::new(agg), agg_area);
}

fn devices(f: &mut Frame, area: Rect, d: &Dashboard) {
    let title = if d.telemetry_live {
        "Devices · live"
    } else {
        "Devices · sample"
    };
    let block = panel(title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    if d.devices.is_empty() {
        let note = Paragraph::new(Line::from(Span::styled(
            "no devices sampled yet — telemetry collector starting",
            Style::default().fg(DIM).add_modifier(Modifier::ITALIC),
        )));
        f.render_widget(note, inner);
        return;
    }

    let header = Row::new(["DEVICE", "TEMP", "UTIL", "P-STATE", "CLOCK", "HASHRATE"])
        .style(Style::default().fg(DIM).add_modifier(Modifier::BOLD));
    let rows = d.devices.iter().map(|dev: &Device| {
        Row::new(vec![
            Cell::from(dev.name.clone()).style(Style::default().fg(INK)),
            Cell::from(format!("{}°C", dev.temp)).style(Style::default().fg(temp_color(dev.temp))),
            Cell::from(progress_bar(dev.util as f64 / 100.0, 8, "running")),
            Cell::from(dev.pstate.clone()).style(Style::default().fg(ACCENT)),
            Cell::from(if dev.clock_mhz > 0 {
                format!("{} MHz", dev.clock_mhz)
            } else {
                "—".into()
            })
            .style(Style::default().fg(INK)),
            Cell::from(fmt_speed(dev.hashrate)).style(Style::default().fg(INK)),
        ])
    });
    let widths = [
        Constraint::Min(14),
        Constraint::Length(6),
        Constraint::Length(13),
        Constraint::Length(7),
        Constraint::Length(9),
        Constraint::Length(11),
    ];
    f.render_widget(
        Table::new(rows, widths).header(header).column_spacing(1),
        inner,
    );
}

/// Connected-agent panel: a status dot and styled name per agent — green bold
/// (online/usable), gray italic (away), red bold-underline (error), orange bold
/// (busy / near-overloaded).
fn agents(f: &mut Frame, area: Rect, d: &Dashboard) {
    let usable = d
        .agents
        .iter()
        .filter(|a| a.status == "online" || a.status == "busy")
        .count();
    let title = format!("Agents · {usable}/{} usable", d.agents.len());
    let block = panel(&title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    if d.agents.is_empty() {
        let note = Paragraph::new(Line::from(Span::styled(
            "no agents enrolled",
            Style::default().fg(DIM).add_modifier(Modifier::ITALIC),
        )));
        f.render_widget(note, inner);
        return;
    }

    let header = Row::new(["", "AGENT", "STATUS"])
        .style(Style::default().fg(DIM).add_modifier(Modifier::BOLD));
    let rows = d.agents.iter().map(|a| {
        let (color, modifier) = match a.status.as_str() {
            "online" => (GOOD, Modifier::BOLD),
            "busy" => (BUSY, Modifier::BOLD),
            "error" => (BAD, Modifier::BOLD | Modifier::UNDERLINED),
            _ => (DIM, Modifier::ITALIC), // away / unknown
        };
        Row::new(vec![
            Cell::from("●").style(Style::default().fg(color)),
            Cell::from(a.name.clone()).style(Style::default().fg(color).add_modifier(modifier)),
            Cell::from(a.status.clone()).style(Style::default().fg(DIM)),
        ])
    });
    let widths = [
        Constraint::Length(1),
        Constraint::Min(10),
        Constraint::Length(7),
    ];
    f.render_widget(
        Table::new(rows, widths).header(header).column_spacing(1),
        inner,
    );
}

fn footer(f: &mut Frame, area: Rect, d: &Dashboard) {
    let mut spans = vec![
        key("↑/↓"),
        lbl(" select  "),
        key("r"),
        lbl(" refresh  "),
        key("f"),
        lbl(if d.hide_finished {
            " show finished  "
        } else {
            " hide finished  "
        }),
    ];
    if d.can_submit {
        spans.extend([
            key("p"),
            lbl(" pause  "),
            key("c"),
            lbl(" cancel  "),
            key("C"),
            lbl(" clear results  "),
        ]);
    }
    spans.extend([key("q"), lbl(" quit")]);
    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(BG)),
        area,
    );
}

// ---- helpers ----

fn panel(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(PANEL))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(INK).add_modifier(Modifier::BOLD),
        ))
        .padding(Padding::horizontal(1))
}

fn key(s: &str) -> Span<'_> {
    Span::styled(s, Style::default().fg(ACCENT).add_modifier(Modifier::BOLD))
}
fn lbl(s: &str) -> Span<'_> {
    Span::styled(s, Style::default().fg(DIM))
}

fn state_color(state: &str) -> Color {
    match state {
        "running" => GOOD,
        "queued" | "assigned" | "pending" => DIM,
        "paused" => WARN,
        "completed" | "done" => GOOD,
        "exhausted" => WARN,
        "cancelled" | "failed" | "error" => BAD,
        _ => INK,
    }
}

fn state_label(state: &str) -> Span<'_> {
    let dot = match state {
        "running" | "completed" | "done" => "●",
        "queued" | "assigned" | "pending" => "○",
        _ => "◆",
    };
    Span::styled(
        format!("{dot} {state}"),
        Style::default().fg(state_color(state)),
    )
}

fn progress_bar(p: f64, width: usize, state: &str) -> Line<'static> {
    let p = p.clamp(0.0, 1.0);
    let filled = (p * width as f64).round() as usize;
    let color = state_color(state);
    let bar = "█".repeat(filled);
    let rest = "░".repeat(width - filled);
    Line::from(vec![
        Span::styled(bar, Style::default().fg(color)),
        Span::styled(rest, Style::default().fg(TRACK)),
        Span::styled(format!(" {:>3.0}%", p * 100.0), Style::default().fg(INK)),
    ])
}

fn crack_color(j: &JobRow) -> Color {
    if j.total > 0 && j.cracked >= j.total {
        GOOD
    } else if j.cracked > 0 {
        ACCENT
    } else {
        DIM
    }
}

fn temp_color(t: i32) -> Color {
    if t >= 85 {
        BAD
    } else if t >= 75 {
        WARN
    } else {
        GOOD
    }
}

fn fmt_speed(h: i64) -> String {
    let f = h as f64;
    if h <= 0 {
        "—".into()
    } else if f >= 1e9 {
        format!("{:.1} GH/s", f / 1e9)
    } else if f >= 1e6 {
        format!("{:.1} MH/s", f / 1e6)
    } else if f >= 1e3 {
        format!("{:.1} kH/s", f / 1e3)
    } else {
        format!("{h} H/s")
    }
}

fn short_num(n: i64) -> String {
    let f = n as f64;
    if f >= 1e12 {
        format!("{:.1}T", f / 1e12)
    } else if f >= 1e9 {
        format!("{:.1}G", f / 1e9)
    } else if f >= 1e6 {
        format!("{:.0}M", f / 1e6)
    } else if f >= 1e3 {
        format!("{:.0}k", f / 1e3)
    } else {
        n.to_string()
    }
}

pub fn fmt_eta(eta: Option<DateTime<Utc>>, now: DateTime<Utc>) -> String {
    match eta {
        None => "—".into(),
        Some(t) => {
            let secs = (t - now).num_seconds();
            if secs <= 0 {
                "soon".into()
            } else if secs >= 3600 {
                format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
            } else {
                format!("{}m{:02}s", secs / 60, secs % 60)
            }
        }
    }
}

/// Resolve a ratatui Color to concrete RGB for the screenshot renderer.
pub fn rgb(c: Color, is_bg: bool) -> (u8, u8, u8) {
    match c {
        Color::Rgb(r, g, b) => (r, g, b),
        Color::Reset => {
            if is_bg {
                (24, 25, 30)
            } else {
                (205, 210, 220)
            }
        }
        Color::Black => (24, 25, 30),
        Color::White => (220, 220, 220),
        Color::Red | Color::LightRed => (224, 108, 117),
        Color::Green | Color::LightGreen => (152, 195, 121),
        Color::Yellow | Color::LightYellow => (229, 192, 123),
        Color::Blue | Color::LightBlue => (97, 175, 239),
        Color::Magenta | Color::LightMagenta => (198, 120, 221),
        Color::Cyan | Color::LightCyan => (86, 182, 194),
        Color::Gray => (150, 150, 150),
        Color::DarkGray => (90, 90, 90),
        _ => {
            if is_bg {
                (24, 25, 30)
            } else {
                (205, 210, 220)
            }
        }
    }
}
