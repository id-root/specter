use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Span, Line},
    widgets::{Block, Borders, Gauge, Paragraph, Sparkline},
    Terminal,
};
use std::{io, sync::atomic::Ordering, time::{Duration, Instant}};
use crate::engine::EngineStats;

pub struct TuiApp {
    stats: EngineStats,
    latency_history: Vec<u64>, // Mock data for sparkline for now
}

impl TuiApp {
    pub fn new(stats: EngineStats) -> Self {
        Self {
            stats,
            latency_history: vec![0; 100],
        }
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let res = self.run_app(&mut terminal).await;

        // Restore terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        if let Err(err) = res {
            println!("{:?}", err)
        }

        Ok(())
    }

    async fn run_app<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> io::Result<()> {
        let mut last_tick = Instant::now();
        let tick_rate = Duration::from_millis(250);

        loop {
            terminal.draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(2)
                    .constraints(
                        [
                            Constraint::Length(3), // KPI Banner
                            Constraint::Length(10), // Latency Sparkline
                            Constraint::Length(3), // Grid Health Gauge
                            Constraint::Min(0),
                        ]
                        .as_ref(),
                    )
                    .split(f.size());

                // 1. KPI Banner
                let total = self.stats.total_requests.load(Ordering::Relaxed);
                let success = self.stats.successful_requests.load(Ordering::Relaxed);
                let blocked = self.stats.blocked_requests.load(Ordering::Relaxed);
                let failed = self.stats.failed_requests.load(Ordering::Relaxed);
                let rps = if total > 0 { total / 10 } else { 0 }; // Mock RPS calculation

                let kpi_text = vec![
                    Line::from(vec![
                        Span::styled(format!("Total: {} ", total), Style::default().fg(Color::White)),
                        Span::styled(format!("Success: {} ", success), Style::default().fg(Color::Green)),
                        Span::styled(format!("Blocked: {} ", blocked), Style::default().fg(Color::Yellow)),
                        Span::styled(format!("Failed: {} ", failed), Style::default().fg(Color::Red)),
                        Span::styled(format!("RPS: ~{} ", rps), Style::default().fg(Color::Cyan)),
                    ]),
                ];

                let kpi_paragraph = Paragraph::new(kpi_text)
                    .block(Block::default().borders(Borders::ALL).title("KPI Banner"));
                f.render_widget(kpi_paragraph, chunks[0]);

                // 2. Latency Sparkline
                // Mock update latency history
                self.latency_history.push(rand::random::<u64>() % 100);
                if self.latency_history.len() > 100 {
                    self.latency_history.remove(0);
                }

                let sparkline = Sparkline::default()
                    .block(Block::default().title("Latency Overhead (ms)").borders(Borders::ALL))
                    .data(&self.latency_history)
                    .style(Style::default().fg(Color::Blue));
                f.render_widget(sparkline, chunks[1]);

                // 3. Grid Health Gauge
                let health = if total > 0 {
                    (success as f64 / total as f64) * 100.0
                } else {
                    100.0
                };

                let gauge = Gauge::default()
                    .block(Block::default().title("Grid Health").borders(Borders::ALL))
                    .gauge_style(Style::default().fg(Color::Green).bg(Color::Black).add_modifier(Modifier::ITALIC))
                    .percent(health as u16);
                f.render_widget(gauge, chunks[2]);

            })?;

            let timeout = tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0));

            if crossterm::event::poll(timeout)? {
                if let Event::Key(key) = event::read()? {
                    if let KeyCode::Char('q') = key.code {
                        return Ok(());
                    }
                }
            }

            if last_tick.elapsed() >= tick_rate {
                last_tick = Instant::now();
            }
        }
    }
}
