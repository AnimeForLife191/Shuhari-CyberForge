use ratatui::{
    Frame,
    layout::Constraint,
    widgets::{Block, Borders, Row, Table, TableState},
    style::{Color, Modifier, Style},
};
use crossterm::event::{self, Event, KeyCode,};

use super::Hashes;
use crate::common::{setup_terminal, teardown_terminal};

pub struct HashApp {
    pub hashes: Vec<Hashes>,
    pub state: TableState
}

impl HashApp {
    pub fn new(hashes: Vec<Hashes>) -> Self {
        let mut state = TableState::default();
        state.select(Some(0));
        HashApp { hashes, state }
    }

    pub fn scroll_down(&mut self) {
        let next = match self.state.selected() {
            Some(i) => {
                if i < self.hashes.len().saturating_sub(1) {
                    i + 1
                } else {
                    i
                }
            }
            None => 0
        };
        self.state.select(Some(next));
    }

    pub fn scroll_up(&mut self) {
        let prev = match self.state.selected() {
            Some(i) => if i > 0 { i - 1 } else { 0 },
            None => 0
        };
        self.state.select(Some(prev));
    }
}

fn draw_table(frame: &mut Frame, app: &mut HashApp) {
    // 1. Define the rows from your hash data
    let rows: Vec<Row> = app.hashes.iter().map(|h| {
        Row::new(vec![
            h.file.display().to_string(),
            h.md5.clone(),
            h.sha256.clone(),
        ])
    }).collect();

    // 2. Define column widths
    let widths = [
        Constraint::Percentage(30),  // file name
        Constraint::Percentage(20),  // md5
        Constraint::Percentage(50),  // sha256
    ];

    // 3. Build the table widget
    let table = Table::new(rows, widths)
        .block(Block::default().borders(Borders::ALL).title("File Hashes").title_bottom("q: quit  ↑↓: scroll"))
        .header(Row::new(vec!["File", "MD5", "SHA256"])
            .style(Style::default().fg(Color::Yellow)))
        .row_highlight_style(Style::default()
            .fg(Color::Black)
            .bg(Color::White)
            .add_modifier(Modifier::BOLD));

    frame.render_stateful_widget(table, frame.area(), &mut app.state);
}

pub fn show(hashes: Vec<Hashes>) -> Result<(), Box<dyn std::error::Error>> {
    let mut terminal = setup_terminal()?;
    let mut app = HashApp::new(hashes);

    loop {
        // 1. Draw
        terminal.draw(|frame| {
            draw_table(frame, &mut app);
        })?;

        // 2. Handle input
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Down => app.scroll_down(),
                    KeyCode::Up => app.scroll_up(),
                    _ => {}
                }
            }
        }
    }

    teardown_terminal(&mut terminal)?;
    Ok(())
}