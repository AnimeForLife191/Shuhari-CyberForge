pub mod helper;

use ratatui::{
    Terminal,
    backend::CrosstermBackend,
};
use crossterm::{
    terminal::{
        enable_raw_mode,
        disable_raw_mode,
        EnterAlternateScreen,
        LeaveAlternateScreen
    },
    execute
};
use std::io;

/// Ratatui Helper
pub fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>, Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

pub fn teardown_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<(), Box<dyn std::error::Error>> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}