use anyhow::Result;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, Event, EventStream},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};
use std::io;
use futures::StreamExt;

pub struct TerminalGuard;

impl TerminalGuard {
    pub fn new() -> Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen, DisableMouseCapture);
    }
}

pub struct UiState {
    pub messages: Vec<String>,
    pub input: String,
}

impl UiState {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            input: String::new(),
        }
    }

    pub fn draw(&self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Min(0), Constraint::Length(3)].as_ref())
                .split(f.size());

            let message_items: Vec<ListItem> = self.messages
                .iter()
                .map(|m| ListItem::new(Line::from(Span::styled(m, Style::default().fg(Color::White)))))
                .collect();

            let messages_list = List::new(message_items)
                .block(Block::default().borders(Borders::ALL).title("Chat"));
            f.render_widget(messages_list, chunks[0]);

            let input_widget = Paragraph::new(self.input.as_str())
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().borders(Borders::ALL).title("Message"));
            f.render_widget(input_widget, chunks[1]);
        })?;
        Ok(())
    }
}

pub async fn next_event(reader: &mut EventStream) -> Option<Result<Event>> {
    reader.next().await.map(|res| res.map_err(|e| anyhow::anyhow!(e)))
}
