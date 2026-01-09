use anyhow::Result;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Clear},
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

pub enum MenuItem {
    Username,
    Port,
    Mdns,
    ConnectTo,
    Start,
}

pub struct Menu {
    pub username: String,
    pub port: String,
    pub mdns: bool,
    pub connect_addr: String,
    pub selected: MenuItem,
}

impl Menu {
    pub fn new(username: String, port: u16, mdns: bool, connect_to: Option<String>) -> Self {
        Self {
            username,
            port: if port == 0 { String::new() } else { port.to_string() },
            mdns,
            connect_addr: connect_to.unwrap_or_default(),
            selected: MenuItem::Username,
        }
    }

    pub fn next(&mut self) {
        self.selected = match self.selected {
            MenuItem::Username => MenuItem::Port,
            MenuItem::Port => MenuItem::Mdns,
            MenuItem::Mdns => MenuItem::ConnectTo,
            MenuItem::ConnectTo => MenuItem::Start,
            MenuItem::Start => MenuItem::Username,
        };
    }

    pub fn previous(&mut self) {
        self.selected = match self.selected {
            MenuItem::Username => MenuItem::Start,
            MenuItem::Port => MenuItem::Username,
            MenuItem::Mdns => MenuItem::Port,
            MenuItem::ConnectTo => MenuItem::Mdns,
            MenuItem::Start => MenuItem::ConnectTo,
        };
    }

    pub fn handle_input(&mut self, key: KeyCode) {
        match self.selected {
            MenuItem::Username => match key {
                KeyCode::Char(c) => self.username.push(c),
                KeyCode::Backspace => { self.username.pop(); },
                _ => {}
            },
            MenuItem::Port => match key {
                KeyCode::Char(c) if c.is_numeric() => self.port.push(c),
                KeyCode::Backspace => { self.port.pop(); },
                _ => {}
            },
            MenuItem::Mdns => match key {
                KeyCode::Enter | KeyCode::Char(' ') => self.mdns = !self.mdns,
                _ => {}
            },
            MenuItem::ConnectTo => match key {
                KeyCode::Char(c) => self.connect_addr.push(c),
                KeyCode::Backspace => { self.connect_addr.pop(); },
                _ => {}
            },
            MenuItem::Start => {}
        }
    }

    pub fn draw(&self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
        terminal.draw(|f| {
            let size = f.size();
            let block = Block::default().title("Configuration").borders(Borders::ALL);
            let area = centered_rect(60, 50, size);
            
            f.render_widget(Clear, area); // Clear background
            f.render_widget(block, area);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(2)
                .constraints(
                    [
                        Constraint::Length(3), // Username
                        Constraint::Length(3), // Port
                        Constraint::Length(3), // mDNS
                        Constraint::Length(3), // Connect To
                        Constraint::Length(3), // Start Button
                    ]
                    .as_ref(),
                )
                .split(area);

            let style_selected = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
            let style_normal = Style::default().fg(Color::White);

            // Username
            let username_style = if matches!(self.selected, MenuItem::Username) { style_selected } else { style_normal };
            f.render_widget(
                Paragraph::new(self.username.as_str())
                    .block(Block::default().borders(Borders::ALL).title("Username"))
                    .style(username_style),
                chunks[0],
            );

            // Port
            let port_style = if matches!(self.selected, MenuItem::Port) { style_selected } else { style_normal };
            f.render_widget(
                Paragraph::new(self.port.as_str())
                    .block(Block::default().borders(Borders::ALL).title("Port (0 for random)"))
                    .style(port_style),
                chunks[1],
            );

            // mDNS
            let mdns_style = if matches!(self.selected, MenuItem::Mdns) { style_selected } else { style_normal };
            let mdns_text = if self.mdns { "[x] Enable mDNS" } else { "[ ] Enable mDNS" };
            f.render_widget(
                Paragraph::new(mdns_text)
                    .block(Block::default().borders(Borders::ALL).title("Discovery"))
                    .style(mdns_style),
                chunks[2],
            );

            // Connect To
            let connect_style = if matches!(self.selected, MenuItem::ConnectTo) { style_selected } else { style_normal };
            f.render_widget(
                Paragraph::new(self.connect_addr.as_str())
                    .block(Block::default().borders(Borders::ALL).title("Connect to Peer (IP:PORT)"))
                    .style(connect_style),
                chunks[3],
            );

            // Start
            let start_style = if matches!(self.selected, MenuItem::Start) { 
                Style::default().bg(Color::Green).fg(Color::Black).add_modifier(Modifier::BOLD)
            } else { 
                style_normal 
            };
            f.render_widget(
                Paragraph::new("START CHAT")
                    .block(Block::default().borders(Borders::ALL))
                    .style(start_style)
                    .alignment(ratatui::layout::Alignment::Center),
                chunks[4],
            );
        })?;
        Ok(())
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}
