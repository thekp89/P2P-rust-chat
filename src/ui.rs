use anyhow::Result;
use crossterm::{
    cursor::Show,
    event::{DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::StreamExt;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Terminal,
};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

static PANIC_HOOK_SET: AtomicBool = AtomicBool::new(false);

pub struct TerminalGuard;

impl TerminalGuard {
    pub fn new() -> Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

        // Install panic hook only once to ensure terminal is restored on any panic
        if !PANIC_HOOK_SET.swap(true, Ordering::SeqCst) {
            let default_panic = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |panic_info| {
                let _ = disable_raw_mode();
                let mut stdout = io::stdout();
                let _ = execute!(stdout, LeaveAlternateScreen, DisableMouseCapture, Show);
                default_panic(panic_info);
            }));
        }

        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen, DisableMouseCapture, Show);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageType {
    Chat { username: String, is_self: bool },
    System,
    Error,
    Success,
}

#[derive(Clone, Debug)]
pub struct UiMessage {
    pub timestamp: String,
    pub msg_type: MessageType,
    pub content: String,
}

#[derive(Clone, Debug)]
pub struct PeerStatus {
    pub peer_id: String,
    pub username: Option<String>,
    pub is_secure: bool,
    pub connected_at: String,
}

pub struct UiState {
    pub messages: Vec<UiMessage>,
    pub input: String,
    pub cursor_pos: usize, // character position in `input`
    pub scroll_offset: usize, // lines scrolled up from the bottom
    pub peers: Vec<PeerStatus>,
    pub local_peer_id: String,
    pub local_username: String,
    pub listen_addr: Option<String>,
}

impl UiState {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            input: String::new(),
            cursor_pos: 0,
            scroll_offset: 0,
            peers: Vec::new(),
            local_peer_id: String::new(),
            local_username: "anonymous".into(),
            listen_addr: None,
        }
    }

    pub fn insert_char(&mut self, c: char) {
        let mut chars: Vec<char> = self.input.chars().collect();
        if self.cursor_pos > chars.len() {
            self.cursor_pos = chars.len();
        }
        chars.insert(self.cursor_pos, c);
        self.input = chars.into_iter().collect();
        self.cursor_pos += 1;
    }

    pub fn delete_char_before_cursor(&mut self) {
        if self.cursor_pos > 0 {
            let mut chars: Vec<char> = self.input.chars().collect();
            chars.remove(self.cursor_pos - 1);
            self.input = chars.into_iter().collect();
            self.cursor_pos -= 1;
        }
    }

    pub fn delete_char_at_cursor(&mut self) {
        let mut chars: Vec<char> = self.input.chars().collect();
        if self.cursor_pos < chars.len() {
            chars.remove(self.cursor_pos);
            self.input = chars.into_iter().collect();
        }
    }

    pub fn move_cursor_left(&mut self) {
        if self.cursor_pos > 0 {
            self.cursor_pos -= 1;
        }
    }

    pub fn move_cursor_right(&mut self) {
        let len = self.input.chars().count();
        if self.cursor_pos < len {
            self.cursor_pos += 1;
        }
    }

    pub fn move_cursor_home(&mut self) {
        self.cursor_pos = 0;
    }

    pub fn move_cursor_end(&mut self) {
        self.cursor_pos = self.input.chars().count();
    }

    pub fn scroll_up(&mut self, amount: usize) {
        self.scroll_offset = self.scroll_offset.saturating_add(amount);
    }

    pub fn scroll_down(&mut self, amount: usize) {
        self.scroll_offset = self.scroll_offset.saturating_sub(amount);
    }

    pub fn scroll_to_bottom(&mut self) {
        self.scroll_offset = 0;
    }

    pub fn add_message(&mut self, msg_type: MessageType, content: String) {
        let time_str = current_time_str();
        self.messages.push(UiMessage {
            timestamp: time_str,
            msg_type,
            content,
        });
        // Auto-scroll to bottom when new messages arrive
        self.scroll_to_bottom();
    }

    pub fn add_chat(&mut self, username: String, content: String, is_self: bool) {
        self.add_message(MessageType::Chat { username, is_self }, content);
    }

    pub fn add_system(&mut self, content: String) {
        self.add_message(MessageType::System, content);
    }

    pub fn add_error(&mut self, content: String) {
        self.add_message(MessageType::Error, content);
    }

    pub fn add_success(&mut self, content: String) {
        self.add_message(MessageType::Success, content);
    }

    pub fn upsert_peer(&mut self, peer_id: String, username: Option<String>, is_secure: bool) {
        if let Some(peer) = self.peers.iter_mut().find(|p| p.peer_id == peer_id) {
            if let Some(name) = username {
                peer.username = Some(name);
            }
            peer.is_secure = is_secure;
        } else {
            self.peers.push(PeerStatus {
                peer_id,
                username,
                is_secure,
                connected_at: current_time_str(),
            });
        }
    }

    pub fn remove_peer(&mut self, peer_id: &str) {
        self.peers.retain(|p| p.peer_id != peer_id);
    }

    pub fn draw(&mut self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
        terminal.draw(|f| {
            let total_size = f.size();

            // Main vertical layout: Top content (chat + sidebar) and Bottom input bar
            let main_chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(0)
                .constraints([Constraint::Min(5), Constraint::Length(3)].as_ref())
                .split(total_size);

            // Top area split horizontally: Chat window (75%) and Peers/Info sidebar (25%)
            let body_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(75), Constraint::Percentage(25)].as_ref())
                .split(main_chunks[0]);

            let chat_area = body_chunks[0];
            let sidebar_area = body_chunks[1];
            let input_area = main_chunks[1];

            // 1. Render Chat Messages
            let chat_inner_height = chat_area.height.saturating_sub(2) as usize;
            let total_msgs = self.messages.len();

            // Calculate window slice based on scroll_offset
            let start_idx = if total_msgs > chat_inner_height {
                let max_offset = total_msgs.saturating_sub(chat_inner_height);
                let current_offset = self.scroll_offset.min(max_offset);
                total_msgs.saturating_sub(chat_inner_height + current_offset)
            } else {
                0
            };
            let end_idx = (start_idx + chat_inner_height).min(total_msgs);

            let visible_messages = if total_msgs > 0 {
                &self.messages[start_idx..end_idx]
            } else {
                &[]
            };

            let message_items: Vec<ListItem> = visible_messages
                .iter()
                .map(|m| {
                    let ts_span = Span::styled(
                        format!("[{}] ", m.timestamp),
                        Style::default().fg(Color::DarkGray),
                    );

                    let line = match &m.msg_type {
                        MessageType::Chat { username, is_self } => {
                            let name_style = if *is_self {
                                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                            };
                            let prefix = if *is_self { "You" } else { username.as_str() };
                            Line::from(vec![
                                ts_span,
                                Span::styled(format!("{prefix}: "), name_style),
                                Span::styled(&m.content, Style::default().fg(Color::White)),
                            ])
                        }
                        MessageType::System => Line::from(vec![
                            ts_span,
                            Span::styled("ℹ️  ", Style::default().fg(Color::Yellow)),
                            Span::styled(&m.content, Style::default().fg(Color::Yellow)),
                        ]),
                        MessageType::Success => Line::from(vec![
                            ts_span,
                            Span::styled("🔒 ", Style::default().fg(Color::LightGreen)),
                            Span::styled(&m.content, Style::default().fg(Color::LightGreen)),
                        ]),
                        MessageType::Error => Line::from(vec![
                            ts_span,
                            Span::styled("⚠️  ", Style::default().fg(Color::Red)),
                            Span::styled(&m.content, Style::default().fg(Color::LightRed)),
                        ]),
                    };
                    ListItem::new(line)
                })
                .collect();

            let scroll_indicator = if self.scroll_offset > 0 {
                format!(" [Scrolled Up {} lines - Esc/End to Reset]", self.scroll_offset)
            } else {
                String::new()
            };

            let chat_title = format!(" Chat - /help for commands{} ", scroll_indicator);
            let messages_list = List::new(message_items).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(chat_title)
                    .style(Style::default().fg(Color::White)),
            );
            f.render_widget(messages_list, chat_area);

            // 2. Render Sidebar (Local Info & Peers)
            let sidebar_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(7), Constraint::Min(5)].as_ref())
                .split(sidebar_area);

            // Local Node Info Box
            let short_id = if self.local_peer_id.len() > 12 {
                format!(
                    "{}...{}",
                    &self.local_peer_id[..6],
                    &self.local_peer_id[self.local_peer_id.len() - 4..]
                )
            } else {
                self.local_peer_id.clone()
            };

            let listen_str = self
                .listen_addr
                .as_deref()
                .unwrap_or("binding...");

            let info_lines = vec![
                Line::from(vec![
                    Span::styled("User: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&self.local_username, Style::default().fg(Color::Yellow)),
                ]),
                Line::from(vec![
                    Span::styled("Peer: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(short_id, Style::default().fg(Color::Cyan)),
                ]),
                Line::from(vec![
                    Span::styled("Port: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(listen_str, Style::default().fg(Color::White)),
                ]),
                Line::from(vec![
                    Span::styled("Peers: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{}", self.peers.len()),
                        Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD),
                    ),
                ]),
            ];
            let info_box = Paragraph::new(info_lines)
                .block(Block::default().borders(Borders::ALL).title(" My Node "));
            f.render_widget(info_box, sidebar_chunks[0]);

            // Connected Peers List
            let peer_items: Vec<ListItem> = if self.peers.is_empty() {
                vec![ListItem::new(Line::from(Span::styled(
                    "No peers connected\n(Use /connect <addr>)",
                    Style::default().fg(Color::DarkGray),
                )))]
            } else {
                self.peers
                    .iter()
                    .map(|p| {
                        let sec_icon = if p.is_secure { "🔒" } else { "⏳" };
                        let display_name = p.username.as_deref().unwrap_or("anon");
                        let short_pid = if p.peer_id.len() > 10 {
                            format!("..{}", &p.peer_id[p.peer_id.len() - 6..])
                        } else {
                            p.peer_id.clone()
                        };

                        ListItem::new(Line::from(vec![
                            Span::raw(format!("{sec_icon} ")),
                            Span::styled(display_name, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                            Span::styled(format!(" ({short_pid})"), Style::default().fg(Color::DarkGray)),
                        ]))
                    })
                    .collect()
            };

            let peers_box = List::new(peer_items).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" Peers ({}) ", self.peers.len())),
            );
            f.render_widget(peers_box, sidebar_chunks[1]);

            // 3. Render Input Widget
            let input_title = " Message (Enter: Send, Ctrl+C: Quit) ";
            let input_widget = Paragraph::new(self.input.as_str())
                .style(Style::default().fg(Color::Yellow))
                .wrap(Wrap { trim: false })
                .block(Block::default().borders(Borders::ALL).title(input_title));
            f.render_widget(input_widget, input_area);

            // Position terminal cursor inside the input box at cursor_pos
            let cursor_x = input_area.x + 1 + (self.cursor_pos as u16);
            let cursor_y = input_area.y + 1;
            f.set_cursor(cursor_x, cursor_y);
        })?;

        Ok(())
    }
}

fn current_time_str() -> String {
    let now = std::time::SystemTime::now();
    let duration = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = duration.as_secs();
    let hours = (secs / 3600) % 24;
    let mins = (secs / 60) % 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}", hours, mins, s)
}

pub async fn next_event(reader: &mut EventStream) -> Option<Result<Event>> {
    reader.next().await.map(|res| res.map_err(|e| anyhow::anyhow!(e)))
}

#[derive(Clone, Copy, PartialEq, Eq)]
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
    pub should_exit: bool,
}

impl Menu {
    pub fn new(username: String, port: u16, mdns: bool, connect_to: Option<String>) -> Self {
        Self {
            username,
            port: if port == 0 { String::new() } else { port.to_string() },
            mdns,
            connect_addr: connect_to.unwrap_or_default(),
            selected: MenuItem::Username,
            should_exit: false,
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
                KeyCode::Backspace => {
                    self.username.pop();
                }
                KeyCode::Enter => self.next(),
                _ => {}
            },
            MenuItem::Port => match key {
                KeyCode::Char(c) if c.is_numeric() => self.port.push(c),
                KeyCode::Backspace => {
                    self.port.pop();
                }
                KeyCode::Enter => self.next(),
                _ => {}
            },
            MenuItem::Mdns => match key {
                KeyCode::Enter | KeyCode::Char(' ') => self.mdns = !self.mdns,
                _ => {}
            },
            MenuItem::ConnectTo => match key {
                KeyCode::Char(c) => self.connect_addr.push(c),
                KeyCode::Backspace => {
                    self.connect_addr.pop();
                }
                KeyCode::Enter => self.next(),
                _ => {}
            },
            MenuItem::Start => {}
        }
    }

    pub fn draw(&self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
        terminal.draw(|f| {
            let size = f.size();
            let block = Block::default()
                .title(" P2P Encrypted Chat - Setup ")
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::Cyan));
            let area = centered_rect(65, 60, size);

            f.render_widget(Clear, area);
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
                        Constraint::Length(2), // Help hint
                    ]
                    .as_ref(),
                )
                .split(area);

            let style_selected = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
            let style_normal = Style::default().fg(Color::White);

            // Username
            let username_style = if matches!(self.selected, MenuItem::Username) {
                style_selected
            } else {
                style_normal
            };
            f.render_widget(
                Paragraph::new(self.username.as_str())
                    .block(Block::default().borders(Borders::ALL).title(" Username "))
                    .style(username_style),
                chunks[0],
            );

            // Port
            let port_style = if matches!(self.selected, MenuItem::Port) {
                style_selected
            } else {
                style_normal
            };
            let port_display = if self.port.is_empty() {
                "0 (Random available port)"
            } else {
                self.port.as_str()
            };
            f.render_widget(
                Paragraph::new(port_display)
                    .block(Block::default().borders(Borders::ALL).title(" Listen Port "))
                    .style(port_style),
                chunks[1],
            );

            // mDNS
            let mdns_style = if matches!(self.selected, MenuItem::Mdns) {
                style_selected
            } else {
                style_normal
            };
            let mdns_text = if self.mdns {
                "[x] Enable local peer discovery (mDNS)"
            } else {
                "[ ] Enable local peer discovery (mDNS)"
            };
            f.render_widget(
                Paragraph::new(mdns_text)
                    .block(Block::default().borders(Borders::ALL).title(" Discovery "))
                    .style(mdns_style),
                chunks[2],
            );

            // Connect To
            let connect_style = if matches!(self.selected, MenuItem::ConnectTo) {
                style_selected
            } else {
                style_normal
            };
            let connect_display = if self.connect_addr.is_empty() {
                "(Optional: e.g. 192.168.1.50:9000 or /ip4/...)"
            } else {
                self.connect_addr.as_str()
            };
            f.render_widget(
                Paragraph::new(connect_display)
                    .block(Block::default().borders(Borders::ALL).title(" Connect to Peer (Optional) "))
                    .style(connect_style),
                chunks[3],
            );

            // Start Button
            let start_style = if matches!(self.selected, MenuItem::Start) {
                Style::default().bg(Color::Green).fg(Color::Black).add_modifier(Modifier::BOLD)
            } else {
                style_normal
            };
            f.render_widget(
                Paragraph::new("ENTER CHAT ROOM")
                    .block(Block::default().borders(Borders::ALL))
                    .style(start_style)
                    .alignment(ratatui::layout::Alignment::Center),
                chunks[4],
            );

            // Navigation Hint
            let hint = Paragraph::new("↑/↓/Tab: Navigate | Enter: Select/Next | Esc: Quit")
                .style(Style::default().fg(Color::DarkGray))
                .alignment(ratatui::layout::Alignment::Center);
            f.render_widget(hint, chunks[5]);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ui_input_and_cursor() {
        let mut state = UiState::new();
        state.insert_char('h');
        state.insert_char('e');
        state.insert_char('l');
        state.insert_char('o');
        assert_eq!(state.input, "helo");
        assert_eq!(state.cursor_pos, 4);

        // move left twice and insert 'l' -> "hello"
        state.move_cursor_left();
        state.move_cursor_left();
        assert_eq!(state.cursor_pos, 2);
        state.insert_char('l');
        assert_eq!(state.input, "hello");
        assert_eq!(state.cursor_pos, 3);

        // delete backspace
        state.delete_char_before_cursor();
        assert_eq!(state.input, "helo");
        assert_eq!(state.cursor_pos, 2);

        // delete forward
        state.delete_char_at_cursor();
        assert_eq!(state.input, "heo");
    }

    #[test]
    fn test_menu_navigation() {
        let mut menu = Menu::new("test".into(), 9000, true, None);
        assert!(matches!(menu.selected, MenuItem::Username));
        menu.next();
        assert!(matches!(menu.selected, MenuItem::Port));
        menu.next();
        assert!(matches!(menu.selected, MenuItem::Mdns));
        menu.previous();
        assert!(matches!(menu.selected, MenuItem::Port));
    }
}
