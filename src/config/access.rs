//! The roster: `access.conf`.
//!
//! ```text
//! <user>  <token> [token ...]   [# comment]
//! ```
//!
//! A token is a role or a flag, optionally scoped: `admin`, `user@node3`,
//! `locked@gpu1`. Comments and blank lines are kept when the file is
//! rewritten; only the line of the edited user changes.

use std::fmt;

/// Flags are not roles: they modify how a user's roles apply.
/// `locked` locks the account, `nopasswd` gives passwordless sudo where the
/// user has sudo, `pwonly` refuses SSH keys.
pub const FLAGS: [&str; 3] = ["locked", "nopasswd", "pwonly"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub name: String,
    /// `None`: the role's default nodes (all nodes for a flag).
    pub scope: Option<Vec<String>>,
}

impl Token {
    pub fn parse(s: &str) -> Token {
        match s.split_once('@') {
            Some((name, scope)) => Token {
                name: name.to_string(),
                scope: Some(
                    scope
                        .split(',')
                        .filter(|n| !n.is_empty())
                        .map(String::from)
                        .collect(),
                ),
            },
            None => Token::plain(s),
        }
    }

    pub fn plain(name: &str) -> Token {
        Token {
            name: name.to_string(),
            scope: None,
        }
    }

    pub fn is_flag(&self) -> bool {
        FLAGS.contains(&self.name.as_str())
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.scope {
            Some(nodes) => write!(f, "{}@{}", self.name, nodes.join(",")),
            None => f.write_str(&self.name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub user: String,
    pub tokens: Vec<Token>,
    /// Trailing comment including the `#`, or empty.
    pub comment: String,
    /// The line exactly as read; `None` once the entry has been changed.
    raw: Option<String>,
}

impl Entry {
    pub fn new(user: &str, tokens: Vec<Token>, comment: &str) -> Entry {
        Entry {
            user: user.to_string(),
            tokens,
            comment: comment.to_string(),
            raw: None,
        }
    }

    pub fn set_tokens(&mut self, tokens: Vec<Token>) {
        self.tokens = tokens;
        self.raw = None;
    }

    /// The tokens as written in the file, space separated.
    pub fn tokens_text(&self) -> String {
        self.tokens
            .iter()
            .map(Token::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn render(&self) -> String {
        match &self.raw {
            Some(raw) => raw.clone(),
            None => format!(
                "{:<16} {:<34} {}",
                self.user,
                self.tokens_text(),
                self.comment
            )
            .trim_end()
            .to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    Entry(Entry),
    /// A comment or blank line, kept verbatim.
    Other(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessFile {
    pub lines: Vec<Line>,
}

impl AccessFile {
    pub fn parse(text: &str) -> AccessFile {
        let lines = text
            .lines()
            .map(|raw| {
                let (body, comment) = match raw.find('#') {
                    Some(p) => (&raw[..p], raw[p..].trim_end()),
                    None => (raw, ""),
                };
                let mut fields = body.split_whitespace();
                match fields.next() {
                    None => Line::Other(raw.to_string()),
                    Some(user) => Line::Entry(Entry {
                        user: user.to_string(),
                        tokens: fields.map(Token::parse).collect(),
                        comment: comment.to_string(),
                        raw: Some(raw.to_string()),
                    }),
                }
            })
            .collect();
        AccessFile { lines }
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.lines.iter().filter_map(|l| match l {
            Line::Entry(e) => Some(e),
            Line::Other(_) => None,
        })
    }

    pub fn get(&self, user: &str) -> Option<&Entry> {
        self.entries().find(|e| e.user == user)
    }

    pub fn get_mut(&mut self, user: &str) -> Option<&mut Entry> {
        self.lines.iter_mut().find_map(|l| match l {
            Line::Entry(e) if e.user == user => Some(e),
            _ => None,
        })
    }

    pub fn push(&mut self, entry: Entry) {
        self.lines.push(Line::Entry(entry));
    }

    /// Remove every line of this user. Returns whether anything was removed.
    pub fn remove(&mut self, user: &str) -> bool {
        let before = self.lines.len();
        self.lines
            .retain(|l| !matches!(l, Line::Entry(e) if e.user == user));
        self.lines.len() != before
    }

    /// The file content, ready to be written back.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for line in &self.lines {
            match line {
                Line::Entry(e) => out.push_str(&e.render()),
                Line::Other(text) => out.push_str(text),
            }
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str =
        "# roster\n\nalice    admin nopasswd\ndave     student gpu@gpu1,node3   # two nodes\n";

    #[test]
    fn round_trips_untouched_files_byte_for_byte() {
        assert_eq!(AccessFile::parse(TEXT).render(), TEXT);
    }

    #[test]
    fn parses_tokens_and_comments() {
        let f = AccessFile::parse(TEXT);
        let dave = f.get("dave").unwrap();
        assert_eq!(dave.tokens[1], Token::parse("gpu@gpu1,node3"));
        assert_eq!(dave.tokens[1].scope.as_deref().unwrap(), ["gpu1", "node3"]);
        assert_eq!(dave.comment, "# two nodes");
        assert!(Token::parse("locked@gpu1").is_flag());
        assert_eq!(f.entries().count(), 2);
    }

    #[test]
    fn only_the_edited_line_is_reformatted() {
        let mut f = AccessFile::parse(TEXT);
        f.get_mut("dave")
            .unwrap()
            .set_tokens(vec![Token::plain("student")]);
        let out = f.render();
        assert!(out.starts_with("# roster\n\nalice    admin nopasswd\n"));
        assert!(out.contains("dave             student                            # two nodes\n"));
    }
}
