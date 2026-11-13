//! Site settings: `grantctl.conf`.
//!
//! `KEY=VALUE` lines with `#` comments. Values may be quoted. grantctl only
//! reads plain assignments and never executes anything from the file.

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    /// Control node name as written in the nodes file. Default: its first line.
    pub control: Option<String>,
    /// Group the distribution's /etc/sudoers grants full sudo.
    pub sudo_group: String,
    /// Role `init` uses for SSH access it finds outside other roles.
    pub shell_role: String,
    /// Files in sshd_config.d / sudoers.d / limits.d that grantctl replaces.
    pub legacy_sshd: Vec<String>,
    pub legacy_sudo: Vec<String>,
    pub legacy_limits: Vec<String>,
    /// Regex marking slice drop-ins of another tool that grantctl may take over.
    pub legacy_slice_marker: Option<String>,
    /// Old management scripts `audit` should warn about.
    pub legacy_managers: Vec<String>,
}

impl Default for Site {
    fn default() -> Self {
        Site {
            control: None,
            sudo_group: "sudo".to_string(),
            shell_role: "user".to_string(),
            legacy_sshd: Vec::new(),
            legacy_sudo: Vec::new(),
            legacy_limits: Vec::new(),
            legacy_slice_marker: None,
            legacy_managers: Vec::new(),
        }
    }
}

impl Site {
    pub fn parse(text: &str, file: &str) -> Result<Site> {
        let mut site = Site::default();
        for (i, raw) in text.lines().enumerate() {
            let n = i + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, rest)) = line.split_once('=') else {
                return Err(Error::parse(file, n, "expected KEY=VALUE"));
            };
            let value = unquote(rest).map_err(|m| Error::parse(file, n, m))?;
            let words = || -> Vec<String> { value.split_whitespace().map(String::from).collect() };
            let optional = || (!value.is_empty()).then(|| value.clone());
            match key.trim() {
                "CONTROL" => site.control = optional(),
                "SUDO_GROUP" => {
                    if value.is_empty() {
                        return Err(Error::parse(file, n, "SUDO_GROUP must not be empty"));
                    }
                    site.sudo_group = value.clone();
                }
                "SHELL_ROLE" => site.shell_role = value.clone(),
                "LEGACY_SSHD" => site.legacy_sshd = words(),
                "LEGACY_SUDO" => site.legacy_sudo = words(),
                "LEGACY_LIMITS" => site.legacy_limits = words(),
                "LEGACY_SLICE_MARKER" => site.legacy_slice_marker = optional(),
                "LEGACY_MANAGERS" => site.legacy_managers = words(),
                other => {
                    return Err(Error::parse(file, n, format!("unknown setting {other}")));
                }
            }
        }
        Ok(site)
    }
}

/// The value part of a `KEY=VALUE` line: `"quoted"`, `'quoted'` or a bare
/// word, optionally followed by a `# comment`.
fn unquote(rest: &str) -> std::result::Result<String, String> {
    let rest = rest.trim_start();
    for quote in ['"', '\''] {
        if let Some(body) = rest.strip_prefix(quote) {
            let Some(end) = body.find(quote) else {
                return Err("missing closing quote".to_string());
            };
            let tail = body[end + 1..].trim();
            if !tail.is_empty() && !tail.starts_with('#') {
                return Err("unexpected text after the closing quote".to_string());
            }
            return Ok(body[..end].to_string());
        }
    }
    let bare = match rest.find(" #").or_else(|| rest.find("\t#")) {
        Some(i) => &rest[..i],
        None => rest,
    };
    Ok(bare.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_empty() {
        assert_eq!(Site::parse("", "f").unwrap(), Site::default());
    }

    #[test]
    fn reads_quoted_values_and_comments() {
        let text = "# site\nCONTROL=nst-n1\nSUDO_GROUP=sudo   # distro group\n\
                    LEGACY_SSHD=\"00-lockdown.conf 99-admin-password.conf\"\n\
                    LEGACY_SLICE_MARKER='managed by old-tool'\n";
        let s = Site::parse(text, "f").unwrap();
        assert_eq!(s.control.as_deref(), Some("nst-n1"));
        assert_eq!(s.sudo_group, "sudo");
        assert_eq!(
            s.legacy_sshd,
            ["00-lockdown.conf", "99-admin-password.conf"]
        );
        assert_eq!(
            s.legacy_slice_marker.as_deref(),
            Some("managed by old-tool")
        );
    }

    #[test]
    fn rejects_unknown_keys_and_bad_quotes() {
        assert!(Site::parse("COLOUR=blue\n", "f").is_err());
        assert!(Site::parse("CONTROL=\"n1\n", "f").is_err());
        assert!(Site::parse("just words\n", "f").is_err());
    }
}
