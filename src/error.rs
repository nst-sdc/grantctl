use std::fmt;
use std::path::PathBuf;

/// Everything that can go wrong on the control side.
#[derive(Debug)]
pub enum Error {
    /// A file could not be read or written.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A configuration file has a syntax error.
    Parse {
        file: String,
        line: usize,
        msg: String,
    },
    /// The configuration is well-formed but must not be applied.
    Invalid(Vec<String>),
    /// Anything else.
    Msg(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn msg(m: impl Into<String>) -> Self {
        Error::Msg(m.into())
    }

    pub fn parse(file: &str, line: usize, msg: impl Into<String>) -> Self {
        Error::Parse {
            file: file.to_string(),
            line,
            msg: msg.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io { path, source } => write!(f, "{}: {}", path.display(), source),
            Error::Parse { file, line, msg } => write!(f, "{file}:{line}: {msg}"),
            Error::Invalid(problems) => {
                write!(f, "fix the configuration first:")?;
                for p in problems {
                    write!(f, "\n  {p}")?;
                }
                Ok(())
            }
            Error::Msg(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
