use serde::{Deserialize, Serialize};
use std::str::FromStr;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub enum OutputStatus {
    Unspent,
    Locked,
    Spent,
    /// Output discovered during fast sync backfill that is known to be spent
    /// but whose spending input has not yet been processed. Once the backfill
    /// processes the corresponding input, the status transitions to `Spent`.
    SpentUnconfirmed,
}

impl std::fmt::Display for OutputStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputStatus::Unspent => write!(f, "UNSPENT"),
            OutputStatus::Locked => write!(f, "LOCKED"),
            OutputStatus::Spent => write!(f, "SPENT"),
            OutputStatus::SpentUnconfirmed => write!(f, "SPENT_UNCONFIRMED"),
        }
    }
}

impl FromStr for OutputStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "UNSPENT" => Ok(OutputStatus::Unspent),
            "LOCKED" => Ok(OutputStatus::Locked),
            "SPENT" => Ok(OutputStatus::Spent),
            "SPENT_UNCONFIRMED" => Ok(OutputStatus::SpentUnconfirmed),
            _ => Err(format!("Invalid OutputStatus: {}", s)),
        }
    }
}
