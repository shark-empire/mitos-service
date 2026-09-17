//! Risk classification for named capabilities - the "how dangerous is
//! this" step the MITOS permissions design describes mitos-service
//! doing before deciding whether a prompt needs a password. Purely a
//! lookup table today: given a capability name, what's its risk level.
//!
//! Capability names are free-form strings (not an enum) on purpose -
//! this project doesn't get to enumerate every capability mitos-kernel
//! or mitos-init might ever report; an unrecognized name is classified
//! `Dangerous` (see `classify`'s doc) rather than rejected, so a new
//! capability nobody's taught this table about yet fails toward asking
//! rather than silently auto-allowing.

use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Risk {
    /// Read-only, narrowly-scoped, hard to abuse - e.g. reading the
    /// system's own idle/battery state. Still asked about once; MITOS's
    /// golden rules don't carve out a silent-allow tier at all.
    Low,
    /// Meaningful access to something private or shared, but reversible
    /// and contained - e.g. the microphone, the camera, a specific
    /// folder.
    Moderate,
    /// Whole-system or hard-to-reverse access - e.g. raw disk access,
    /// installing a kernel module, reading another app's private data.
    Dangerous,
    /// Root-equivalent or safety-relevant - e.g. writing to firmware,
    /// disabling the permission system itself.
    Critical,
}

impl Risk {
    pub fn as_str(&self) -> &'static str {
        match self {
            Risk::Low => "low",
            Risk::Moderate => "moderate",
            Risk::Dangerous => "dangerous",
            Risk::Critical => "critical",
        }
    }
}

/// The built-in classification table. Loaded once; see `classify`.
fn table() -> &'static HashMap<&'static str, Risk> {
    static TABLE: OnceLock<HashMap<&'static str, Risk>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = HashMap::new();
        t.insert("battery_status", Risk::Low);
        t.insert("idle_state", Risk::Low);
        t.insert("network_status", Risk::Low);
        t.insert("notification_post", Risk::Low);

        t.insert("microphone", Risk::Moderate);
        t.insert("camera", Risk::Moderate);
        t.insert("location", Risk::Moderate);
        t.insert("contacts_read", Risk::Moderate);
        t.insert("clipboard_read", Risk::Moderate);
        t.insert("downloads_folder", Risk::Moderate);
        t.insert("bluetooth", Risk::Moderate);

        t.insert("raw_disk", Risk::Dangerous);
        t.insert("all_files", Risk::Dangerous);
        t.insert("other_app_data", Risk::Dangerous);
        t.insert("ptrace", Risk::Dangerous);
        t.insert("network_raw_socket", Risk::Dangerous);
        t.insert("mount_filesystem", Risk::Dangerous);
        t.insert("kernel_module_load", Risk::Dangerous);
        t.insert("root_shell", Risk::Dangerous);

        t.insert("firmware_write", Risk::Critical);
        t.insert("disable_permission_system", Risk::Critical);
        t.insert("bootloader_write", Risk::Critical);
        t
    })
}

/// Classifies `capability`. An unrecognized name is classified
/// `Dangerous` rather than rejected outright or treated as `Low` -
/// erring toward "ask, and take it seriously" for anything this table
/// hasn't been explicitly taught is safer than that. Update the table
/// in `table()` above as mitos-kernel/mitos-init grow real capability
/// names to report.
pub fn classify(capability: &str) -> Risk {
    table().get(capability).copied().unwrap_or(Risk::Dangerous)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_a_known_low_risk_capability() {
        assert_eq!(classify("battery_status"), Risk::Low);
    }

    #[test]
    fn classifies_a_known_critical_capability() {
        assert_eq!(classify("firmware_write"), Risk::Critical);
    }

    #[test]
    fn unrecognized_capability_defaults_to_dangerous() {
        assert_eq!(classify("something_nobody_taught_this_table_about"), Risk::Dangerous);
    }

    #[test]
    fn risk_levels_order_low_to_critical() {
        assert!(Risk::Low < Risk::Moderate);
        assert!(Risk::Moderate < Risk::Dangerous);
        assert!(Risk::Dangerous < Risk::Critical);
    }
}
