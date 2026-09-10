//! Native Spider bridge; never delegates applying hosts to the renderer.
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
};
pub const HOST: &str = "127.0.0.1:50761";
pub const ORIGIN: &str = "https://spider.yangdy.com";
const BEGIN: &str = "# BEGIN SPIDER MANAGED";
const END: &str = "# END SPIDER MANAGED";
const BEGIN_WITH_SEPARATOR: &str = "# BEGIN SPIDER MANAGED (separator added)";
pub const ENTRY_ID: &str = "spider-managed-environment";
pub static APPLY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn records(content: &str) -> Result<BTreeMap<String, BTreeSet<IpAddr>>, String> {
    if content.len() > 256 * 1024
        || content
            .bytes()
            .any(|b| b < 32 && !matches!(b, b'\n' | b'\r' | b'\t'))
    {
        return Err("Invalid or oversized hosts content".into());
    }
    let mut records = BTreeMap::<String, BTreeSet<IpAddr>>::new();
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let ip: IpAddr = parts
            .next()
            .unwrap()
            .parse()
            .map_err(|_| "Invalid IP address")?;
        let names: Vec<_> = parts.collect();
        if names.is_empty() {
            return Err("IP address has no hostname".into());
        }
        for name in names {
            if name.len() > 253
                || !name.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && label.as_bytes()[0].is_ascii_alphanumeric()
                        && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
            {
                return Err("Invalid hostname".into());
            }
            records
                .entry(name.to_ascii_lowercase())
                .or_default()
                .insert(ip);
        }
        if records.len() > 2000 {
            return Err("Too many hostnames".into());
        }
    }
    Ok(records)
}
fn conflicts(existing: &str, incoming: &str) -> Result<(), String> {
    let incoming = records(incoming)?;
    // Existing user content can include platform-specific directives; inspect
    // valid records, while strict validation applies to all incoming content.
    let mut current = BTreeMap::<String, BTreeSet<IpAddr>>::new();
    for line in existing.lines() {
        if let Ok(parsed) = records(line) {
            for (name, ips) in parsed {
                current.entry(name).or_default().extend(ips);
            }
        }
    }
    for (name, ips) in incoming {
        if current.get(&name).is_some_and(|other| *other != ips) {
            return Err(format!("Conflicting active hosts entry: {name}"));
        }
    }
    Ok(())
}
pub(crate) fn strip_block(content: &str) -> Result<String, String> {
    let starts: Vec<_> = content.match_indices(BEGIN).collect();
    let ends: Vec<_> = content.match_indices(END).collect();
    if starts.is_empty() && ends.is_empty() {
        return Ok(content.into());
    }
    if starts.len() != 1 || ends.len() != 1 || starts[0].0 >= ends[0].0 {
        return Err("Corrupt Spider managed block; recovery required".into());
    }
    let mut start = starts[0].0;
    if start > 0 && !content[..start].ends_with('\n') {
        return Err("Invalid Spider marker".into());
    }
    let header = content[start..].lines().next().unwrap_or("");
    if header != BEGIN && header != BEGIN_WITH_SEPARATOR {
        return Err("Invalid Spider marker".into());
    }
    if header == BEGIN_WITH_SEPARATOR {
        if start == 0 {
            return Err("Missing Spider separator".into());
        }
        // The separator is owned by the block. Ordinary Windows apply may
        // have converted its LF to CRLF since the native transaction.
        start -= if content[..start].ends_with("\r\n") {
            2
        } else {
            1
        };
    }
    let end = ends[0].0 + END.len();
    let tail = &content[end..];
    let end = if tail.starts_with("\r\n") {
        end + 2
    } else if tail.starts_with('\n') {
        end + 1
    } else if tail.is_empty() {
        end
    } else {
        return Err("Invalid Spider marker".into());
    };
    Ok(format!("{}{}", &content[..start], &content[end..]))
}

fn compose(current: &str, incoming: &str) -> Result<String, String> {
    let baseline = strip_block(current)?;
    if incoming.is_empty() {
        return Ok(baseline);
    }
    conflicts(&baseline, incoming)?;
    let separator = if baseline.is_empty() || baseline.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    let begin = if separator.is_empty() {
        BEGIN
    } else {
        BEGIN_WITH_SEPARATOR
    };
    Ok(format!(
        "{baseline}{separator}{begin}\n{}{END}\n",
        if incoming.ends_with('\n') {
            incoming.to_string()
        } else {
            format!("{incoming}\n")
        }
    ))
}
pub fn authorize(
    peer: SocketAddr,
    host: &str,
    origin: &str,
    bearer: Option<&str>,
    token: Option<&str>,
    pairing: bool,
) -> Result<(), String> {
    if !peer.ip().is_loopback() || host != HOST || origin != ORIGIN {
        return Err("Forbidden local bridge origin, host or peer".into());
    }
    if !pairing {
        let supplied = bearer
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or("Pair SwitchHosts first")?;
        let expected = token
            .filter(|s| !s.is_empty())
            .ok_or("Pair SwitchHosts first")?;
        if supplied.len() != expected.len()
            || supplied
                .bytes()
                .zip(expected.bytes())
                .fold(0u8, |diff, (a, b)| diff | (a ^ b))
                != 0
        {
            return Err("Invalid bridge token; pair again".into());
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_hosts_and_compares_address_sets() {
        assert!(records("127.0.0.1 foo.example\n::1 foo.example").is_ok());
        for bad in [
            "bogus foo",
            "127.0.0.1 -foo",
            "127.0.0.1 foo/path",
            "127.0.0.1",
            "127.0.0.1 foo\0",
        ] {
            assert!(records(bad).is_err(), "{bad}");
        }
        assert!(conflicts("1.2.3.4 foo\n::1 foo", "::1 foo\n1.2.3.4 foo").is_ok());
        assert!(conflicts("1.2.3.4 foo", "1.2.3.5 foo").is_err());
    }
    #[test]
    fn managed_block_preserves_baseline_and_reset_is_idempotent() {
        let original = "127.0.0.1 localhost\n# user comment\n";
        let installed = compose(original, "1.2.3.4 foo").unwrap();
        assert!(installed.starts_with(original));
        assert_eq!(strip_block(&installed).unwrap(), original);
        assert_eq!(compose(&installed, "1.2.3.4 foo").unwrap(), installed);
        assert_eq!(compose(&installed, "").unwrap(), original);
        assert!(strip_block("# BEGIN SPIDER MANAGED\nmissing end").is_err());
    }
    #[test]
    fn reset_preserves_baseline_without_final_newline_and_accepts_crlf_markers() {
        let baseline = "127.0.0.1 localhost";
        let applied = compose(baseline, "2.2.2.2 foo").unwrap();
        assert_eq!(compose(&applied, "").unwrap(), baseline);
        let crlf = compose("127.0.0.1 localhost\n", "2.2.2.2 foo")
            .unwrap()
            .replace('\n', "\r\n");
        assert_eq!(compose(&crlf, "").unwrap(), "127.0.0.1 localhost\r\n");
    }
    #[test]
    fn guard_rejects_foreign_peer_host_origin_and_token() {
        assert!(authorize(
            "127.0.0.1:42".parse().unwrap(),
            HOST,
            ORIGIN,
            Some("Bearer abc"),
            Some("abc"),
            false
        )
        .is_ok());
        for (peer, host, origin, bearer) in [
            ("10.0.0.1:42", HOST, ORIGIN, "Bearer abc"),
            ("127.0.0.1:42", "evil:50761", ORIGIN, "Bearer abc"),
            ("127.0.0.1:42", HOST, "https://evil.test", "Bearer abc"),
            ("127.0.0.1:42", HOST, ORIGIN, "Bearer wrong"),
        ] {
            assert!(authorize(
                peer.parse().unwrap(),
                host,
                origin,
                Some(bearer),
                Some("abc"),
                false
            )
            .is_err());
        }
        assert!(authorize(
            "127.0.0.1:42".parse().unwrap(),
            HOST,
            ORIGIN,
            None,
            None,
            false
        )
        .is_err());
        assert!(authorize("127.0.0.1:42".parse().unwrap(), HOST, "", None, None, true).is_err());
    }
}

#[cfg(test)]
mod transaction_tests {
    use super::*;
    use crate::storage::V5Paths;
    fn fixture() -> (V5Paths, std::path::PathBuf) {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "swh-spider-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let paths = V5Paths::under(root);
        paths.ensure_dirs().unwrap();
        let hosts = paths.root.join("fake-hosts");
        std::fs::write(&hosts, "127.0.0.1 localhost\n").unwrap();
        (paths, hosts)
    }
    fn request(mode: &str, content: &str) -> Environment {
        Environment {
            mode: mode.into(),
            content: content.into(),
            revision: if mode == "system" {
                String::new()
            } else {
                digest(content)
            },
        }
    }
    #[test]
    fn native_transaction_preserves_other_entries_and_detects_disk_drift() {
        let (paths, hosts) = fixture();
        let mut manifest = crate::storage::manifest::Manifest::default();
        manifest
            .root
            .push(serde_json::json!({"id":"other", "title":"Other", "on":true, "type":"local"}));
        manifest.save(&paths).unwrap();
        crate::storage::entries::write_entry(&paths.entries_dir, "other", "1.1.1.1 other").unwrap();
        let mut write = |s: &str| std::fs::write(&hosts, s).map_err(|e| e.to_string());
        let req = request("daily", "2.2.2.2 foo\n");
        apply(&paths, &hosts, &req, &mut write).unwrap();
        assert!(status(&paths, &hosts).unwrap().applied);
        let disk = std::fs::read_to_string(&hosts).unwrap();
        apply(&paths, &hosts, &req, &mut write).unwrap();
        assert_eq!(disk, std::fs::read_to_string(&hosts).unwrap());
        let m = crate::storage::manifest::Manifest::load(&paths).unwrap();
        assert_eq!(m.root[0]["on"], true);
        assert_eq!(m.root.iter().filter(|n| n["id"] == ENTRY_ID).count(), 1);
        std::fs::write(&hosts, "# drift\n").unwrap();
        assert!(!status(&paths, &hosts).unwrap().applied);
        std::fs::write(&hosts, disk).unwrap();
        apply(&paths, &hosts, &request("system", ""), &mut write).unwrap();
        assert!(!std::fs::read_to_string(&hosts).unwrap().contains("2.2.2.2"));
        assert_eq!(
            crate::storage::manifest::Manifest::load(&paths)
                .unwrap()
                .root[0]["on"],
            true
        );
        std::fs::remove_dir_all(paths.root).unwrap();
    }
    #[test]
    fn stale_renderer_aggregation_includes_current_managed_content() {
        let (paths, hosts) = fixture();
        let mut write = |s: &str| std::fs::write(&hosts, s).map_err(|e| e.to_string());
        apply(
            &paths,
            &hosts,
            &request("daily", "2.2.2.2 foo\n"),
            &mut write,
        )
        .unwrap();
        let aggregate = aggregate_for_ui(&paths, &[], false).unwrap();
        assert!(check_aggregate(&paths, &aggregate)
            .unwrap()
            .contains("2.2.2.2 foo"));
        std::fs::remove_dir_all(paths.root).unwrap();
    }
    #[test]
    fn native_then_ordinary_append_remains_switchable_and_resettable() {
        let (paths, hosts) = fixture();
        let mut write = |s: &str| std::fs::write(&hosts, s).map_err(|e| e.to_string());
        apply(
            &paths,
            &hosts,
            &request("daily", "2.2.2.2 foo\n"),
            &mut write,
        )
        .unwrap();
        let aggregate =
            check_aggregate(&paths, &aggregate_for_ui(&paths, &[], false).unwrap()).unwrap();
        let disk = std::fs::read_to_string(&hosts).unwrap();
        let append = crate::hosts_apply::write::make_append_content(&disk, &aggregate).unwrap();
        std::fs::write(&hosts, append).unwrap();
        apply(
            &paths,
            &hosts,
            &request("prod", "3.3.3.3 foo\n"),
            &mut write,
        )
        .unwrap();
        apply(&paths, &hosts, &request("system", ""), &mut write).unwrap();
        assert!(!std::fs::read_to_string(&hosts).unwrap().contains(BEGIN));
        std::fs::remove_dir_all(paths.root).unwrap();
    }
    #[test]
    fn pending_transaction_reports_unknown_then_recovers_without_renderer() {
        let (paths, hosts) = fixture();
        let before = std::fs::read_to_string(&hosts).unwrap();
        let after = compose(&before, "2.2.2.2 foo\n").unwrap();
        let files = SNAPSHOT_NAMES
            .iter()
            .map(|name| Snapshot {
                name: name.to_string(),
                bytes: read_optional(&paths.root.join(name)).unwrap(),
            })
            .collect();
        save_json(
            &journal_path(&paths),
            &Journal {
                before: before.clone(),
                after: after.clone(),
                files,
            },
        )
        .unwrap();
        std::fs::write(&hosts, &after).unwrap();
        assert!(!status(&paths, &hosts).unwrap().applied);
        assert!(require_no_pending_transaction(&paths).is_err());
        let mut write = |s: &str| std::fs::write(&hosts, s).map_err(|e| e.to_string());
        apply(&paths, &hosts, &request("system", ""), &mut write).unwrap();
        assert_eq!(std::fs::read_to_string(&hosts).unwrap(), before);
        assert!(status(&paths, &hosts).unwrap().applied);
        std::fs::remove_dir_all(paths.root).unwrap();
    }
    #[test]
    fn corrupt_journal_never_writes_hosts_during_recovery() {
        let (paths, hosts) = fixture();
        let current = std::fs::read_to_string(&hosts).unwrap();
        save_json(
            &journal_path(&paths),
            &Journal {
                before: "malformed untrusted snapshot".into(),
                after: current.clone(),
                files: vec![],
            },
        )
        .unwrap();
        let mut write = |s: &str| std::fs::write(&hosts, s).map_err(|e| e.to_string());
        assert!(apply(&paths, &hosts, &request("system", ""), &mut write).is_err());
        assert_eq!(std::fs::read_to_string(&hosts).unwrap(), current);
        assert!(!status(&paths, &hosts).unwrap().applied);
        std::fs::remove_dir_all(paths.root).unwrap();
    }
    #[test]
    fn metadata_commit_failure_rolls_back_prior_hosts_and_manifest() {
        let (paths, hosts) = fixture();
        let original = std::fs::read_to_string(&hosts).unwrap();
        let mut count = 0;
        let mut write = |s: &str| {
            std::fs::write(&hosts, s).map_err(|e| e.to_string())?;
            count += 1;
            if count == 1 {
                std::fs::rename(&paths.entries_dir, paths.root.join("entries-backup")).unwrap();
                std::fs::write(&paths.entries_dir, "block entries").unwrap();
            }
            Ok(())
        };
        assert!(apply(
            &paths,
            &hosts,
            &request("daily", "2.2.2.2 foo\n"),
            &mut write
        )
        .is_err());
        assert_eq!(std::fs::read_to_string(&hosts).unwrap(), original);
        assert!(!journal_path(&paths).exists());
        assert!(load_saved(&paths).unwrap().is_none());
        std::fs::remove_dir_all(paths.root).unwrap();
    }

    #[test]
    fn write_failure_and_conflict_do_not_replace_active_environment() {
        let (paths, hosts) = fixture();
        let before = std::fs::read_to_string(&hosts).unwrap();
        let mut fail = |_: &str| Err("denied".into());
        assert!(apply(&paths, &hosts, &request("prod", "2.2.2.2 foo\n"), &mut fail).is_err());
        assert_eq!(std::fs::read_to_string(&hosts).unwrap(), before);
        let mut write = |s: &str| std::fs::write(&hosts, s).map_err(|e| e.to_string());
        assert!(apply(
            &paths,
            &hosts,
            &request("prod", "2.2.2.2 localhost\n"),
            &mut write
        )
        .is_err());
        assert_eq!(std::fs::read_to_string(&hosts).unwrap(), before);
        std::fs::remove_dir_all(paths.root).unwrap();
    }
}

use crate::storage::{atomic::atomic_write, entries, manifest::Manifest, V5Paths};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub mode: String,
    pub content: String,
    pub revision: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    api_version: u8,
    mode: String,
    revision: String,
    pub applied: bool,
    entry_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}
#[derive(Deserialize, Serialize)]
struct Saved {
    environment: Environment,
    expected_hosts: String,
}
#[derive(Deserialize, Serialize)]
struct Snapshot {
    name: String,
    bytes: Option<Vec<u8>>,
}
#[derive(Deserialize, Serialize)]
struct Journal {
    before: String,
    after: String,
    files: Vec<Snapshot>,
}
fn digest(content: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(content.as_bytes()))
}
fn state_path(paths: &V5Paths) -> PathBuf {
    paths.root.join("internal/spider-environment.json")
}
fn journal_path(paths: &V5Paths) -> PathBuf {
    paths.root.join("internal/spider-transaction.json")
}
fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
fn sync_file(path: &Path) -> Result<(), String> {
    std::fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}
fn sync_parent(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            sync_file(parent)?;
        }
    }
    Ok(())
}
fn save_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    atomic_write(path, &serde_json::to_vec(value).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    sync_file(path)?;
    sync_parent(path)
}
fn validate_journal(journal: &Journal) -> Result<(), String> {
    if journal.files.len() != SNAPSHOT_NAMES.len()
        || journal
            .files
            .iter()
            .zip(SNAPSHOT_NAMES)
            .any(|(s, n)| s.name != n)
    {
        return Err("Invalid transaction snapshot".into());
    }
    Ok(())
}
fn load_saved(paths: &V5Paths) -> Result<Option<Saved>, String> {
    read_optional(&state_path(paths))?
        .map(|b| serde_json::from_slice(&b).map_err(|e| format!("Corrupt Spider state: {e}")))
        .transpose()
}
fn validate(request: &Environment) -> Result<usize, String> {
    if !["system", "prod", "staging", "daily"].contains(&request.mode.as_str()) {
        return Err("Unknown environment mode".into());
    }
    if request.mode == "system" {
        if !request.content.is_empty() || !request.revision.is_empty() {
            return Err("System mode requires empty content and revision".into());
        }
        return Ok(0);
    }
    if request.content.contains(BEGIN) || request.content.contains(END) {
        return Err("Reserved hosts marker".into());
    }
    let parsed = records(&request.content)?;
    if parsed.is_empty() || request.revision != digest(&request.content) {
        return Err("Empty hosts or revision mismatch".into());
    }
    Ok(parsed.len())
}
pub fn status(paths: &V5Paths, hosts: &Path) -> Result<Status, String> {
    let disk = std::fs::read_to_string(hosts).map_err(|e| e.to_string())?;
    let saved = load_saved(paths)?;
    let pending = journal_path(paths).exists();
    let environment = saved
        .as_ref()
        .map(|s| s.environment.clone())
        .unwrap_or(Environment {
            mode: "system".into(),
            content: String::new(),
            revision: String::new(),
        });
    let count = validate(&environment)?;
    let mut applied = !pending && strip_block(&disk).is_ok();
    if let Some(saved) = saved {
        applied &= saved.expected_hosts == disk;
        let manifest = Manifest::load(paths).map_err(|e| e.to_string())?;
        let nodes = managed_nodes(&manifest.root);
        applied &= if environment.mode == "system" {
            nodes.is_empty() && !disk.contains(BEGIN)
        } else {
            nodes.len() == 1
                && nodes[0].get("on").and_then(serde_json::Value::as_bool) == Some(true)
                && entries::read_entry(&paths.entries_dir, ENTRY_ID).map_err(|e| e.to_string())?
                    == block(&environment.content)
        };
    } else {
        applied &= !disk.contains(BEGIN);
    }
    Ok(Status {
        api_version: 1,
        mode: environment.mode,
        revision: environment.revision,
        applied,
        entry_count: count,
        message: if applied {
            None
        } else {
            Some(
                if pending {
                    "Incomplete transaction; retry to recover"
                } else {
                    "System hosts or managed entry differs from the applied environment"
                }
                .into(),
            )
        },
    })
}
fn managed_nodes(nodes: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    let mut found = Vec::new();
    for node in nodes {
        if node["id"] == ENTRY_ID {
            found.push(node);
        }
        if let Some(children) = node["children"].as_array() {
            found.extend(managed_nodes(children));
        }
    }
    found
}
fn remove_managed(nodes: &mut Vec<serde_json::Value>) {
    nodes.retain(|n| n["id"] != ENTRY_ID);
    for node in nodes {
        if let Some(children) = node
            .get_mut("children")
            .and_then(serde_json::Value::as_array_mut)
        {
            remove_managed(children);
        }
    }
}
fn block(content: &str) -> String {
    format!(
        "{BEGIN}\n{}{END}\n",
        if content.ends_with('\n') {
            content.to_string()
        } else {
            format!("{content}\n")
        }
    )
}
const SNAPSHOT_NAMES: [&str; 4] = [
    "manifest.json",
    "internal/state.json",
    "entries/spider-managed-environment.hosts",
    "internal/spider-environment.json",
];
fn restore(paths: &V5Paths, journal: &Journal) -> Result<(), String> {
    validate_journal(journal)?;
    for snapshot in &journal.files {
        let path = paths.root.join(&snapshot.name);
        match &snapshot.bytes {
            Some(b) => atomic_write(&path, b).map_err(|e| e.to_string())?,
            None => {
                if path.exists() {
                    std::fs::remove_file(path).map_err(|e| e.to_string())?;
                }
            }
        }
    }
    Ok(())
}
fn recover(
    paths: &V5Paths,
    hosts: &Path,
    write: &mut impl FnMut(&str) -> Result<(), String>,
) -> Result<(), String> {
    let Some(bytes) = read_optional(&journal_path(paths))? else {
        return Ok(());
    };
    let journal: Journal = serde_json::from_slice(&bytes)
        .map_err(|_| "Corrupt transaction journal; manual recovery required")?;
    validate_journal(&journal)?;
    let actual = std::fs::read_to_string(hosts).map_err(|e| e.to_string())?;
    if actual != journal.before {
        if actual != journal.after {
            return Err(
                "Hosts changed during incomplete transaction; recovery state unknown".into(),
            );
        }
        write(&journal.before)?;
    }
    if std::fs::read_to_string(hosts).map_err(|e| e.to_string())? != journal.before {
        return Err("Cannot verify transaction rollback".into());
    }
    restore(paths, &journal)?;
    std::fs::remove_file(journal_path(paths)).map_err(|e| e.to_string())
}
pub fn apply(
    paths: &V5Paths,
    hosts: &Path,
    request: &Environment,
    write: &mut impl FnMut(&str) -> Result<(), String>,
) -> Result<Status, String> {
    validate(request)?;
    recover(paths, hosts, write)?;
    // Validate existing state before any mutation. A malformed file never resets silently.
    let previous = load_saved(paths)?;
    if previous.as_ref().is_some_and(|s| s.environment == *request) && status(paths, hosts)?.applied
    {
        return status(paths, hosts);
    }
    let before = std::fs::read_to_string(hosts).map_err(|e| e.to_string())?;
    let mut manifest = Manifest::load(paths).map_err(|e| e.to_string())?;
    remove_managed(&mut manifest.root);
    let other = crate::hosts_apply::aggregate_selected_content(&manifest.root, paths, false)
        .map_err(|e| e.to_string())?;
    conflicts(&other, &request.content)?;
    let after = compose(&before, &request.content)?;
    let files = SNAPSHOT_NAMES
        .iter()
        .map(|name| {
            Ok(Snapshot {
                name: name.to_string(),
                bytes: read_optional(&paths.root.join(name))?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let journal = Journal {
        before: before.clone(),
        after: after.clone(),
        files,
    };
    save_json(&journal_path(paths), &journal)?;
    let result = (|| {
        write(&after)?;
        if std::fs::read_to_string(hosts).map_err(|e| e.to_string())? != after {
            return Err("System hosts verification failed".into());
        }
        if request.mode != "system" {
            manifest.root.push(serde_json::json!({"id":ENTRY_ID,"title":"Spider运行环境","type":"local","on":true}));
            entries::write_entry(&paths.entries_dir, ENTRY_ID, &block(&request.content))
                .map_err(|e| e.to_string())?;
        } else {
            entries::delete_entry(&paths.entries_dir, ENTRY_ID).map_err(|e| e.to_string())?;
        }
        manifest.save(paths).map_err(|e| e.to_string())?;
        save_json(
            &state_path(paths),
            &Saved {
                environment: request.clone(),
                expected_hosts: after.clone(),
            },
        )?;
        for name in SNAPSHOT_NAMES {
            let path = paths.root.join(name);
            if path.exists() {
                sync_file(&path)?;
            }
            sync_parent(&path)?;
        }
        Ok::<_, String>(())
    })();
    if let Err(error) = result {
        return match recover(paths, hosts, write) {
            Ok(()) => Err(error),
            Err(recovery) => Err(format!("{error}; rollback incomplete: {recovery}")),
        };
    }
    std::fs::remove_file(journal_path(paths))
        .map_err(|e| format!("Applied but transaction finalization failed: {e}"))?;
    sync_parent(&journal_path(paths))?;
    status(paths, hosts)
}

pub fn require_no_pending_transaction(paths: &V5Paths) -> Result<(), String> {
    if journal_path(paths).exists() {
        Err("An incomplete Spider transaction must be recovered before applying hosts".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod coordination_tests {
    use super::*;
    #[test]
    fn stale_list_cannot_drop_new_native_entry_but_explicit_disable_survives() {
        let current = vec![serde_json::json!({"id":ENTRY_ID,"on":true})];
        let mut stale = vec![serde_json::json!({"id":"other","on":true})];
        retain_managed_entry(&current, &mut stale);
        assert_eq!(managed_nodes(&stale).len(), 1);
        assert_eq!(managed_nodes(&stale)[0]["on"], true);
        let mut disabled = vec![serde_json::json!({"id":ENTRY_ID,"on":false})];
        retain_managed_entry(&current, &mut disabled);
        assert_eq!(disabled[0]["on"], false);
    }
    #[test]
    fn rejects_aggregate_from_before_native_switch() {
        let root = std::env::temp_dir().join(format!("spider-snapshot-{}", std::process::id()));
        let paths = V5Paths::under(root);
        paths.ensure_dirs().unwrap();
        let old = stamp_aggregate(&paths, "127.0.0.1 localhost").unwrap();
        save_json(
            &state_path(&paths),
            &Saved {
                environment: Environment {
                    mode: "daily".into(),
                    content: "2.2.2.2 foo\n".into(),
                    revision: digest("2.2.2.2 foo\n"),
                },
                expected_hosts: String::new(),
            },
        )
        .unwrap();
        assert!(check_aggregate(&paths, &old).is_err());
        let fresh = stamp_aggregate(&paths, "127.0.0.1 localhost").unwrap();
        assert_eq!(
            check_aggregate(&paths, &fresh).unwrap(),
            "127.0.0.1 localhost"
        );
        std::fs::remove_dir_all(paths.root).unwrap();
    }
}
const SNAPSHOT_MARKER: &str = "\n# SPIDER APPLY SNAPSHOT ";
fn generation(paths: &V5Paths) -> Result<String, String> {
    Ok(read_optional(&state_path(paths))?
        .map(|b| digest(&String::from_utf8_lossy(&b)))
        .unwrap_or("unpaired".into()))
}
pub fn stamp_aggregate(paths: &V5Paths, content: &str) -> Result<String, String> {
    Ok(format!("{content}{SNAPSHOT_MARKER}{}", generation(paths)?))
}
pub fn check_aggregate(paths: &V5Paths, content: &str) -> Result<String, String> {
    if let Some((body, stamp)) = content.rsplit_once(SNAPSHOT_MARKER) {
        if stamp == generation(paths)? {
            return Ok(body.into());
        }
        return Err("Spider environment changed; reload the list and apply again".into());
    }
    if load_saved(paths)?.is_some() {
        return Err("Reload hosts selection before applying while Spider is connected".into());
    }
    Ok(content.into())
}
/// A stale list reorder cannot silently delete a newly created native entry.
pub fn retain_managed_entry(current: &[serde_json::Value], next: &mut Vec<serde_json::Value>) {
    if managed_nodes(next).is_empty() {
        for node in managed_nodes(current) {
            next.push(node.clone());
        }
    }
}

pub fn aggregate_for_ui(
    paths: &V5Paths,
    list: &[serde_json::Value],
    dedup: bool,
) -> Result<String, String> {
    let current = Manifest::load(paths).map_err(|e| e.to_string())?;
    let mut list = list.to_vec();
    retain_managed_entry(&current.root, &mut list);
    stamp_aggregate(
        paths,
        &crate::hosts_apply::aggregate_selected_content(&list, paths, dedup)
            .map_err(|e| e.to_string())?,
    )
}
