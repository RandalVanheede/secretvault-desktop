use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Manager};

const KEYCHAIN_SERVICE: &str = "ddev-secret-vault";
const KEYCHAIN_ACCOUNT: &str = "master";
const MARKER_START: &str = "# --- secret-vault: BEGIN ---";
const MARKER_END: &str = "# --- secret-vault: END ---";

#[derive(Default)]
struct AppState {
    unlocked_password: Mutex<Option<String>>,
    initial_project: Mutex<Option<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultSummary {
    project: String,
    path: String,
    modified_at: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppBootstrap {
    vault_dir: String,
    keychain_available: bool,
    stored_password_available: bool,
    unlocked: bool,
    initial_project: Option<String>,
    vaults: Vec<VaultSummary>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SecretEntry {
    key: String,
    value: String,
    imported_from: Option<String>,
    imported_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultDetails {
    project: String,
    path: String,
    project_path: Option<String>,
    created: Option<String>,
    updated: Option<String>,
    secret_count: usize,
    secrets: Vec<SecretEntry>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportCandidate {
    path: String,
    kind: String,
    label: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportPreviewItem {
    key: String,
    value_preview: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportPreview {
    path: String,
    kind: String,
    secret_count: usize,
    secrets: Vec<ImportPreviewItem>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CleanPreview {
    backup_path: String,
    diff: String,
    cleaned_content: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportResult {
    vault: VaultDetails,
    imported_count: usize,
    cleaned: bool,
    cleaned_file: Option<String>,
    backup_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnlockPayload {
    password: String,
    save_to_keychain: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SaveSecretPayload {
    project: String,
    key: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteSecretPayload {
    project: String,
    key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportPayload {
    project: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateVaultPayload {
    project: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteVaultPayload {
    project: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProjectPathPayload {
    project: String,
    project_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SaveProjectPathPayload {
    project: String,
    project_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangePasswordPayload {
    current_password: String,
    new_password: String,
    save_to_keychain: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportPreviewPayload {
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportApplyPayload {
    project: String,
    path: String,
    clean: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InjectionStatus {
    env_path: String,
    injected_count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CleanStatus {
    env_path: String,
    removed: bool,
}

#[derive(Debug)]
enum ImportKind {
    Env,
    Php,
}

#[derive(Debug, Clone)]
struct ParsedSecret {
    key: String,
    value: String,
}

#[derive(Debug)]
struct ParsedImport {
    kind: ImportKind,
    source_label: String,
    secrets: Vec<ParsedSecret>,
    original_content: String,
}

#[tauri::command]
fn bootstrap(state: tauri::State<'_, AppState>) -> Result<AppBootstrap, String> {
    let vault_dir = vault_dir()?;
    let vaults = list_vault_summaries(&vault_dir)?;
    let unlocked = state
        .unlocked_password
        .lock()
        .map_err(|_| "Failed to read app state".to_string())?
        .is_some();
    let initial_project = state
        .initial_project
        .lock()
        .map_err(|_| "Failed to read app state".to_string())?
        .clone();

    Ok(AppBootstrap {
        vault_dir: vault_dir.display().to_string(),
        keychain_available: keychain_available(),
        stored_password_available: load_password_from_keychain().is_some(),
        unlocked,
        initial_project,
        vaults,
    })
}

#[tauri::command]
fn unlock(payload: UnlockPayload, state: tauri::State<'_, AppState>) -> Result<(), String> {
    if payload.password.len() < 8 {
        return Err("Password must be at least 8 characters.".to_string());
    }

    validate_password(&payload.password)?;

    if payload.save_to_keychain {
        save_password_to_keychain(&payload.password)?;
    }

    let mut guard = state
        .unlocked_password
        .lock()
        .map_err(|_| "Failed to store app state".to_string())?;
    *guard = Some(payload.password);
    Ok(())
}

#[tauri::command]
fn use_stored_password(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let password = load_password_from_keychain()
        .ok_or_else(|| "No stored password found in the OS keychain.".to_string())?;
    validate_password(&password)?;

    let mut guard = state
        .unlocked_password
        .lock()
        .map_err(|_| "Failed to store app state".to_string())?;
    *guard = Some(password);
    Ok(())
}

#[tauri::command]
fn lock_app(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut guard = state
        .unlocked_password
        .lock()
        .map_err(|_| "Failed to update app state".to_string())?;
    *guard = None;
    Ok(())
}

#[tauri::command]
fn list_vaults() -> Result<Vec<VaultSummary>, String> {
    list_vault_summaries(&vault_dir()?)
}

#[tauri::command]
fn create_vault(
    payload: CreateVaultPayload,
    state: tauri::State<'_, AppState>,
) -> Result<VaultDetails, String> {
    let password = get_password(&state)?;
    let project = payload.project.trim();
    validate_project_name(project)?;

    let vault_path = vault_path(project)?;
    if vault_path.exists() {
        return Err(format!("A vault for '{}' already exists.", project));
    }

    let dir = vault_dir()?;
    fs::create_dir_all(&dir).map_err(|err| format!("Failed to create {}: {err}", dir.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .map_err(|err| format!("Failed to set directory permissions: {err}"))?;
    }

    let now = iso_now();
    let data = json_object([
        ("version", Value::Number(1.into())),
        ("project", Value::String(project.to_string())),
        ("created", Value::String(now.clone())),
        ("updated", Value::String(now)),
        ("secrets", Value::Object(Map::new())),
        (
            "metadata",
            json_object([("vault", Value::Object(Map::new()))]),
        ),
    ]);

    encrypt_vault(&vault_path, &password, &data)?;
    Ok(to_vault_details(&vault_path, &data))
}

#[tauri::command]
fn delete_vault(payload: DeleteVaultPayload) -> Result<(), String> {
    let vault_path = vault_path(&payload.project)?;
    if !vault_path.exists() {
        return Err(format!("Vault '{}' does not exist.", payload.project));
    }
    fs::remove_file(&vault_path)
        .map_err(|err| format!("Failed to delete {}: {err}", vault_path.display()))?;
    Ok(())
}

#[tauri::command]
fn get_vault(project: String, state: tauri::State<'_, AppState>) -> Result<VaultDetails, String> {
    let password = get_password(&state)?;
    let vault_path = vault_path(&project)?;
    let data = decrypt_vault(&vault_path, &password)?;
    Ok(to_vault_details(&vault_path, &data))
}

#[tauri::command]
fn save_secret(
    payload: SaveSecretPayload,
    state: tauri::State<'_, AppState>,
) -> Result<VaultDetails, String> {
    validate_key(&payload.key)?;
    let password = get_password(&state)?;
    let vault_path = vault_path(&payload.project)?;
    let mut data = decrypt_vault(&vault_path, &password)?;
    let now = iso_now();

    ensure_object(&mut data, "secrets")?.insert(payload.key.clone(), Value::String(payload.value));
    let metadata = ensure_object(&mut data, "metadata")?;
    let entry = metadata
        .entry(payload.key)
        .or_insert_with(|| Value::Object(Map::new()));
    let entry_obj = entry
        .as_object_mut()
        .ok_or_else(|| "Vault metadata is invalid.".to_string())?;
    entry_obj.insert("updated_at".to_string(), Value::String(now.clone()));
    data["updated"] = Value::String(now);

    encrypt_vault(&vault_path, &password, &data)?;
    Ok(to_vault_details(&vault_path, &data))
}

#[tauri::command]
fn delete_secret(
    payload: DeleteSecretPayload,
    state: tauri::State<'_, AppState>,
) -> Result<VaultDetails, String> {
    let password = get_password(&state)?;
    let vault_path = vault_path(&payload.project)?;
    let mut data = decrypt_vault(&vault_path, &password)?;

    let removed = ensure_object(&mut data, "secrets")?
        .remove(&payload.key)
        .is_some();
    if !removed {
        return Err(format!("Secret '{}' not found.", payload.key));
    }

    ensure_object(&mut data, "metadata")?.remove(&payload.key);
    data["updated"] = Value::String(iso_now());

    encrypt_vault(&vault_path, &password, &data)?;
    Ok(to_vault_details(&vault_path, &data))
}

#[tauri::command]
fn export_env(payload: ExportPayload, state: tauri::State<'_, AppState>) -> Result<String, String> {
    let password = get_password(&state)?;
    let vault_path = vault_path(&payload.project)?;
    let data = decrypt_vault(&vault_path, &password)?;

    let secrets = data
        .get("secrets")
        .and_then(Value::as_object)
        .ok_or_else(|| "Vault secrets are invalid.".to_string())?;

    let mut lines = vec![
        format!("# secret-vault export - project: {}", payload.project),
        format!("# exported: {}", iso_now()),
        format!("# secrets: {}", secrets.len()),
        String::new(),
    ];

    let mut keys: Vec<_> = secrets.keys().cloned().collect();
    keys.sort();

    for key in keys {
        let value = secrets
            .get(&key)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("Secret '{}' has an invalid value.", key))?;
        lines.push(format_env_assignment(&key, value));
    }

    Ok(format!("{}\n", lines.join("\n")))
}

#[tauri::command]
fn inject_project_env(
    payload: ProjectPathPayload,
    state: tauri::State<'_, AppState>,
) -> Result<InjectionStatus, String> {
    let password = get_password(&state)?;
    let vault_path = vault_path(&payload.project)?;
    let data = decrypt_vault(&vault_path, &password)?;
    let secrets = data
        .get("secrets")
        .and_then(Value::as_object)
        .ok_or_else(|| "Vault secrets are invalid.".to_string())?;
    let env_path = Path::new(&payload.project_path).join(".ddev").join(".env");

    let mut existing = String::new();
    if env_path.exists() {
        existing = fs::read_to_string(&env_path)
            .map_err(|err| format!("Failed to read {}: {err}", env_path.display()))?;
    }

    let cleaned = strip_secret_block(&existing).trim_end().to_string();
    let mut lines = Vec::new();
    if !cleaned.is_empty() {
        lines.push(cleaned);
        lines.push(String::new());
    }
    lines.push(MARKER_START.to_string());

    let mut keys: Vec<_> = secrets.keys().cloned().collect();
    keys.sort();
    for key in &keys {
        let value = secrets
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("Secret '{}' has an invalid value.", key))?;
        lines.push(format_env_assignment(key, value));
    }
    lines.push(MARKER_END.to_string());

    if let Some(parent) = env_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("Failed to create {}: {err}", parent.display()))?;
    }
    fs::write(&env_path, format!("{}\n", lines.join("\n")))
        .map_err(|err| format!("Failed to write {}: {err}", env_path.display()))?;

    Ok(InjectionStatus {
        env_path: env_path.display().to_string(),
        injected_count: keys.len(),
    })
}

#[tauri::command]
fn save_project_path(
    payload: SaveProjectPathPayload,
    state: tauri::State<'_, AppState>,
) -> Result<VaultDetails, String> {
    let password = get_password(&state)?;
    let vault_path = vault_path(&payload.project)?;
    let mut data = decrypt_vault(&vault_path, &password)?;
    let trimmed = payload.project_path.trim();

    let vault_meta = ensure_vault_metadata(&mut data)?;
    if trimmed.is_empty() {
        vault_meta.remove("project_path");
    } else {
        vault_meta.insert(
            "project_path".to_string(),
            Value::String(trimmed.to_string()),
        );
    }
    data["updated"] = Value::String(iso_now());

    encrypt_vault(&vault_path, &password, &data)?;
    Ok(to_vault_details(&vault_path, &data))
}

#[tauri::command]
fn clean_project_env(payload: ProjectPathPayload) -> Result<CleanStatus, String> {
    let env_path = Path::new(&payload.project_path).join(".ddev").join(".env");
    if !env_path.exists() {
        return Ok(CleanStatus {
            env_path: env_path.display().to_string(),
            removed: false,
        });
    }

    let existing = fs::read_to_string(&env_path)
        .map_err(|err| format!("Failed to read {}: {err}", env_path.display()))?;
    let cleaned = strip_secret_block(&existing).trim().to_string();

    if cleaned.is_empty() {
        fs::remove_file(&env_path)
            .map_err(|err| format!("Failed to remove {}: {err}", env_path.display()))?;
    } else {
        fs::write(&env_path, format!("{}\n", cleaned))
            .map_err(|err| format!("Failed to write {}: {err}", env_path.display()))?;
    }

    Ok(CleanStatus {
        env_path: env_path.display().to_string(),
        removed: true,
    })
}

#[tauri::command]
fn change_master_password(
    payload: ChangePasswordPayload,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    if payload.new_password.len() < 8 {
        return Err("New password must be at least 8 characters.".to_string());
    }

    validate_password(&payload.current_password)?;
    let vaults = collect_vault_paths(&vault_dir()?)?;

    for vault_path in &vaults {
        let data = decrypt_vault(vault_path, &payload.current_password)?;
        encrypt_vault(vault_path, &payload.new_password, &data)?;
    }

    if payload.save_to_keychain {
        save_password_to_keychain(&payload.new_password)?;
    }

    let mut guard = state
        .unlocked_password
        .lock()
        .map_err(|_| "Failed to update app state".to_string())?;
    *guard = Some(payload.new_password);
    Ok(())
}

#[tauri::command]
fn find_import_candidates(project_path: String) -> Result<Vec<ImportCandidate>, String> {
    let root = PathBuf::from(project_path);
    let mut candidates = Vec::new();

    collect_env_candidates(&root, &mut candidates);

    for base in ["web/sites", "docroot/sites", "sites"] {
        let base_path = root.join(base);
        if !base_path.exists() {
            continue;
        }
        collect_settings_local_candidates(&base_path, &mut candidates)?;
    }

    candidates.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(candidates)
}

#[tauri::command]
fn preview_import(payload: ImportPreviewPayload) -> Result<ImportPreview, String> {
    let parsed = parse_import_file(Path::new(&payload.path))?;
    Ok(ImportPreview {
        path: payload.path,
        kind: import_kind_name(&parsed.kind).to_string(),
        secret_count: parsed.secrets.len(),
        secrets: parsed
            .secrets
            .iter()
            .map(|secret| ImportPreviewItem {
                key: secret.key.clone(),
                value_preview: mask_value(&secret.value),
            })
            .collect(),
    })
}

#[tauri::command]
fn preview_clean_import_source(payload: ImportPreviewPayload) -> Result<CleanPreview, String> {
    let path = PathBuf::from(&payload.path);
    let parsed = parse_import_file(&path)?;
    let (cleaned_content, diff) = match parsed.kind {
        ImportKind::Env => clean_env_content(&parsed.original_content),
        ImportKind::Php => clean_php_content(&parsed.original_content, &parsed.secrets),
    };

    Ok(CleanPreview {
        backup_path: format!("{}.bak", path.display()),
        diff,
        cleaned_content,
    })
}

#[tauri::command]
fn apply_import(
    payload: ImportApplyPayload,
    state: tauri::State<'_, AppState>,
) -> Result<ImportResult, String> {
    let password = get_password(&state)?;
    let vault_path = vault_path(&payload.project)?;
    let mut data = decrypt_vault(&vault_path, &password)?;
    let source_path = PathBuf::from(&payload.path);
    let parsed = parse_import_file(&source_path)?;
    let now = iso_now();

    for secret in &parsed.secrets {
        ensure_object(&mut data, "secrets")?
            .insert(secret.key.clone(), Value::String(secret.value.clone()));
        ensure_object(&mut data, "metadata")?.insert(
            secret.key.clone(),
            json_object([
                ("imported_from", Value::String(parsed.source_label.clone())),
                ("imported_at", Value::String(now.clone())),
                ("updated_at", Value::String(now.clone())),
            ]),
        );
    }

    data["updated"] = Value::String(now);
    encrypt_vault(&vault_path, &password, &data)?;

    let mut cleaned_file = None;
    let mut backup_path = None;
    if payload.clean {
        let (cleaned_content, _) = match parsed.kind {
            ImportKind::Env => clean_env_content(&parsed.original_content),
            ImportKind::Php => clean_php_content(&parsed.original_content, &parsed.secrets),
        };
        let backup = format!("{}.bak", source_path.display());
        fs::copy(&source_path, &backup)
            .map_err(|err| format!("Failed to create backup {}: {err}", backup))?;
        fs::write(&source_path, cleaned_content)
            .map_err(|err| format!("Failed to write {}: {err}", source_path.display()))?;
        cleaned_file = Some(source_path.display().to_string());
        backup_path = Some(backup);
    }

    Ok(ImportResult {
        vault: to_vault_details(&vault_path, &data),
        imported_count: parsed.secrets.len(),
        cleaned: payload.clean,
        cleaned_file,
        backup_path,
    })
}

fn vault_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set.".to_string())?;
    Ok(Path::new(&home).join(".ddev").join("secret-vault"))
}

fn collect_vault_paths(dir: &Path) -> Result<Vec<PathBuf>, String> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut paths = Vec::new();
    let entries =
        fs::read_dir(dir).map_err(|err| format!("Failed to read {}: {err}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|err| format!("Failed to read vault entry: {err}"))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("vault") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn list_vault_summaries(dir: &Path) -> Result<Vec<VaultSummary>, String> {
    collect_vault_paths(dir)?
        .into_iter()
        .map(|path| {
            let metadata = fs::metadata(&path)
                .map_err(|err| format!("Failed to stat {}: {err}", path.display()))?;
            let modified_at = metadata.modified().ok().and_then(system_time_to_iso);
            let project = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .ok_or_else(|| format!("Invalid vault filename: {}", path.display()))?
                .to_string();

            Ok(VaultSummary {
                project,
                path: path.display().to_string(),
                modified_at,
            })
        })
        .collect()
}

fn collect_settings_local_candidates(
    dir: &Path,
    out: &mut Vec<ImportCandidate>,
) -> Result<(), String> {
    let entries =
        fs::read_dir(dir).map_err(|err| format!("Failed to read {}: {err}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|err| format!("Failed to read {}: {err}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_settings_local_candidates(&path, out)?;
            continue;
        }
        if path.file_name().and_then(|name| name.to_str()) == Some("settings.local.php") {
            let subsite = path
                .parent()
                .and_then(Path::file_name)
                .and_then(|name| name.to_str())
                .unwrap_or("site");
            out.push(ImportCandidate {
                path: path.display().to_string(),
                kind: "php".to_string(),
                label: format!("settings.local.php ({subsite})"),
            });
        }
    }
    Ok(())
}

fn parse_import_file(path: &Path) -> Result<ParsedImport, String> {
    if !path.exists() {
        return Err(format!("Import file not found: {}", path.display()));
    }

    let original_content = fs::read_to_string(path)
        .map_err(|err| format!("Failed to read {}: {err}", path.display()))?;
    if path.extension().and_then(|ext| ext.to_str()) == Some("php") {
        let secrets = parse_php_secrets(&original_content, path);
        return Ok(ParsedImport {
            kind: ImportKind::Php,
            source_label: path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("settings.local.php")
                .to_string(),
            secrets,
            original_content,
        });
    }

    let secrets = parse_env_secrets(&original_content)?;
    Ok(ParsedImport {
        kind: ImportKind::Env,
        source_label: path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(".env")
            .to_string(),
        secrets,
        original_content,
    })
}

fn parse_env_secrets(content: &str) -> Result<Vec<ParsedSecret>, String> {
    let mut secrets = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, raw_value)) = trimmed.split_once('=') else {
            continue;
        };
        let mut key = key.trim().to_string();
        if validate_key(&key).is_err() {
            if let Some(mapped) = derive_env_key_from_label(key.as_str()) {
                key = mapped;
            } else {
                continue;
            }
        }

        let mut value = raw_value.trim().to_string();
        if ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
            && value.len() >= 2
        {
            value = value[1..value.len() - 1].to_string();
        } else if let Some(index) = value.find(" #") {
            value = value[..index].trim_end().to_string();
        }

        secrets.push(ParsedSecret { key, value });
    }

    if secrets.is_empty() {
        return Err("No importable KEY=VALUE entries found.".to_string());
    }

    Ok(secrets)
}

fn parse_php_secrets(content: &str, path: &Path) -> Vec<ParsedSecret> {
    let mut secrets = std::collections::BTreeMap::<String, String>::new();
    let subsite_prefix = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .map(normalize_env_name)
        .unwrap_or_else(|| "SITE".to_string());

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }

        if trimmed.contains("hash_salt") {
            if let Some(value) = extract_quoted_value(trimmed) {
                secrets.insert("DRUPAL_HASH_SALT".to_string(), value);
            }
        }

        if (trimmed.contains("['password']")
            || trimmed.contains("\"password\"")
            || trimmed.contains("=>"))
            && trimmed.contains("password")
            && !trimmed.contains("getenv(")
        {
            if let Some(value) = extract_quoted_value(trimmed) {
                if !matches!(value.as_str(), "db" | "root" | "drupal" | "") {
                    secrets.entry("DB_PASSWORD".to_string()).or_insert(value);
                }
            }
        }

        if trimmed.contains("username") && !trimmed.contains("getenv(") {
            if let Some(value) = extract_quoted_value(trimmed) {
                if !matches!(value.as_str(), "db" | "root" | "drupal" | "") {
                    secrets.entry("DB_USER".to_string()).or_insert(value);
                }
            }
        }

        if let Some((config_key, value)) = extract_php_assignment(trimmed) {
            let lower = config_key.to_lowercase();
            if lower.contains("password")
                || lower.contains("token")
                || lower.contains("secret")
                || lower.contains("client")
                || lower.contains("license")
                || lower.contains("webhook")
                || lower.contains("bearer")
                || lower.contains("oauth")
                || lower.contains("signing")
                || lower.contains("private")
                || lower.contains("stripe")
                || lower.contains("mailgun")
                || lower.contains("sendgrid")
                || lower.contains("recaptcha")
                || lower.contains("google")
                || lower.contains("twilio")
                || lower.contains("algolia")
                || lower.contains("sentry")
                || lower.contains("redis")
                || lower.contains("amplitude")
                || lower.contains("segment")
                || lower.contains("slack")
                || lower.contains("github")
                || lower.contains("gitlab")
                || lower.contains("azure")
                || lower.contains("aws")
                || lower.contains("jwt")
                || lower.contains("api")
            {
                let env_key = normalize_env_name(&config_key);
                let final_key = if env_key == "DB_PASSWORD" || env_key == "DRUPAL_HASH_SALT" {
                    env_key
                } else {
                    format!("{}__{}", subsite_prefix, env_key)
                };
                secrets.entry(final_key).or_insert(value);
            }
        }
    }

    let mut items: Vec<_> = secrets
        .into_iter()
        .map(|(key, value)| ParsedSecret { key, value })
        .collect();
    items.sort_by(|a, b| a.key.cmp(&b.key));
    items
}

fn extract_php_assignment(line: &str) -> Option<(String, String)> {
    if line.contains("getenv(") {
        return None;
    }
    let bytes = line.as_bytes();
    let mut quoted_segments = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        if ch == '\'' || ch == '"' {
            let quote = ch;
            let start = index + 1;
            index += 1;
            while index < bytes.len() && bytes[index] as char != quote {
                index += 1;
            }
            if index < bytes.len() {
                quoted_segments.push(line[start..index].to_string());
            }
        }
        index += 1;
    }
    if quoted_segments.len() < 2 {
        return None;
    }

    let config_key = quoted_segments.first()?.clone();
    let value = quoted_segments.last()?.clone();
    Some((config_key, value))
}

fn extract_quoted_value(line: &str) -> Option<String> {
    extract_php_assignment(line).map(|(_, value)| value)
}

fn normalize_env_name(value: &str) -> String {
    let mut out = String::new();
    let mut last_underscore = false;
    for ch in value.chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_uppercase()
        } else {
            '_'
        };
        if mapped == '_' {
            if !last_underscore {
                out.push(mapped);
            }
            last_underscore = true;
        } else {
            out.push(mapped);
            last_underscore = false;
        }
    }
    out.trim_matches('_').to_string()
}

fn import_kind_name(kind: &ImportKind) -> &'static str {
    match kind {
        ImportKind::Env => "env",
        ImportKind::Php => "php",
    }
}

fn validate_password(password: &str) -> Result<(), String> {
    let vaults = collect_vault_paths(&vault_dir()?)?;
    if let Some(first_vault) = vaults.first() {
        decrypt_vault(first_vault, password).map(|_| ())
    } else {
        Ok(())
    }
}

fn validate_key(key: &str) -> Result<(), String> {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return Err("Secret key is required.".to_string());
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err("Key must match [A-Za-z_][A-Za-z0-9_]*".to_string());
    }
    if chars.any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_')) {
        return Err("Key must match [A-Za-z_][A-Za-z0-9_]*".to_string());
    }
    Ok(())
}

fn validate_project_name(project: &str) -> Result<(), String> {
    if project.is_empty() || project.contains('/') || project.contains('\0') {
        return Err("Project name is invalid.".to_string());
    }
    Ok(())
}

fn vault_path(project: &str) -> Result<PathBuf, String> {
    let trimmed = project.trim();
    validate_project_name(trimmed)?;
    Ok(vault_dir()?.join(format!("{trimmed}.vault")))
}

fn get_password(state: &tauri::State<'_, AppState>) -> Result<String, String> {
    state
        .unlocked_password
        .lock()
        .map_err(|_| "Failed to read app state".to_string())?
        .clone()
        .ok_or_else(|| "Unlock the vault manager first.".to_string())
}

fn to_vault_details(vault_path: &Path, data: &Value) -> VaultDetails {
    let project = data
        .get("project")
        .and_then(Value::as_str)
        .or_else(|| vault_path.file_stem().and_then(|stem| stem.to_str()))
        .unwrap_or("unknown")
        .to_string();

    let metadata = data
        .get("metadata")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let project_path = metadata
        .get("vault")
        .and_then(Value::as_object)
        .and_then(|obj| obj.get("project_path"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut secrets = Vec::new();

    if let Some(secret_map) = data.get("secrets").and_then(Value::as_object) {
        let mut keys: Vec<_> = secret_map.keys().cloned().collect();
        keys.sort();
        for key in keys {
            let value = secret_map
                .get(&key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let meta = metadata.get(&key).and_then(Value::as_object);
            secrets.push(SecretEntry {
                key,
                value,
                imported_from: meta.and_then(|obj| string_field(obj, "imported_from")),
                imported_at: meta.and_then(|obj| string_field(obj, "imported_at")),
                updated_at: meta.and_then(|obj| string_field(obj, "updated_at")),
            });
        }
    }

    VaultDetails {
        project,
        path: vault_path.display().to_string(),
        project_path,
        created: data
            .get("created")
            .and_then(Value::as_str)
            .map(str::to_string),
        updated: data
            .get("updated")
            .and_then(Value::as_str)
            .map(str::to_string),
        secret_count: secrets.len(),
        secrets,
    }
}

fn string_field(obj: &Map<String, Value>, key: &str) -> Option<String> {
    obj.get(key).and_then(Value::as_str).map(str::to_string)
}

fn ensure_vault_metadata<'a>(data: &'a mut Value) -> Result<&'a mut Map<String, Value>, String> {
    let metadata = ensure_object(data, "metadata")?;
    let vault = metadata
        .entry("vault".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    vault
        .as_object_mut()
        .ok_or_else(|| "Vault metadata is invalid.".to_string())
}

fn ensure_object<'a>(data: &'a mut Value, key: &str) -> Result<&'a mut Map<String, Value>, String> {
    if !data[key].is_object() {
        data[key] = Value::Object(Map::new());
    }
    data[key]
        .as_object_mut()
        .ok_or_else(|| format!("Vault field '{key}' is invalid."))
}

fn decrypt_vault(vault_path: &Path, password: &str) -> Result<Value, String> {
    if !vault_path.exists() {
        return Err(format!("Vault not found: {}", vault_path.display()));
    }

    let output = Command::new("openssl")
        .args([
            "enc",
            "-d",
            "-aes-256-cbc",
            "-pbkdf2",
            "-iter",
            "100000",
            "-in",
        ])
        .arg(vault_path)
        .arg("-pass")
        .arg(format!("pass:{password}"))
        .output()
        .map_err(|err| format!("Failed to run openssl: {err}"))?;

    if !output.status.success() {
        return Err("Decryption failed. Check the master password.".to_string());
    }

    serde_json::from_slice(&output.stdout).map_err(|err| format!("Vault JSON is invalid: {err}"))
}

fn encrypt_vault(vault_path: &Path, password: &str, data: &Value) -> Result<(), String> {
    let plaintext = serde_json::to_vec_pretty(data)
        .map_err(|err| format!("Failed to serialize vault: {err}"))?;
    let output = Command::new("openssl")
        .args([
            "enc",
            "-aes-256-cbc",
            "-pbkdf2",
            "-iter",
            "100000",
            "-salt",
            "-out",
        ])
        .arg(vault_path)
        .arg("-pass")
        .arg(format!("pass:{password}"))
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;

            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(&plaintext)?;
            }
            child.wait_with_output()
        })
        .map_err(|err| format!("Failed to run openssl: {err}"))?;

    if !output.status.success() {
        return Err("Encryption failed.".to_string());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(vault_path, fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("Failed to set file permissions: {err}"))?;
    }

    Ok(())
}

fn iso_now() -> String {
    let output = Command::new("date")
        .arg("-u")
        .arg("+%Y-%m-%dT%H:%M:%SZ")
        .output();

    match output {
        Ok(result) if result.status.success() => {
            String::from_utf8_lossy(&result.stdout).trim().to_string()
        }
        _ => "1970-01-01T00:00:00Z".to_string(),
    }
}

fn system_time_to_iso(time: SystemTime) -> Option<String> {
    let duration = time.duration_since(UNIX_EPOCH).ok()?;
    let secs = duration.as_secs();
    let output = Command::new("date")
        .arg("-u")
        .arg("-r")
        .arg(secs.to_string())
        .arg("+%Y-%m-%dT%H:%M:%SZ")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn strip_secret_block(content: &str) -> String {
    let mut result = Vec::new();
    let mut skipping = false;

    for line in content.lines() {
        if line.trim() == MARKER_START {
            skipping = true;
            continue;
        }
        if line.trim() == MARKER_END {
            skipping = false;
            continue;
        }
        if !skipping {
            result.push(line);
        }
    }

    result.join("\n")
}

fn format_env_assignment(key: &str, value: &str) -> String {
    format!("{}=\"{}\"", key, value.replace('"', "\\\""))
}

fn collect_env_candidates(root: &Path, out: &mut Vec<ImportCandidate>) {
    for name in [
        ".env",
        ".env.local",
        ".env.dev",
        ".env.development",
        ".env.ddev",
        ".env.secrets",
        "secrets.env",
    ] {
        let path = root.join(name);
        if path.is_file() {
            out.push(ImportCandidate {
                path: path.display().to_string(),
                kind: "env".to_string(),
                label: name.to_string(),
            });
        }
    }
}

fn derive_env_key_from_label(label: &str) -> Option<String> {
    let normalized = normalize_env_name(label);
    if normalized.is_empty() {
        return None;
    }
    if normalized.contains("PASSWORD")
        || normalized.contains("TOKEN")
        || normalized.contains("SECRET")
        || normalized.contains("KEY")
        || normalized.contains("WEBHOOK")
        || normalized.contains("JWT")
        || normalized.contains("LICENSE")
        || normalized.contains("CREDENTIAL")
        || normalized.contains("PRIVATE")
        || normalized.contains("CLIENT")
    {
        Some(normalized)
    } else {
        None
    }
}

fn mask_value(value: &str) -> String {
    if value.is_empty() {
        return "(empty)".to_string();
    }
    if value.len() <= 4 {
        return value.to_string();
    }
    format!(
        "{}{}{}",
        &value[..2],
        "*".repeat(value.len().saturating_sub(4)),
        &value[value.len() - 2..]
    )
}

fn clean_env_content(original: &str) -> (String, String) {
    let mut cleaned_lines = Vec::new();

    for line in original.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            cleaned_lines.push(line.to_string());
            continue;
        }

        let Some((key, raw_value)) = line.split_once('=') else {
            cleaned_lines.push(line.to_string());
            continue;
        };
        let key = key.trim();
        let value = raw_value.trim();
        if validate_key(key).is_err()
            || value.is_empty()
            || value.starts_with("${")
            || value.starts_with('#')
        {
            cleaned_lines.push(line.to_string());
            continue;
        }

        cleaned_lines.push(format!("# {} - managed by secret-vault", key));
        cleaned_lines.push(format!(r#"{}="${{{}}}""#, key, key));
    }

    let cleaned = format!("{}\n", cleaned_lines.join("\n"));
    let diff = simple_diff(original, &cleaned);
    (cleaned, diff)
}

fn clean_php_content(original: &str, secrets: &[ParsedSecret]) -> (String, String) {
    let mut cleaned = original.to_string();

    for secret in secrets {
        let replacement = format!("getenv('{}')", secret.key);
        let quoted_single = format!("'{}'", secret.value);
        let quoted_double = format!("\"{}\"", secret.value);
        cleaned = cleaned.replace(&quoted_single, &replacement);
        cleaned = cleaned.replace(&quoted_double, &replacement);
    }

    let diff = simple_diff(original, &cleaned);
    (cleaned, diff)
}

fn simple_diff(original: &str, cleaned: &str) -> String {
    let orig_lines: Vec<_> = original.lines().collect();
    let clean_lines: Vec<_> = cleaned.lines().collect();
    let max_len = orig_lines.len().max(clean_lines.len());
    let mut out = vec!["--- original".to_string(), "+++ cleaned".to_string()];

    for index in 0..max_len {
        match (orig_lines.get(index), clean_lines.get(index)) {
            (Some(left), Some(right)) if left == right => out.push(format!(" {}", left)),
            (Some(left), Some(right)) => {
                out.push(format!("-{}", left));
                out.push(format!("+{}", right));
            }
            (Some(left), None) => out.push(format!("-{}", left)),
            (None, Some(right)) => out.push(format!("+{}", right)),
            (None, None) => {}
        }
    }

    out.join("\n")
}

fn json_object<const N: usize>(entries: [(&str, Value); N]) -> Value {
    let mut obj = Map::new();
    for (key, value) in entries {
        obj.insert(key.to_string(), value);
    }
    Value::Object(obj)
}

fn keychain_available() -> bool {
    if cfg!(target_os = "macos") {
        return Command::new("security").arg("-h").output().is_ok();
    }

    // On Linux: secret-tool OR file-based fallback (always available)
    true
}

fn secret_tool_available() -> bool {
    Command::new("secret-tool").arg("--help").output().is_ok()
}

// ---------------------------------------------------------------------------
// File-based fallback for Linux systems without libsecret/secret-tool.
// Encrypts master password using a key derived from machine-id.
// ---------------------------------------------------------------------------

fn keyfile_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config"))
        .join("ddev-secret-vault")
}

fn keyfile_path() -> PathBuf {
    keyfile_dir().join("keyfile")
}

fn get_machine_key() -> String {
    let machine_id = std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .unwrap_or_else(|_| {
            format!(
                "{}-{}",
                hostname::get()
                    .map(|h| h.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "unknown".to_string()),
                unsafe { libc::getuid() }
            )
        })
        .trim()
        .to_string();

    // Derive key using openssl (same as shell version)
    let output = Command::new("openssl")
        .args(["dgst", "-sha256", "-binary"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(format!("ddev-secret-vault:{}", machine_id).as_bytes())
                .ok();
            child.wait_with_output()
        })
        .map(|o| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&o.stdout)
        })
        .unwrap_or_default();

    output
}

fn keyfile_load() -> Option<String> {
    let path = keyfile_path();
    if !path.exists() {
        return None;
    }
    let key = get_machine_key();
    let output = Command::new("openssl")
        .args([
            "enc",
            "-d",
            "-aes-256-cbc",
            "-pbkdf2",
            "-iter",
            "10000",
            "-in",
        ])
        .arg(&path)
        .arg("-pass")
        .arg(format!("pass:{}", key))
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let password = String::from_utf8_lossy(&output.stdout).to_string();
    if password.is_empty() {
        None
    } else {
        Some(password)
    }
}

fn keyfile_save(password: &str) -> Result<(), String> {
    let dir = keyfile_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create keyfile dir: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).ok();
    }
    let path = keyfile_path();
    let key = get_machine_key();

    let mut child = Command::new("openssl")
        .args([
            "enc",
            "-aes-256-cbc",
            "-pbkdf2",
            "-iter",
            "10000",
            "-salt",
            "-out",
        ])
        .arg(&path)
        .arg("-pass")
        .arg(format!("pass:{}", key))
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to encrypt keyfile: {e}"))?;
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .ok_or_else(|| "Failed to write to openssl stdin".to_string())?
            .write_all(password.as_bytes())
            .map_err(|e| format!("Failed to write password: {e}"))?;
    }
    let status = child
        .wait()
        .map_err(|e| format!("Failed to finish openssl: {e}"))?;
    if !status.success() {
        return Err("openssl encryption failed".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).ok();
    }
    Ok(())
}

#[allow(dead_code)]
fn keyfile_delete() {
    let _ = fs::remove_file(keyfile_path());
}

fn load_password_from_keychain() -> Option<String> {
    if cfg!(target_os = "macos") {
        let output = Command::new("security")
            .args([
                "find-generic-password",
                "-a",
                KEYCHAIN_ACCOUNT,
                "-s",
                KEYCHAIN_SERVICE,
                "-w",
            ])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return if password.is_empty() {
            None
        } else {
            Some(password)
        };
    }

    if !secret_tool_available() {
        return keyfile_load();
    }

    let output = match Command::new("secret-tool")
        .args([
            "lookup",
            "application",
            KEYCHAIN_SERVICE,
            "account",
            KEYCHAIN_ACCOUNT,
        ])
        .output()
    {
        Ok(o) => o,
        Err(_) => return keyfile_load(),
    };
    if !output.status.success() {
        // Fall back to file-based storage
        return keyfile_load();
    }
    let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if password.is_empty() {
        keyfile_load()
    } else {
        Some(password)
    }
}

fn save_password_to_keychain(password: &str) -> Result<(), String> {
    let status = if cfg!(target_os = "macos") {
        Command::new("security")
            .args([
                "add-generic-password",
                "-a",
                KEYCHAIN_ACCOUNT,
                "-s",
                KEYCHAIN_SERVICE,
                "-w",
                password,
                "-U",
            ])
            .status()
            .map_err(|err| format!("Failed to update macOS Keychain: {err}"))?
    } else if secret_tool_available() {
        let mut child = Command::new("secret-tool")
            .args([
                "store",
                "--label=DDEV Secret Vault (master)",
                "application",
                KEYCHAIN_SERVICE,
                "account",
                KEYCHAIN_ACCOUNT,
            ])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|err| format!("Failed to update libsecret: {err}"))?;
        {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .ok_or_else(|| "Failed to write to libsecret.".to_string())?
                .write_all(password.as_bytes())
                .map_err(|err| format!("Failed to write to libsecret: {err}"))?;
        }
        child
            .wait()
            .map_err(|err| format!("Failed to finish libsecret command: {err}"))?
    } else {
        // File-based fallback
        return keyfile_save(password);
    };

    if status.success() {
        Ok(())
    } else {
        Err("Failed to save password to the OS keychain.".to_string())
    }
}

fn read_initial_project() -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if let Some(project) = arg.strip_prefix("--project=") {
            return Some(project.to_string());
        }
        if arg == "--project" {
            return args.next();
        }
    }
    None
}

fn apply_cli_context(app: &AppHandle) {
    if let Some(project) = read_initial_project() {
        if let Some(state) = app.try_state::<AppState>() {
            if let Ok(mut guard) = state.initial_project.lock() {
                *guard = Some(project);
            }
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::default())
        .setup(|app| {
            apply_cli_context(app.handle());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            bootstrap,
            unlock,
            use_stored_password,
            lock_app,
            list_vaults,
            create_vault,
            delete_vault,
            get_vault,
            save_secret,
            delete_secret,
            export_env,
            inject_project_env,
            save_project_path,
            clean_project_env,
            change_master_password,
            find_import_candidates,
            preview_import,
            preview_clean_import_source,
            apply_import,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
