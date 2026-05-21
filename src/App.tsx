import { FormEvent, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ask } from "@tauri-apps/plugin-dialog";
import { Menu } from '@tauri-apps/api/menu';
import appIcon from "./assets/icon.png";
import "./App.css";

type VaultSummary = {
  project: string;
  path: string;
  modifiedAt?: string | null;
};

type BootstrapData = {
  vaultDir: string;
  keychainAvailable: boolean;
  storedPasswordAvailable: boolean;
  unlocked: boolean;
  initialProject?: string | null;
  vaults: VaultSummary[];
};

type SecretEntry = {
  key: string;
  value: string;
  importedFrom?: string | null;
  importedAt?: string | null;
  updatedAt?: string | null;
};

type VaultDetails = {
  project: string;
  path: string;
  projectPath?: string | null;
  created?: string | null;
  updated?: string | null;
  secretCount: number;
  secrets: SecretEntry[];
};

type ImportCandidate = {
  path: string;
  kind: string;
  label: string;
};

type ImportPreview = {
  path: string;
  kind: string;
  secretCount: number;
  secrets: Array<{
    key: string;
    valuePreview: string;
  }>;
};

type CleanPreview = {
  backupPath: string;
  diff: string;
  cleanedContent: string;
};

type ImportResult = {
  vault: VaultDetails;
  importedCount: number;
  cleaned: boolean;
  cleanedFile?: string | null;
  backupPath?: string | null;
};

type InjectionStatus = {
  envPath: string;
  injectedCount: number;
};

type CleanStatus = {
  envPath: string;
  removed: boolean;
};

const INITIAL_BOOTSTRAP: BootstrapData = {
  vaultDir: "",
  keychainAvailable: false,
  storedPasswordAvailable: false,
  unlocked: false,
  initialProject: null,
  vaults: [],
};

function App() {
  const [bootstrap, setBootstrap] = useState(INITIAL_BOOTSTRAP);
  const [selectedProject, setSelectedProject] = useState("");
  const [vault, setVault] = useState<VaultDetails | null>(null);
  const [search, setSearch] = useState("");
  const [vaultSearch, setVaultSearch] = useState("");
  const [showValues, setShowValues] = useState(false);
  const [unlockPassword, setUnlockPassword] = useState("");
  const [saveToKeychain, setSaveToKeychain] = useState(true);
  const [createProject, setCreateProject] = useState("");
  const [projectPath, setProjectPath] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [saveNewPassword, setSaveNewPassword] = useState(true);
  const [showRotatePassword, setShowRotatePassword] = useState(false);
  const [editingKey, setEditingKey] = useState("");
  const [editingValue, setEditingValue] = useState("");
  const [isEditing, setIsEditing] = useState(false);
  const [busyLabel, setBusyLabel] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [importCandidates, setImportCandidates] = useState<ImportCandidate[]>([]);
  const [selectedImportPath, setSelectedImportPath] = useState("");
  const [importPreview, setImportPreview] = useState<ImportPreview | null>(null);
  const [cleanPreview, setCleanPreview] = useState<CleanPreview | null>(null);
  const [cleanOnImport, setCleanOnImport] = useState(false);

  useEffect(() => {
    void loadBootstrap();
  }, []);

  useEffect(() => {
    if (!notice) {
      return;
    }

    const timeout = window.setTimeout(() => setNotice(""), 4500);
    return () => window.clearTimeout(timeout);
  }, [notice]);

  useEffect(() => {
    if (!error) {
      return;
    }

    const timeout = window.setTimeout(() => setError(""), 6000);
    return () => window.clearTimeout(timeout);
  }, [error]);

  useEffect(() => {
    if (!bootstrap.unlocked || !selectedProject) {
      setVault(null);
      return;
    }
    void loadVault(selectedProject);

    const interval = setInterval(async () => {
      try {
        const data = await invoke<VaultDetails>("get_vault", { project: selectedProject });
        setVault((current) => {
          if (JSON.stringify(current) === JSON.stringify(data)) return current;
          return data;
        });
      } catch (err) {
        // Silently ignore background polling errors
      }
    }, 2000);
    return () => clearInterval(interval);
  }, [bootstrap.unlocked, selectedProject]);

  useEffect(() => {
    if (vault?.projectPath) {
      setProjectPath(vault.projectPath);
    }
  }, [vault?.projectPath]);

  const visibleSecrets = useMemo(() => {
    const secrets = vault?.secrets ?? [];
    const query = search.trim().toLowerCase();
    if (!query) {
      return secrets;
    }

    return secrets.filter((secret) => {
      return (
        secret.key.toLowerCase().includes(query) ||
        (secret.importedFrom ?? "").toLowerCase().includes(query)
      );
    });
  }, [search, vault]);

  const visibleVaults = useMemo(() => {
    const query = vaultSearch.trim().toLowerCase();
    if (!query) {
      return bootstrap.vaults;
    }
    return bootstrap.vaults.filter((v) => v.project.toLowerCase().includes(query));
  }, [vaultSearch, bootstrap.vaults]);

  async function loadBootstrap() {
    try {
      const data = await invoke<BootstrapData>("bootstrap");
      setBootstrap(data);
      setSelectedProject((current) => {
        if (current && data.vaults.some((vaultSummary) => vaultSummary.project === current)) {
          return current;
        }
        if (
          data.initialProject &&
          data.vaults.some((vaultSummary) => vaultSummary.project === data.initialProject)
        ) {
          return data.initialProject;
        }
        return data.vaults[0]?.project ?? "";
      });
    } catch (err) {
      setError(asMessage(err));
    }
  }

  async function loadVault(project: string) {
    try {
      const data = await invoke<VaultDetails>("get_vault", { project });
      setVault(data);
      setError("");
    } catch (err) {
      setError(asMessage(err));
    }
  }

  async function withBusy<T>(label: string, fn: () => Promise<T>) {
    setBusyLabel(label);
    setError("");
    try {
      return await fn();
    } finally {
      setBusyLabel("");
    }
  }

  async function handleUnlock(event: FormEvent) {
    event.preventDefault();
    await withBusy("Unlocking vault manager", async () => {
      await invoke("unlock", {
        payload: {
          password: unlockPassword,
          saveToKeychain,
        },
      });
      setUnlockPassword("");
      setNotice("Vault manager unlocked.");
      await loadBootstrap();
    }).catch((err) => setError(asMessage(err)));
  }

  async function handleUseStoredPassword() {
    await withBusy("Loading saved password", async () => {
      await invoke("use_stored_password");
      setNotice("Unlocked with the saved OS keychain password.");
      await loadBootstrap();
    }).catch((err) => setError(asMessage(err)));
  }

  async function handleCreateVault(event: FormEvent) {
    event.preventDefault();
    await withBusy("Creating vault", async () => {
      const created = await invoke<VaultDetails>("create_vault", {
        payload: { project: createProject },
      });
      setCreateProject("");
      setSelectedProject(created.project);
      setVault(created);
      setNotice(`Created vault for ${created.project}.`);
      await loadBootstrap();
    }).catch((err) => setError(asMessage(err)));
  }

  async function handleDeleteVault() {
    if (!selectedProject) return;
    
    const confirmed = await ask(`Delete vault ${selectedProject}? This removes the encrypted vault file.`, {
      title: 'Secret Vault',
      kind: 'warning',
    });
    
    if (!confirmed) {
      return;
    }

    await withBusy("Deleting vault", async () => {
      await invoke("delete_vault", {
        payload: { project: selectedProject },
      });
      setVault(null);
      setSelectedProject("");
      setProjectPath("");
      setNotice(`Deleted vault ${selectedProject}.`);
      await loadBootstrap();
    }).catch((err) => setError(asMessage(err)));
  }

  async function handleSaveSecret(event: FormEvent) {
    event.preventDefault();
    if (!selectedProject) {
      return;
    }

    await withBusy("Saving secret", async () => {
      const updated = await invoke<VaultDetails>("save_secret", {
        payload: {
          project: selectedProject,
          key: editingKey,
          value: editingValue,
        },
      });
      setVault(updated);
      setEditingKey("");
      setEditingValue("");
      setIsEditing(false);
      setNotice(`Saved ${editingKey}.`);
    }).catch((err) => setError(asMessage(err)));
  }

  async function handleDeleteSecret(key: string) {
    if (!selectedProject) return;
    
    const confirmed = await ask(`Delete ${key}?`, {
      title: 'Secret Vault',
      kind: 'warning',
    });
    
    if (!confirmed) {
      return;
    }

    await withBusy("Deleting secret", async () => {
      const updated = await invoke<VaultDetails>("delete_secret", {
        payload: {
          project: selectedProject,
          key,
        },
      });
      setVault(updated);
      setNotice(`Deleted ${key}.`);
    }).catch((err) => setError(asMessage(err)));
  }

  async function handleExportEnv() {
    if (!selectedProject) {
      return;
    }

    await withBusy("Preparing export", async () => {
      const exported = await invoke<string>("export_env", {
        payload: { project: selectedProject },
      });
      await navigator.clipboard.writeText(exported);
      setNotice("Copied .env export to the clipboard.");
    }).catch((err) => setError(asMessage(err)));
  }

  async function handleInject() {
    if (!selectedProject || !projectPath.trim()) {
      setError("Enter a DDEV project path first.");
      return;
    }

    await withBusy("Injecting secrets", async () => {
      const status = await invoke<InjectionStatus>("inject_project_env", {
        payload: {
          project: selectedProject,
          projectPath,
        },
      });
      setNotice(`Injected ${status.injectedCount} secret(s) into ${status.envPath}.`);
    }).catch((err) => setError(asMessage(err)));
  }

  async function handleClean() {
    if (!selectedProject || !projectPath.trim()) {
      setError("Enter a DDEV project path first.");
      return;
    }

    await withBusy("Cleaning .ddev/.env", async () => {
      const status = await invoke<CleanStatus>("clean_project_env", {
        payload: {
          project: selectedProject,
          projectPath,
        },
      });
      setNotice(
        status.removed
          ? `Removed injected secrets from ${status.envPath}.`
          : `Nothing to clean at ${status.envPath}.`,
      );
    }).catch((err) => setError(asMessage(err)));
  }

  async function handleSaveProjectPath() {
    if (!selectedProject) {
      return;
    }

    await withBusy("Saving project path", async () => {
      const updated = await invoke<VaultDetails>("save_project_path", {
        payload: {
          project: selectedProject,
          projectPath,
        },
      });
      setVault(updated);
      setNotice(projectPath.trim() ? "Saved DDEV project path to vault." : "Cleared saved DDEV project path.");
    }).catch((err) => setError(asMessage(err)));
  }

  async function handleChangePassword(event: FormEvent) {
    event.preventDefault();
    await withBusy("Changing master password", async () => {
      await invoke("change_master_password", {
        payload: {
          currentPassword,
          newPassword,
          saveToKeychain: saveNewPassword,
        },
      });
      setCurrentPassword("");
      setNewPassword("");
      setNotice("Re-encrypted all vaults with the new password.");
      await loadBootstrap();
      if (selectedProject) {
        await loadVault(selectedProject);
      }
    }).catch((err) => setError(asMessage(err)));
  }

  async function handleLock() {
    await withBusy("Locking app", async () => {
      await invoke("lock_app");
      setVault(null);
      setBootstrap((current) => ({ ...current, unlocked: false }));
      setNotice("Vault manager locked.");
    }).catch((err) => setError(asMessage(err)));
  }

  async function handleFindImportCandidates() {
    if (!projectPath.trim()) {
      setError("Enter a DDEV project path first.");
      return;
    }

    await withBusy("Scanning project files", async () => {
      const found = await invoke<ImportCandidate[]>("find_import_candidates", {
        projectPath,
      });
      setImportCandidates(found);
      const first = found[0]?.path ?? "";
      setSelectedImportPath(first);
      setImportPreview(null);
      setCleanPreview(null);
      setNotice(found.length ? `Found ${found.length} import candidate(s).` : "No import candidates found.");
    }).catch((err) => setError(asMessage(err)));
  }

  async function handlePreviewImport() {
    if (!selectedImportPath) {
      setError("Select an import source first.");
      return;
    }

    await withBusy("Previewing import", async () => {
      const preview = await invoke<ImportPreview>("preview_import", {
        payload: { path: selectedImportPath },
      });
      setImportPreview(preview);
      if (cleanOnImport) {
        const clean = await invoke<CleanPreview>("preview_clean_import_source", {
          payload: { path: selectedImportPath },
        });
        setCleanPreview(clean);
      } else {
        setCleanPreview(null);
      }
    }).catch((err) => setError(asMessage(err)));
  }

  async function handleApplyImport() {
    if (!selectedProject || !selectedImportPath) {
      setError("Select a vault and import source first.");
      return;
    }

    await withBusy("Importing secrets", async () => {
      const result = await invoke<ImportResult>("apply_import", {
        payload: {
          project: selectedProject,
          path: selectedImportPath,
          clean: cleanOnImport,
        },
      });
      setVault(result.vault);
      setNotice(
        result.cleaned
          ? `Imported ${result.importedCount} secret(s) and cleaned ${result.cleanedFile}.`
          : `Imported ${result.importedCount} secret(s).`,
      );
      await loadBootstrap();
      if (cleanOnImport) {
        setCleanPreview(null);
      }
    }).catch((err) => setError(asMessage(err)));
  }

  async function handleVaultContextMenu(event: React.MouseEvent, vaultSummary: VaultSummary) {
    event.preventDefault();
    try {
      const menu = await Menu.new({
        items: [
          {
            id: 'open',
            text: 'Open Vault',
            action: () => setSelectedProject(vaultSummary.project)
          },
          {
            id: 'copy-path',
            text: 'Copy File Path',
            action: async () => {
              await navigator.clipboard.writeText(vaultSummary.path);
              setNotice(`Copied path for ${vaultSummary.project}`);
            }
          },
          {
            item: 'Separator'
          },
          {
            id: 'delete',
            text: 'Delete Vault',
            action: async () => {
              const confirmed = await ask(`Delete vault ${vaultSummary.project}? This removes the encrypted vault file.`, {
                title: 'Secret Vault',
                kind: 'warning',
              });
              if (!confirmed) return;
              await withBusy("Deleting vault", async () => {
                await invoke("delete_vault", {
                  payload: { project: vaultSummary.project },
                });
                if (selectedProject === vaultSummary.project) {
                  setVault(null);
                  setSelectedProject("");
                  setProjectPath("");
                }
                setNotice(`Deleted vault ${vaultSummary.project}.`);
                await loadBootstrap();
              }).catch((err) => setError(asMessage(err)));
            }
          }
        ]
      });
      await menu.popup();
    } catch (err) {
      console.error("Failed to show context menu", err);
    }
  }

  async function handleSecretContextMenu(event: React.MouseEvent, secret: SecretEntry) {
    event.preventDefault();
    try {
      const menu = await Menu.new({
        items: [
          {
            id: 'copy-key',
            text: 'Copy Key',
            action: async () => {
              await navigator.clipboard.writeText(secret.key);
              setNotice(`Copied key: ${secret.key}`);
            }
          },
          {
            id: 'copy-value',
            text: 'Copy Value',
            action: async () => {
              await navigator.clipboard.writeText(secret.value);
              setNotice(`Copied value for: ${secret.key}`);
            }
          },
          {
            item: 'Separator'
          },
          {
            id: 'edit',
            text: 'Edit',
            action: () => beginEdit(secret)
          },
          {
            id: 'delete',
            text: 'Delete',
            action: () => handleDeleteSecret(secret.key)
          }
        ]
      });
      await menu.popup();
    } catch (err) {
      console.error("Failed to show context menu", err);
    }
  }

  function beginEdit(secret?: SecretEntry) {
    setIsEditing(Boolean(secret));
    setEditingKey(secret?.key ?? "");
    setEditingValue(secret?.value ?? "");
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <img src={appIcon} alt="Secret Vault" className="brand-mark-img" />
          <div>
            <p className="eyebrow">Native Vault Studio</p>
            <h1>Secret Vault</h1>
          </div>
        </div>

        <section className={`panel glass-panel ${bootstrap.unlocked ? 'compact-panel' : ''}`}>
          <div>
            {!bootstrap.unlocked && <p className="eyebrow">Shared Master Password</p>}
            <h2 style={bootstrap.unlocked ? { fontSize: '1.05rem', display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' } : { marginBottom: '0.8rem' }}>
              {bootstrap.unlocked ? (
                <>
                  <span style={{ fontSize: '1.2rem' }}>🔓</span> Vault manager unlocked
                </>
              ) : (
                "Unlock your vaults"
              )}
            </h2>
            {!bootstrap.unlocked && (
              <p className="muted" style={{ marginBottom: '1rem' }}>
                Same vault format, same keychain entry, much better desktop flow.
              </p>
            )}
          </div>

          {bootstrap.unlocked ? (
            <div className="inline-actions">
              <button className="ghost subtle" onClick={handleLock} type="button">
                Lock app
              </button>
            </div>
          ) : (
            <form className="unlock-form stack" onSubmit={handleUnlock}>
              <input
                type="password"
                value={unlockPassword}
                onChange={(event) => setUnlockPassword(event.currentTarget.value)}
                placeholder="Master vault password"
              />
              <label className="checkbox-row">
                <input
                  checked={saveToKeychain}
                  onChange={(event) => setSaveToKeychain(event.currentTarget.checked)}
                  type="checkbox"
                />
                Save to OS keychain
              </label>
              <div className="inline-actions">
                <button disabled={!unlockPassword} type="submit">
                  Unlock
                </button>
                {bootstrap.storedPasswordAvailable ? (
                  <button className="ghost" onClick={handleUseStoredPassword} type="button">
                    Use saved password
                  </button>
                ) : null}
              </div>
            </form>
          )}
        </section>

        <section className="panel compact-panel glass-panel">
          <div className="section-heading">
            <h2>Vaults</h2>
            {bootstrap.unlocked && <span className="badge">{bootstrap.vaults.length}</span>}
          </div>
          <div className="vault-list">
            {!bootstrap.unlocked ? (
              <p className="empty-copy">Unlock to view vaults.</p>
            ) : (
              <>
                <input
                  className="subtle-input"
                  value={vaultSearch}
                  onChange={(event) => setVaultSearch(event.currentTarget.value)}
                  placeholder="Filter vaults"
                />
                {visibleVaults.length === 0 ? <p className="empty-copy">No vaults found.</p> : null}
                {visibleVaults.map((vaultSummary) => (
                  <button
                    key={vaultSummary.project}
                    className={selectedProject === vaultSummary.project ? "vault-item active" : "vault-item"}
                    onClick={() => setSelectedProject(vaultSummary.project)}
                    onContextMenu={(e) => handleVaultContextMenu(e, vaultSummary)}
                    type="button"
                  >
                    <strong>{vaultSummary.project}</strong>
                    <span>{formatDate(vaultSummary.modifiedAt)}</span>
                  </button>
                ))}
              </>
            )}
          </div>
        </section>

        {bootstrap.unlocked && (
          <section className="panel compact-panel glass-panel">
            <div className="section-heading">
              <h2>Create Vault</h2>
            </div>
            <form className="stack" onSubmit={handleCreateVault}>
              <input
                value={createProject}
                onChange={(event) => setCreateProject(event.currentTarget.value)}
                placeholder="my-drupal-site"
              />
              <button disabled={!createProject.trim()} type="submit">
                Create vault
              </button>
            </form>
          </section>
        )}
      </aside>

      <main className="content">
        <section className="dashboard-grid">
          <section className="panel vault-panel dramatic-panel">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Selected Vault</p>
                <h2>{selectedProject || "Choose a vault"}</h2>
              </div>
              <div className="inline-actions">
                {vault ? <span className="badge">{vault.secretCount} secrets</span> : null}
                {selectedProject ? (
                  <button className="danger ghost subtle" onClick={handleDeleteVault} type="button">
                    Delete vault
                  </button>
                ) : null}
              </div>
            </div>

            {!bootstrap.unlocked ? (
              <p className="empty-copy">Unlock the app to inspect and edit secrets.</p>
            ) : !selectedProject ? (
              <p className="empty-copy">Create or select a vault from the left.</p>
            ) : !vault ? (
              <p className="empty-copy">Loading vault...</p>
            ) : (
              <>
                <div className="toolbar">
                  <input
                    value={search}
                    onChange={(event) => setSearch(event.currentTarget.value)}
                    placeholder="Filter keys or import sources"
                  />
                  <button className="ghost" onClick={() => setShowValues((value) => !value)} type="button">
                    {showValues ? "Hide values" : "Show values"}
                  </button>
                  <button className="ghost" onClick={handleExportEnv} type="button">
                    Copy .env export
                  </button>
                </div>

                <div className="vault-meta">
                  <span>Created {formatDate(vault.created)}</span>
                  <span>Updated {formatDate(vault.updated)}</span>
                </div>

                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Key</th>
                        <th>Value</th>
                        <th>Source</th>
                        <th>Updated</th>
                        <th />
                      </tr>
                    </thead>
                    <tbody>
                      {visibleSecrets.map((secret) => (
                        <tr key={secret.key} onContextMenu={(e) => handleSecretContextMenu(e, secret)}>
                          <td className="mono strong">{secret.key}</td>
                          <td className="mono">{showValues ? secret.value : mask(secret.value)}</td>
                          <td>{secret.importedFrom || "vault set"}</td>
                          <td>{formatDate(secret.updatedAt || secret.importedAt)}</td>
                          <td>
                            <div className="row-actions">
                              <button className="ghost subtle" onClick={() => beginEdit(secret)} type="button">
                                Edit
                              </button>
                              <button className="danger ghost subtle" onClick={() => handleDeleteSecret(secret.key)} type="button">
                                Delete
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {visibleSecrets.length === 0 ? <p className="empty-copy">No secrets match this filter.</p> : null}
                </div>
              </>
            )}
          </section>

          <section className="column-stack">
            <section className="panel action-panel accent-panel">
              <div className="section-heading">
                <h2>{isEditing ? "Edit Secret" : "Add Secret"}</h2>
              </div>
              <form className="stack" onSubmit={handleSaveSecret}>
                <input
                  disabled={!bootstrap.unlocked || isEditing}
                  onChange={(event) => setEditingKey(event.currentTarget.value)}
                  placeholder="MY_SECRET_KEY"
                  value={editingKey}
                />
                <textarea
                  disabled={!bootstrap.unlocked}
                  onChange={(event) => setEditingValue(event.currentTarget.value)}
                  placeholder="secret value"
                  rows={4}
                  value={editingValue}
                />
                <div className="inline-actions">
                  <button disabled={!bootstrap.unlocked || !selectedProject || !editingKey} type="submit">
                    {isEditing ? "Save changes" : "Add secret"}
                  </button>
                  {isEditing ? (
                    <button
                      className="ghost"
                      onClick={() => {
                        setIsEditing(false);
                        setEditingKey("");
                        setEditingValue("");
                      }}
                      type="button"
                    >
                      Cancel edit
                    </button>
                  ) : null}
                </div>
              </form>
            </section>

            <section className="panel action-panel">
              <div className="section-heading">
                <h2>Import Project Secrets</h2>
              </div>
              <div className="stack">
                <input
                  onChange={(event) => setProjectPath(event.currentTarget.value)}
                  placeholder="/path/to/your/ddev-project"
                  value={projectPath}
                />
                <div className="inline-actions">
                  <button className="ghost" disabled={!bootstrap.unlocked || !selectedProject} onClick={handleSaveProjectPath} type="button">
                    Save vault path
                  </button>
                  <button disabled={!projectPath.trim()} onClick={handleFindImportCandidates} type="button">
                    Scan project
                  </button>
                  <button className="ghost" disabled={!selectedImportPath} onClick={handlePreviewImport} type="button">
                    Preview import
                  </button>
                </div>
                <select
                  className="select-input"
                  onChange={(event) => setSelectedImportPath(event.currentTarget.value)}
                  value={selectedImportPath}
                >
                  <option value="">Select an import source</option>
                  {importCandidates.map((candidate) => (
                    <option key={candidate.path} value={candidate.path}>
                      {candidate.label} - {candidate.path}
                    </option>
                  ))}
                </select>
                <label className="checkbox-row">
                  <input
                    checked={cleanOnImport}
                    onChange={(event) => setCleanOnImport(event.currentTarget.checked)}
                    type="checkbox"
                  />
                  Clean source file after import and create a `.bak` backup
                </label>
                {importPreview ? (
                  <div className="preview-card">
                    <p className="preview-label">
                      {importPreview.secretCount} secret(s) from {importPreview.kind}
                    </p>
                    <div className="preview-list">
                      {importPreview.secrets.map((secret) => (
                        <div className="preview-row" key={secret.key}>
                          <span className="mono strong">{secret.key}</span>
                          <span className="mono muted">{secret.valuePreview}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}
                {cleanPreview ? (
                  <div className="preview-card diff-card">
                    <p className="preview-label">Clean preview, backup at {cleanPreview.backupPath}</p>
                    <pre>{cleanPreview.diff}</pre>
                  </div>
                ) : null}
                <div className="inline-actions">
                  <button
                    disabled={!bootstrap.unlocked || !selectedProject || !selectedImportPath}
                    onClick={handleApplyImport}
                    type="button"
                  >
                    Import into vault
                  </button>
                  <button disabled={!bootstrap.unlocked || !selectedProject} onClick={handleInject} type="button">
                    Inject into .ddev/.env
                  </button>
                  <button className="ghost" disabled={!selectedProject} onClick={handleClean} type="button">
                    Clean injected block
                  </button>
                </div>
              </div>
            </section>

            <section className="panel action-panel">
              <div className="section-heading" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h2>Master Password</h2>
                {bootstrap.unlocked && (
                  <button className="ghost subtle" onClick={() => setShowRotatePassword(!showRotatePassword)} type="button">
                    {showRotatePassword ? 'Cancel Rotation' : 'Rotate Master Password'}
                  </button>
                )}
              </div>
              {showRotatePassword && (
                <form className="stack" onSubmit={handleChangePassword}>
                  <input
                    onChange={(event) => setCurrentPassword(event.currentTarget.value)}
                    placeholder="Current password"
                    type="password"
                    value={currentPassword}
                  />
                  <input
                    onChange={(event) => setNewPassword(event.currentTarget.value)}
                    placeholder="New password"
                    type="password"
                    value={newPassword}
                  />
                  <label className="checkbox-row">
                    <input
                      checked={saveNewPassword}
                      onChange={(event) => setSaveNewPassword(event.currentTarget.checked)}
                      type="checkbox"
                    />
                    Save new password to OS keychain
                  </label>
                  <button disabled={!bootstrap.unlocked || !currentPassword || !newPassword} type="submit">
                    Change password for all vaults
                  </button>
                </form>
              )}
            </section>
          </section>
        </section>
      </main>

      <div className="toast-container">
        {error ? <div className="message error toast">{error}</div> : null}
        {notice ? <div className="message success toast">{notice}</div> : null}
        {busyLabel ? <div className="message info toast">{busyLabel}...</div> : null}
      </div>
    </div>
  );
}

function mask(value: string) {
  if (!value) {
    return "(empty)";
  }
  if (value.length <= 4) {
    return "*".repeat(value.length);
  }
  return `${value.slice(0, 2)}${"*".repeat(Math.max(value.length - 4, 4))}${value.slice(-2)}`;
}

function formatDate(value?: string | null) {
  if (!value) {
    return "-";
  }
  return value.replace("T", " ").replace("Z", " UTC");
}

function asMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}

export default App;
