        let ws;
        let reconnectInterval = 5000;
        let currentUser = null;
        let userGroups = [];
        let isAdmin = false;
        let canCreate = false;
        let isCreatorGroupMember = false;
        let deleteClusterData = null;
        let editClusterData = null;
        let clusterParameters = [];
        let allClusterParameters = []; // all parameters (unfiltered, for "More details" read-only)
        let editableFields = {}; // key -> { enabled, min, max } from /api/cluster/editable
        let workerGroupFields = []; // config-driven worker-group form schema from /api/cluster/worker-group-fields

        // Initialize everything when page loads
        document.addEventListener('DOMContentLoaded', function() {
            loadUserInfo().then(() => {
                loadVersions();
                loadUserGroups();
                loadUserPermissions();
                loadClusterParameters();
                loadWorkerGroupFields();
                loadEditableFields();
                loadConfig();
                connectWebSocket();
                loadClusters();
                startAutoRefresh(); // Start periodic refresh as fallback
            });
        });

        // Clean up when page unloads
        window.addEventListener('beforeunload', function() {
            stopAutoRefresh();
            if (ws) {
                ws.close();
            }
        });

        // User info
        function loadUserInfo() {
            return fetch('/api/user', {
                credentials: 'include'
            })
                .then(response => response.json())
                .then(user => {
                    currentUser = user;
                    document.getElementById('userName').textContent = user.username;
                    userGroups = user.groups || [];
                    isAdmin = user.isAdmin || false; // Use the backend's admin determination
                    console.log('User loaded:', user.username, 'Groups:', userGroups, 'IsAdmin:', isAdmin);
                })
                .catch(error => {
                    console.error('Error loading user info:', error);
                });
        }

        // Load configuration
        function loadConfig() {
            fetch('/api/config', {
                credentials: 'include'
            })
                .then(response => response.json())
                .then(config => {
                    // Show docs link if configured
                    if (config.docsUrl) {
                        const docsLink = document.getElementById('docsLink');
                        docsLink.href = config.docsUrl;
                        docsLink.style.display = 'inline-flex';
                    }
                })
                .catch(error => {
                    console.error('Error loading config:', error);
                });
        }

        // WebSocket connection
        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = protocol + '//' + window.location.host + '/ws';

            ws = new WebSocket(wsUrl);

            ws.onopen = function() {
                console.log('WebSocket connected');
                updateConnectionStatus(true);
                reconnectInterval = 5000;
            };

            ws.onmessage = function(event) {
                try {
                    const data = JSON.parse(event.data);
                    if (data.clusters) {
                        updateClusters(data.clusters);
                        updateStats(data.clusters);
                    }
                } catch (error) {
                    console.error('Error parsing WebSocket message:', error);
                }
            };

            ws.onclose = function() {
                console.log('WebSocket disconnected');
                updateConnectionStatus(false);

                // Check if session is still valid before reconnecting
                checkSessionAndReconnect();
            };

            ws.onerror = function(error) {
                console.error('WebSocket error:', error);
                updateConnectionStatus(false);
            };
        }

        function updateConnectionStatus(connected) {
            const statusEl = document.getElementById('connectionStatus');
            if (connected) {
                statusEl.className = 'status-indicator connected';
                statusEl.innerHTML = '<span class="material-symbols-outlined">cloud_done</span><span>Connected</span>';
            } else {
                statusEl.className = 'status-indicator disconnected';
                statusEl.innerHTML = '<span class="material-symbols-outlined">cloud_off</span><span>Disconnected</span>';
            }
        }

        function checkSessionAndReconnect() {
            // Try to fetch user info to check if session is still valid
            fetch('/api/user', {
                credentials: 'include'
            })
            .then(response => {
                if (response.status === 401 || response.status === 403) {
                    // Session expired, redirect to login
                    console.log('Session expired, redirecting to login...');
                    window.location.reload();
                } else if (response.ok) {
                    // Session is valid, continue reconnecting
                    console.log('Session valid, attempting to reconnect WebSocket...');
                    setTimeout(connectWebSocket, reconnectInterval);
                    reconnectInterval = Math.min(reconnectInterval * 1.5, 30000);
                } else {
                    // Other error, try reconnecting anyway
                    setTimeout(connectWebSocket, reconnectInterval);
                    reconnectInterval = Math.min(reconnectInterval * 1.5, 30000);
                }
            })
            .catch(error => {
                console.error('Error checking session:', error);
                // Network error, try reconnecting
                setTimeout(connectWebSocket, reconnectInterval);
                reconnectInterval = Math.min(reconnectInterval * 1.5, 30000);
            });
        }

        // Auto-refresh functionality
        let refreshInterval;
        const REFRESH_INTERVAL = 30000; // 30 seconds

        function startAutoRefresh() {
            // Clear any existing interval
            if (refreshInterval) {
                clearInterval(refreshInterval);
            }

            // Set up periodic refresh as fallback
            refreshInterval = setInterval(() => {
                console.log('Auto-refreshing cluster status...');
                loadClusters();
            }, REFRESH_INTERVAL);

            console.log('Auto-refresh started (every 30 seconds)');
        }

        function stopAutoRefresh() {
            if (refreshInterval) {
                clearInterval(refreshInterval);
                refreshInterval = null;
                console.log('Auto-refresh stopped');
            }
        }

        // Load clusters
        function loadClusters() {
            fetch('/api/clusters', {
                credentials: 'include'  // Include cookies for authentication
            })
                .then(response => {
                    if (response.status === 401 || response.status === 403) {
                        console.log('Session expired while loading clusters, reloading page...');
                        window.location.reload();
                        return;
                    }
                    return response.json();
                })
                .then(clusters => {
                    if (clusters) {
                        updateClusters(clusters);
                        updateStats(clusters);
                    }
                })
                .catch(error => {
                    console.error('Error loading clusters:', error);
                });
        }

        // Build the human label for a parameter key from the discovered
        // parameter metadata, falling back to a humanized key.
        function parameterLabel(key) {
            const meta = (allClusterParameters || []).find(p => p.key && p.key.toLowerCase() === key.toLowerCase());
            if (meta && meta.label) return meta.label;
            return key
                .replace(/[_-]/g, ' ')
                .replace(/([a-z])([A-Z])/g, '$1 $2')
                .replace(/\b\w/g, c => c.toUpperCase());
        }

        // Tracks which "More details" panels are open so the expanded state
        // survives full re-renders (the cluster list is rebuilt on every
        // websocket/health-check update).
        const expandedDetails = new Set();

        // Parameters already surfaced elsewhere on the card (main details grid
        // and groups section), excluded from "More details" to avoid duplicates.
        const MORE_DETAILS_EXCLUDE = new Set([
            'podcidr', 'servicecidr', 'servicedomain',
            'version', 'nodes', 'controlplanereplicas', 'groups', 'name',
        ]);

        // Render the collapsible "More details" section listing every parameter
        // that was set for the cluster at creation time.
        function extractLabelValue(path, labels) {
            if (!path || !labels) return undefined;
            const m = path.match(/^metadata\.labels\.'([^']+)'$/);
            return m ? labels[m[1]] : undefined;
        }

        function renderMoreDetails(cluster) {
            const params = Object.assign({}, cluster.parameters || {});
            // Merge boolean parameters whose values live in cluster labels
            // (not in the chihiro.io/parameters annotation) so they show in
            // the "More details" section. Use allClusterParameters so every
            // parameter is always visible in the read-only panel, even when
            // the user lacks the group needed to edit it.
            (allClusterParameters || []).forEach(p => {
                if (p.type === 'boolean' && p.key) {
                    const keyLower = p.key.toLowerCase();
                    const exists = Object.keys(params).some(k => k.toLowerCase() === keyLower);
                    if (!exists) {
                        const val = extractLabelValue(p.path, cluster.labels);
                        if (val !== undefined) params[p.key] = String(val);
                    }
                }
            });
            // Resolve chihiro token references in parameter values using the
            // cluster's live state so stored templates display as the
            // actual resolved value.
            const liveTokens = {};
            if (cluster.version) liveTokens.version = cluster.version;
            Object.keys(params).forEach(k => {
                const v = params[k];
                if (typeof v === 'string' && /\{\{\s*chihiro\.\w+\s*\}\}/.test(v)) {
                    params[k] = resolveChihiroTokens(v, liveTokens);
                }
            });
            // Only show parameters that are declared in config
            // (allClusterParameters). Entries present on the cluster but not in the
            // current config — e.g. addon labels/params like openstack-ccm or
            // openstack-cinder-csi that are not part of cluster.parameters — are
            // ignored and never displayed.
            const declaredKeys = new Set((allClusterParameters || [])
                .filter(p => p.key)
                .map(p => p.key.toLowerCase()));
            const keys = Object.keys(params)
                .filter(key => !MORE_DETAILS_EXCLUDE.has(key.toLowerCase()))
                .filter(key => declaredKeys.has(key.toLowerCase()))
                .sort();
            if (keys.length === 0) return '';

            const id = `more-${cluster.namespace}-${cluster.name}`;
            const isExpanded = expandedDetails.has(id);
            const nameJs = escapeJs(cluster.name);
            const nsJs = escapeJs(cluster.namespace);
            const boolKeys = [];
            const otherKeys = [];
            keys.forEach(key => {
                const meta = (allClusterParameters || []).find(p => p.key && p.key.toLowerCase() === key.toLowerCase());
                const rawVal = String(params[key]).toLowerCase();
                const matchesTrueValue = meta && meta.trueValue && String(params[key]) === meta.trueValue;
                if ((meta && meta.type === 'boolean') || rawVal === 'true' || rawVal === 'false' || matchesTrueValue) {
                    boolKeys.push(key);
                } else {
                    otherKeys.push(key);
                }
            });

            const boolChips = boolKeys.map(key => {
                const meta = (allClusterParameters || []).find(p => p.key && p.key.toLowerCase() === key.toLowerCase());
                const editable = canEditField(cluster, key);
                const on = meta
                    ? (params[key] === 'true' || params[key] === meta.trueValue)
                    : (String(params[key]).toLowerCase() === 'true');
                const editBtn = editable
                    ? `<button class="edit-btn" onclick="openEditParameterModal('${nameJs}', '${nsJs}', '${escapeJs(key)}')"><span class="material-symbols-outlined">edit</span></button>`
                    : '';
                return `<span class="bool-chip-item">${editBtn}<span class="param-bool ${on ? 'on' : 'off'}">${on ? 'On' : 'Off'}</span><span class="bool-chip-label">${escapeHtml(parameterLabel(key))}</span></span>`;
            }).join('');

            const boolRow = boolKeys.length > 0
                ? `<div class="detail-item full-width"><div class="detail-label" style="margin-bottom: 8px;">Options</div><div class="bool-chips-row">${boolChips}</div></div>`
                : '';

            const otherRows = otherKeys.map(key => {
                const editable = canEditField(cluster, key);
                const valueHtml = escapeHtml(params[key]);
                const editBtn = editable
                    ? `<button class="edit-btn" onclick="openEditParameterModal('${nameJs}', '${nsJs}', '${escapeJs(key)}')"><span class="material-symbols-outlined">edit</span></button>`
                    : '';
                return `
                <div class="detail-item">
                    <div class="detail-label">${escapeHtml(parameterLabel(key))}${editBtn}</div>
                    <div class="detail-value">${valueHtml}</div>
                </div>
            `;
            }).join('');

            const rows = boolRow + otherRows;

            return `
                <button class="more-details-toggle ${isExpanded ? 'expanded' : ''}" onclick="toggleMoreDetails('${id}', this)">
                    <span>${isExpanded ? 'Hide details' : 'More details'}</span>
                    <span class="material-symbols-outlined">expand_more</span>
                </button>
                <div class="more-details ${isExpanded ? 'expanded' : ''}" id="${id}">
                    ${rows}
                </div>
            `;
        }

        function toggleMoreDetails(id, btn) {
            const panel = document.getElementById(id);
            if (!panel) return;
            const expanded = panel.classList.toggle('expanded');
            btn.classList.toggle('expanded', expanded);
            btn.querySelector('span').textContent = expanded ? 'Hide details' : 'More details';
            // Persist state so re-renders keep the panel open/closed.
            if (expanded) {
                expandedDetails.add(id);
            } else {
                expandedDetails.delete(id);
            }
        }

        function escapeHtml(value) {
            return String(value)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        // escapeJs escapes a value for safe interpolation inside a single-quoted
        // JavaScript string literal embedded in an inline HTML attribute (e.g.
        // onclick="fn('...')"). It neutralizes quote breakouts, backslashes, and
        // angle brackets so attacker-controlled data (group names, etc.) cannot
        // break out of the handler or the attribute.
        function escapeJs(value) {
            return String(value)
                .replace(/\\/g, '\\\\')
                .replace(/'/g, '\\x27')
                .replace(/"/g, '\\x22')
                .replace(/</g, '\\x3C')
                .replace(/>/g, '\\x3E')
                .replace(/\r/g, '\\r')
                .replace(/\n/g, '\\n');
        }

        // Map a CAPI cluster phase to a status badge style.
        function phaseStatusClass(phase) {
            switch ((phase || '').toLowerCase()) {
                case 'provisioned':
                    return 'provisioned';
                case 'failed':
                case 'deleting':
                    return 'not-ready';
                default: // Pending, Provisioning, Unknown, ...
                    return 'pending';
            }
        }

        // Update clusters display
        function updateClusters(clusters) {
            currentClustersList = clusters || [];
            const container = document.getElementById('clustersContainer');
            const emptyState = document.getElementById('emptyState');

            if (!clusters || clusters.length === 0) {
                container.style.display = 'none';
                emptyState.style.display = 'block';
                return;
            }

            container.style.display = 'grid';
            emptyState.style.display = 'none';

            container.innerHTML = clusters.map(cluster => {
                const age = getAge(cluster.createdAt);
                const statusText = cluster.available ? 'Available' : (cluster.phase || 'Unknown');
                const statusClass = cluster.available ? 'ready' : phaseStatusClass(cluster.phase);

                // All cluster fields below originate from Kubernetes resources
                // (names, groups, creator, parameters) and must be treated as
                // untrusted. Escape for HTML text context and, separately, for
                // the single-quoted JS string literals used inside inline
                // onclick handlers to prevent stored XSS.
                const nameHtml = escapeHtml(cluster.name);
                const nsHtml = escapeHtml(cluster.namespace);
                const nameJs = escapeJs(cluster.name);
                const nsJs = escapeJs(cluster.namespace);
                const versionHtml = cluster.version ? escapeHtml(cluster.version) : 'N/A';
                const versionJs = escapeJs(cluster.version || '');
                const apiEndpointHtml = cluster.apiEndpoint ? escapeHtml(cluster.apiEndpoint) : 'N/A';
                const groupsJoined = cluster.groups ? cluster.groups.join(',') : '';
                const podCidrHtml = cluster.network && cluster.network.podCIDRs && cluster.network.podCIDRs.length > 0
                    ? escapeHtml(cluster.network.podCIDRs.join(', ')) : 'N/A';
                const serviceCidrHtml = cluster.network && cluster.network.serviceCIDRs && cluster.network.serviceCIDRs.length > 0
                    ? escapeHtml(cluster.network.serviceCIDRs.join(', ')) : 'N/A';
                const serviceDomainHtml = cluster.network && cluster.network.serviceDomain
                    ? escapeHtml(cluster.network.serviceDomain) : 'N/A';
                // Element IDs embed namespace/name; sanitize to a safe charset so
                // they can't break out of the attribute or collide with markup.
                const idKey = `${cluster.namespace}-${cluster.name}`.replace(/[^A-Za-z0-9_.-]/g, '_');

                return `
                    <div class="cluster-card">
                        <div class="cluster-header">
                            <h3 class="cluster-name">${nameHtml}</h3>
                            <div class="cluster-status ${statusClass}">${escapeHtml(statusText)}</div>
                        </div>

                        <div class="cluster-details">
                            <div class="detail-item">
                                <div class="detail-label">
                                    Version
                                    ${canEditField(cluster, 'version') ? `<button class="edit-btn" onclick="openEditVersionModal('${nameJs}', '${nsJs}', '${versionJs}')"><span class="material-symbols-outlined">edit</span></button>` : ''}
                                </div>
                                <div class="detail-value">${versionHtml}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">
                                    Worker Groups
                                    ${canEditField(cluster, 'workerGroups') ? `<button class="edit-btn" onclick="openEditWorkerGroupsModal('${nameJs}', '${nsJs}')"><span class="material-symbols-outlined">edit</span></button>` : ''}
                                </div>
                                <div class="detail-value">${formatWorkerGroups(cluster.workerGroups, cluster.nodes)}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">
                                    Control Plane
                                    ${canEditField(cluster, 'controlPlaneReplicas') ? `<button class="edit-btn" onclick="openEditControlPlaneModal('${nameJs}', '${nsJs}', ${Number(cluster.controlPlaneReplicas) || 0})"><span class="material-symbols-outlined">edit</span></button>` : ''}
                                </div>
                                <div class="detail-value">${Number(cluster.controlPlaneReplicas) || 0}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Age</div>
                                <div class="detail-value">${escapeHtml(age)}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Pod CIDR</div>
                                <div class="detail-value">${podCidrHtml}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Service CIDR</div>
                                <div class="detail-value">${serviceCidrHtml}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Service Domain</div>
                                <div class="detail-value">${serviceDomainHtml}</div>
                            </div>
                            <div class="detail-item full-width">
                                <div class="detail-label">API Endpoint</div>
                                <div class="detail-value" style="font-size: 0.75rem; word-break: break-all;">${apiEndpointHtml}</div>
                            </div>
                        </div>

                        ${renderMoreDetails(cluster)}

                        <div class="cluster-groups">
                            <div class="groups-label">
                                Access Groups
                                ${canEditField(cluster, 'groups') ? `<button class="edit-btn" onclick="openEditGroupsModal('${nameJs}', '${nsJs}', '${escapeJs(groupsJoined)}')"><span class="material-symbols-outlined">edit</span></button>` : ''}
                            </div>
                            <div class="group-chips">
                                ${cluster.groups && cluster.groups.length > 0 ?
                                    cluster.groups.map(group => `<span class="group-chip">${escapeHtml(group)}</span>`).join('') :
                                    '<span style="color: var(--md-sys-color-on-surface-variant); font-size: 0.85rem;">No groups assigned</span>'
                                }
                            </div>
                        </div>

                        <div class="cluster-actions">
                            ${cluster.apiEndpoint && cluster.kubeconfigReady ? `
                            <button class="btn btn-filled btn-small"
                                    id="kubeconfig-btn-${idKey}"
                                    onclick="downloadKubeconfig('${nameJs}', '${nsJs}')">
                                <span class="material-symbols-outlined" style="margin-right: 4px;">download</span>
                                Kubeconfig
                            </button>` : `
                            <button class="btn btn-small" disabled
                                    title="${!cluster.apiEndpoint ? 'Waiting for the control plane endpoint to become available.' : 'Waiting for the control plane OIDC configuration so a kubeconfig can be generated.'}"
                                    style="opacity: 0.5; cursor: not-allowed; background-color: var(--md-sys-color-surface); color: var(--md-sys-color-on-surface-variant); border: 1px solid var(--md-sys-color-outline); border-radius: 24px; padding: 0 16px; height: 36px; font-size: 0.85rem; font-family: 'Inter', sans-serif; font-weight: 500; display: inline-flex; align-items: center;">
                                <span class="material-symbols-outlined" style="margin-right: 4px;">download</span>
                                Kubeconfig
                            </button>`}
                            ${canDeleteCluster(cluster) ? `
                                <button class="btn danger btn-small" onclick="openDeleteModal('${nameJs}', '${nsJs}')">
                                    <span class="material-symbols-outlined" style="margin-right: 4px;">delete</span>
                                    Delete
                                </button>
                            ` : ''}
                        </div>
                        <div class="kubeconfig-status" id="kubeconfig-status-${idKey}" style="display: none; margin-top: 8px; font-size: 0.8rem; align-items: center; gap: 6px;"></div>
                    </div>
                `;
            }).join('');

            // Re-apply any in-progress / error kubeconfig status messages that
            // were lost when the cluster cards were re-rendered (WebSocket
            // updates rebuild the whole container's innerHTML).
            for (const [key, state] of Object.entries(kubeconfigStatus)) {
                renderKubeconfigStatus(key, state);
            }
        }

        // Tracks per-cluster kubeconfig generation status across re-renders.
        // Keyed by "namespace/name". Each value: { type: 'pending'|'error', message }.
        const kubeconfigStatus = {};

        function clusterKey(name, namespace) {
            return `${namespace}/${name}`;
        }

        // clusterDomId builds the sanitized suffix used in per-cluster element
        // IDs. It must match the idKey computed during card rendering so lookups
        // resolve to the right element regardless of characters in the
        // namespace/name.
        function clusterDomId(namespace, name) {
            return `${namespace}-${name}`.replace(/[^A-Za-z0-9_.-]/g, '_');
        }

        // renderKubeconfigStatus paints the inline status line for a cluster card
        // from the stored state (or clears it when state is null/undefined).
        function renderKubeconfigStatus(key, state) {
            const slash = key.indexOf('/');
            const namespace = key.slice(0, slash);
            const name = key.slice(slash + 1);
            const el = document.getElementById(`kubeconfig-status-${clusterDomId(namespace, name)}`);
            if (!el) return;

            if (!state) {
                el.style.display = 'none';
                el.innerHTML = '';
                return;
            }

            el.style.display = 'flex';
            if (state.type === 'pending') {
                el.style.color = 'var(--md-sys-color-on-surface-variant)';
                el.innerHTML = `<span class="material-symbols-outlined spin" style="font-size: 1rem;">progress_activity</span><span>${escapeHtml(state.message)}</span>`;
            } else if (state.type === 'error') {
                el.style.color = 'var(--md-sys-color-error)';
                el.innerHTML = `<span class="material-symbols-outlined" style="font-size: 1rem;">error</span><span>${escapeHtml(state.message)}</span>`;
            }
        }

        function setKubeconfigStatus(name, namespace, state) {
            const key = clusterKey(name, namespace);
            if (state) {
                kubeconfigStatus[key] = state;
            } else {
                delete kubeconfigStatus[key];
            }
            renderKubeconfigStatus(key, state);
        }

        // setButtonLoading toggles a button into a "working" state: it disables
        // the button and replaces its label with a spinning progress icon (the
        // same one used by the kubeconfig status line), then restores the
        // original markup and disabled state when called with isLoading=false.
        // Safe to call with a null/undefined button.
        function setButtonLoading(btn, isLoading, loadingText) {
            if (!btn) return;
            if (isLoading) {
                if (btn.dataset.loading === 'true') return;
                btn.dataset.loading = 'true';
                btn.dataset.originalHtml = btn.innerHTML;
                btn.dataset.wasDisabled = btn.disabled ? 'true' : 'false';
                const label = loadingText != null ? loadingText : 'Working…';
                btn.innerHTML =
                    '<span class="material-symbols-outlined spin" style="margin-right: 4px; font-size: 1rem;">progress_activity</span>' +
                    '<span>' + escapeHtml(label) + '</span>';
                btn.disabled = true;
            } else {
                if (btn.dataset.loading !== 'true') return;
                btn.innerHTML = btn.dataset.originalHtml || btn.innerHTML;
                btn.disabled = btn.dataset.wasDisabled === 'true';
                delete btn.dataset.loading;
                delete btn.dataset.originalHtml;
                delete btn.dataset.wasDisabled;
            }
        }

        // downloadKubeconfig fetches the generated kubeconfig via JS so we can
        // show progress and surface server errors inline, instead of navigating
        // the browser to a raw JSON error page. Server-side generation can take
        // a while because it waits for the control plane endpoint and OIDC data.
        async function downloadKubeconfig(name, namespace) {
            const btn = document.getElementById(`kubeconfig-btn-${clusterDomId(namespace, name)}`);
            if (btn) btn.disabled = true;

            setKubeconfigStatus(name, namespace, {
                type: 'pending',
                message: 'Generating kubeconfig… fetching control plane endpoint and OIDC data.'
            });

            try {
                const resp = await fetch(`/api/clusters/${encodeURIComponent(name)}/kubeconfig?namespace=${encodeURIComponent(namespace)}`, {
                    headers: { 'Accept': 'application/octet-stream' }
                });

                if (!resp.ok) {
                    let message = `Failed to generate kubeconfig (HTTP ${resp.status}).`;
                    try {
                        const data = await resp.json();
                        if (data && data.error) message = data.error;
                    } catch (_) { /* non-JSON body, keep generic message */ }
                    setKubeconfigStatus(name, namespace, { type: 'error', message });
                    return;
                }

                const blob = await resp.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${name}-kubeconfig.yaml`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);

                // Briefly confirm success, then clear the status line.
                setKubeconfigStatus(name, namespace, { type: 'pending', message: 'Kubeconfig downloaded.' });
                setTimeout(() => setKubeconfigStatus(name, namespace, null), 4000);
            } catch (error) {
                setKubeconfigStatus(name, namespace, {
                    type: 'error',
                    message: `Failed to generate kubeconfig: ${error.message}`
                });
            } finally {
                if (btn) btn.disabled = false;
            }
        }

        // Update stats
        function updateStats(clusters) {
            const list = clusters || [];
            const total = list.length;
            const ready = list.filter(c => c.ready).length;
            // Pending = anything that is neither ready nor in the Provisioned phase.
            const pending = list.filter(c => !c.ready && (c.phase || '').toLowerCase() !== 'provisioned').length;

            document.getElementById('totalClusters').textContent = total;
            document.getElementById('readyClusters').textContent = ready;
            document.getElementById('pendingClusters').textContent = pending;
        }

        // Utility functions
        function getAge(createdAt) {
            const now = new Date();
            const created = new Date(createdAt);
            const diffMs = now - created;
            const diffMins = Math.floor(diffMs / 60000);
            const diffHours = Math.floor(diffMins / 60);
            const diffDays = Math.floor(diffHours / 24);

            if (diffDays > 0) {
                return diffDays + 'd';
            } else if (diffHours > 0) {
                return diffHours + 'h';
            } else {
                return diffMins + 'm';
            }
        }

        function canEditCluster(cluster) {
            console.log('Checking edit permissions for cluster:', cluster.name, 'User groups:', userGroups, 'Cluster groups:', cluster.groups, 'IsAdmin:', isAdmin, 'Creator:', cluster.creator, 'Current user:', currentUser?.username, 'IsCreatorGroupMember:', isCreatorGroupMember);

            // Admins can edit any cluster
            if (isAdmin) return true;

            // User must be in creator groups to modify
            if (!isCreatorGroupMember) return false;

            // Check if user is the creator
            if (cluster.creator && currentUser && cluster.creator === currentUser.username) {
                console.log('User is creator, can edit');
                return true;
            }

            // Check if user shares a group with the cluster
            if (!cluster.groups) return false;
            const sharesGroup = cluster.groups.some(group => userGroups.includes(group));
            console.log('Can edit result:', sharesGroup);
            return sharesGroup;
        }

        function canDeleteCluster(cluster) {
            return canEditCluster(cluster);
        }

        // Modal functions
        function openCreateModal() {
            console.log('Opening create modal, isAdmin:', isAdmin);
            document.getElementById('createModalOverlay').style.display = 'flex';
            loadLimitsInfo(); // Load and display limits
            renderDynamicParameters();

            // Initialize worker groups editor with one default group seeded
            // from the schema defaults.
            document.getElementById('createWorkerGroups').innerHTML = '';
            createGroupIndex = 0;
            addCreateWorkerGroup(defaultWorkerGroupValues());

            if (isAdmin) {
                console.log('Admin user - showing text input');
                document.getElementById('groupsSection').style.display = 'none';
                document.getElementById('groupsTextSection').style.display = 'block';
            } else {
                console.log('Regular user - showing dropdown');
                document.getElementById('groupsSection').style.display = 'block';
                document.getElementById('groupsTextSection').style.display = 'none';
            }
        }

        function closeCreateModal() {
            document.getElementById('createModalOverlay').style.display = 'none';
            document.getElementById('createClusterForm').reset();
        }

        function openEditGroupsModal(name, namespace, currentGroups) {
            console.log('Opening edit modal, isAdmin:', isAdmin, 'currentGroups:', currentGroups);
            editClusterData = { name, namespace, currentGroups };
            document.getElementById('editClusterName').textContent = name;
            document.getElementById('editGroupsModalOverlay').style.display = 'flex';

            if (isAdmin) {
                console.log('Admin user - showing text input for editing');
                document.getElementById('editGroupsSection').style.display = 'none';
                document.getElementById('editGroupsTextSection').style.display = 'block';
                document.getElementById('editClusterGroupsText').value = currentGroups;
            } else {
                console.log('Regular user - showing dropdown for editing');
                document.getElementById('editGroupsSection').style.display = 'block';
                document.getElementById('editGroupsTextSection').style.display = 'none';

                // Set current selections - only for groups the user belongs to
                const select = document.getElementById('editClusterGroups');
                const currentGroupsList = currentGroups.split(',').filter(g => g.trim());
                Array.from(select.options).forEach(option => {
                    // Only pre-select groups the user belongs to
                    option.selected = currentGroupsList.includes(option.value) && userGroups.includes(option.value);
                });

                // Show info about groups user doesn't control
                const groupsNotOwned = currentGroupsList.filter(g => !userGroups.includes(g));
                if (groupsNotOwned.length > 0) {
                    console.log('Cluster has groups user does not belong to:', groupsNotOwned);
                }
            }
        }

        function closeEditGroupsModal() {
            document.getElementById('editGroupsModalOverlay').style.display = 'none';
            editClusterData = null;
        }

        let editNodesData = null;

        // Seed values for a brand-new worker group from the schema defaults.
        function defaultWorkerGroupValues() {
            const values = {};
            workerGroupFieldSchema().forEach(f => {
                if (f.default !== undefined && f.default !== null && f.default !== '') {
                    values[f.key] = f.default;
                }
            });
            if (values.name === undefined) values.name = 'worker';
            return values;
        }

        function formatWorkerGroups(groups, totalNodes) {
            if (!groups || groups.length === 0) {
                return totalNodes || 0;
            }
            const schema = workerGroupFieldSchema();
            // Summarise each group using the configured fields (skipping name,
            // which is shown as the group identifier).
            return groups.map(g => {
                const replicas = Number(g.replicas) || 0;
                const parts = schema
                    .filter(f => f.key !== 'name' && f.key !== 'replicas')
                    .map(f => g[f.key])
                    .filter(v => v !== undefined && v !== null && v !== '')
                    .map(v => escapeHtml(String(v)));
                const label = g.name ? escapeHtml(String(g.name)) : '';
                const detail = parts.length > 0 ? ` ${parts.join(' / ')}` : '';
                return `${replicas}x${detail}${label ? ` [${label}]` : ''}`;
            }).join(', ');
        }

        function openEditWorkerGroupsModal(name, namespace) {
            editNodesData = { name, namespace };
            document.getElementById('editWorkerGroupsClusterName').textContent = name;

            // Find the cluster to get current worker groups
            const cluster = currentClustersList.find(c => c.name === name && c.namespace === namespace);
            const groups = (cluster && cluster.workerGroups) ? cluster.workerGroups : [];

            const container = document.getElementById('editWorkerGroupsList');
            container.innerHTML = '';
            editGroupIndex = 0;
            if (groups.length === 0) {
                addEditWorkerGroup(defaultWorkerGroupValues());
            } else {
                groups.forEach(g => addEditWorkerGroup(g));
            }

            document.getElementById('editWorkerGroupsModalOverlay').style.display = 'flex';

            // Load limits info
            fetch('/api/limits', { credentials: 'include' })
                .then(r => r.json())
                .then(data => {
                    const el = document.getElementById('editWorkerGroupsLimitsInfo');
                    if (data.maxTotalNodes > 0) {
                        el.textContent = `Available: ${data.availableNodes} nodes | Max: ${data.maxTotalNodes} nodes (${data.currentTotalNodes} in use)`;
                    } else {
                        el.textContent = 'No node limits configured';
                    }
                })
                .catch(() => {
                    document.getElementById('editWorkerGroupsLimitsInfo').textContent = '';
                });
        }

        function closeEditWorkerGroupsModal() {
            document.getElementById('editWorkerGroupsModalOverlay').style.display = 'none';
            editNodesData = null;
        }

        let createGroupIndex = 0;

        // values is an object keyed by worker-group field key (e.g.
        // { name: 'worker', flavor: 'xmedium', replicas: 1 }).
        function addCreateWorkerGroup(values) {
            const container = document.getElementById('createWorkerGroups');
            const idx = createGroupIndex++;
            const div = document.createElement('div');
            div.className = 'worker-group-row';
            div.id = `create-wg-${idx}`;
            div.innerHTML = workerGroupRowHTML(idx, values || {}, 'create');
            container.appendChild(div);
        }

        function removeCreateWorkerGroup(idx) {
            const el = document.getElementById(`create-wg-${idx}`);
            if (el) el.remove();
        }

        let editGroupIndex = 0;

        function addEditWorkerGroup(values) {
            const container = document.getElementById('editWorkerGroupsList');
            const idx = editGroupIndex++;
            const div = document.createElement('div');
            div.className = 'worker-group-row';
            div.id = `edit-wg-${idx}`;
            div.innerHTML = workerGroupRowHTML(idx, values || {}, 'edit');
            container.appendChild(div);
        }

        function removeEditWorkerGroup(idx) {
            const el = document.getElementById(`edit-wg-${idx}`);
            if (el) el.remove();
        }

        // Returns the worker-group field schema, falling back to the legacy
        // name/class/flavor/replicas layout if config hasn't loaded yet.
        function workerGroupFieldSchema() {
            if (workerGroupFields && workerGroupFields.length > 0) {
                return workerGroupFields;
            }
            return [
                { key: 'name', label: 'Group name', type: 'string', required: true },
                { key: 'class', label: 'Class', type: 'string', default: 'default-worker' },
                { key: 'flavor', label: 'Flavor', type: 'string' },
                { key: 'replicas', label: 'Replicas', type: 'number', default: '1', min: 1, max: 10 }
            ];
        }

        function workerGroupFieldInputHTML(field, idx, prefix, value) {
            const id = `${prefix}-wg-${field.key}-${idx}`;
            const cls = `wg-field wg-field-${field.key}`;
            const val = (value !== undefined && value !== null) ? String(value) : '';
            if (field.type === 'select' && field.options && field.options.length > 0) {
                const opts = field.options.map(o =>
                    `<option value="${escapeHtml(o)}" ${o === val ? 'selected' : ''}>${escapeHtml(o)}</option>`
                ).join('');
                return `<select id="${id}" class="${cls}" data-key="${escapeHtml(field.key)}">${opts}</select>`;
            }
            if (field.type === 'number') {
                const min = (field.min != null) ? ` min="${field.min}"` : '';
                const max = (field.max != null) ? ` max="${field.max}"` : '';
                const shown = val || (field.default || '');
                return `<input type="number" id="${id}" class="${cls}" data-key="${escapeHtml(field.key)}" value="${escapeHtml(shown)}"${min}${max}>`;
            }
            return `<input type="text" id="${id}" class="${cls}" data-key="${escapeHtml(field.key)}" value="${escapeHtml(val)}" placeholder="${escapeHtml(field.label || field.key)}">`;
        }

        function workerGroupRowHTML(idx, values, prefix) {
            const schema = workerGroupFieldSchema();
            const nameField = schema.find(f => f.key === 'name');
            const otherFields = schema.filter(f => f.key !== 'name');

            // Render the name field (if present) inline in the header next to the
            // delete button; everything else goes in the details row.
            let headerInput;
            if (nameField) {
                const nameVal = (values && values.name !== undefined) ? values.name : (nameField.default || '');
                headerInput = workerGroupFieldInputHTML(nameField, idx, prefix, nameVal).replace('class="wg-field', 'class="wg-name wg-field');
            } else {
                headerInput = '<span></span>';
            }

            const details = otherFields.map(f => {
                let v = (values && values[f.key] !== undefined) ? values[f.key] : (f.default || '');
                return `
                    <span class="wg-label">${escapeHtml(f.label || f.key)}</span>
                    ${workerGroupFieldInputHTML(f, idx, prefix, v)}
                `;
            }).join('');

            return `
                <div class="wg-header">
                    ${headerInput}
                    <button type="button" class="edit-btn" onclick="remove${prefix === 'create' ? 'Create' : 'Edit'}WorkerGroup(${idx})" style="color: var(--md-sys-color-error); border-color: var(--md-sys-color-error); flex: 0 0 auto;">
                        <span class="material-symbols-outlined">delete</span>
                    </button>
                </div>
                <div class="wg-details">
                    ${details}
                </div>
            `;
        }

        function collectWorkerGroups(prefix) {
            const container = document.getElementById(prefix === 'create' ? 'createWorkerGroups' : 'editWorkerGroupsList');
            const rows = container.querySelectorAll('.worker-group-row');
            const groups = [];
            rows.forEach(row => {
                const group = {};
                row.querySelectorAll('.wg-field').forEach(input => {
                    const key = input.getAttribute('data-key');
                    if (!key) return;
                    let value = input.value.trim();
                    if (input.type === 'number') {
                        group[key] = parseInt(value) || 0;
                    } else {
                        group[key] = value;
                    }
                });
                // A group needs a name to be meaningful.
                if (group.name) {
                    groups.push(group);
                }
            });
            return groups;
        }

        let currentClustersList = [];

        let editControlPlaneData = null;

        function openEditControlPlaneModal(name, namespace, currentReplicas) {
            editControlPlaneData = { name, namespace };
            document.getElementById('editControlPlaneClusterName').textContent = name;

            const input = document.getElementById('editClusterControlPlane');
            const cfg = editableFields['controlplanereplicas'] || {};
            const min = (cfg.min != null) ? cfg.min : 1;
            input.min = min;
            if (cfg.max != null) {
                input.max = cfg.max;
            } else {
                input.removeAttribute('max');
            }
            input.value = currentReplicas;

            const hint = document.getElementById('editControlPlaneHint');
            hint.textContent = (cfg.max != null)
                ? `Allowed range: ${min}–${cfg.max} replicas`
                : `Minimum: ${min} replica${min === 1 ? '' : 's'}`;

            document.getElementById('editControlPlaneModalOverlay').style.display = 'flex';
        }

        function closeEditControlPlaneModal() {
            document.getElementById('editControlPlaneModalOverlay').style.display = 'none';
            editControlPlaneData = null;
        }

        let editVersionData = null;
        let availableVersions = [];

        function openEditVersionModal(name, namespace, currentVersion) {
            console.log('Opening edit version modal for cluster:', name, 'current version:', currentVersion);
            const cluster = currentClustersList.find(c => c.name === name && c.namespace === namespace);
            editVersionData = { name, namespace, currentVersion, cluster };
            document.getElementById('editVersionClusterName').textContent = name;

            // Populate dropdown with upgrade-only versions
            populateUpgradeVersions(currentVersion);
            // Clear any previous dependent-parameter preview.
            renderVersionDependents('');

            document.getElementById('editVersionModalOverlay').style.display = 'flex';
        }

        function closeEditVersionModal() {
            document.getElementById('editVersionModalOverlay').style.display = 'none';
            editVersionData = null;
        }

        // resolveChihiroTokens replaces chihiro token references in a value
        // using the supplied token table (case-insensitive). Unknown tokens are
        // left untouched. Mirrors the server-side resolver.
        function resolveChihiroTokens(value, tokens) {
            if (!value) return value;
            return value.replace(/\{\{\s*chihiro\.(\w+)\s*\}\}/g, function(match, key) {
                const v = tokens[key.toLowerCase()];
                return (v !== undefined && v !== '') ? v : match;
            });
        }

        // optionConstraintValues returns the list of allowed values an option
        // declares for the given field via its generic `constrain` map, or null
        // when the option does not constrain that field.
        function optionConstraintValues(o, field) {
            if (!o || typeof o !== 'object' || !o.constrain) return null;
            const key = Object.keys(o.constrain).find(
                k => k.toLowerCase() === String(field).toLowerCase());
            if (key === undefined) return null;
            const vals = o.constrain[key];
            return Array.isArray(vals) && vals.length > 0 ? vals : null;
        }

        // versionDependentParams returns the declared parameters that will be
        // recomputed when the version changes. This includes parameters with
        // explicit recompute_on "version" as well as select parameters whose
        // options constrain the version field (auto-detected dependency).
        function versionDependentParams() {
            return (clusterParameters || []).filter(p => {
                // Explicit recompute_on dependency.
                if (Array.isArray(p.recomputeOn) &&
                    p.recomputeOn.some(d => String(d).toLowerCase() === 'version')) {
                    return true;
                }
                // Auto-detected: select with options constraining version.
                if (p.type === 'select' && Array.isArray(p.options) &&
                    p.options.some(o => optionConstraintValues(o, 'version') !== null)) {
                    return true;
                }
                return false;
            });
        }

        // computeDependentValueForVersion mirrors the server's recompute logic
        // for a single parameter and target version: pick the option compatible
        // with the new version (honoring each option's versions list), keeping
        // the current option when it stays compatible, then resolve the embedded
        // chihiro version token. Returns the final resolved value.
        function computeDependentValueForVersion(p, newVersion, cluster) {
            const tokens = { version: newVersion };
            // Current raw state from the cluster's stored parameters (if any).
            let current;
            if (cluster && cluster.parameters) {
                const k = Object.keys(cluster.parameters).find(
                    x => x.toLowerCase() === p.key.toLowerCase());
                if (k !== undefined) current = cluster.parameters[k];
            }

            const opts = (p.type === 'select' && Array.isArray(p.options)) ? p.options : [];
            const compatible = (o) => {
                const allowed = optionConstraintValues(o, 'version');
                return !allowed ||
                    allowed.some(v => String(v).toLowerCase() === String(newVersion).toLowerCase());
            };

            let candidate;
            if (opts.length > 0) {
                // Keep current option if still compatible.
                if (current) {
                    const match = opts.find(o =>
                        (o.value === current ||
                         resolveChihiroTokens(o.value, tokens) === resolveChihiroTokens(current, tokens))
                        && compatible(o));
                    if (match) candidate = match.value;
                }
                // Otherwise first compatible option.
                if (candidate === undefined) {
                    const firstCompat = opts.find(compatible);
                    if (firstCompat) candidate = firstCompat.value;
                }
                if (candidate === undefined) candidate = current || p.default;
            } else {
                candidate = current || p.default;
            }

            return resolveChihiroTokens(candidate, tokens);
        }

        // renderVersionDependents shows, for the selected target version, what
        // each version-dependent parameter (e.g. the node image) will be changed
        // to. Pass an empty version to hide the preview.
        function renderVersionDependents(newVersion) {
            const container = document.getElementById('editVersionDependents');
            const deps = versionDependentParams();
            if (!newVersion || deps.length === 0) {
                container.style.display = 'none';
                container.innerHTML = '';
                return;
            }
            const cluster = editVersionData && editVersionData.cluster;
            const rows = deps.map(p => {
                const resolved = computeDependentValueForVersion(p, newVersion, cluster);
                return `
                    <div class="detail-item">
                        <div class="detail-label">${escapeHtml(p.label || parameterLabel(p.key))}</div>
                        <div class="detail-value">${escapeHtml(resolved || '')}</div>
                    </div>`;
            }).join('');
            container.innerHTML = `
                <div class="detail-label" style="margin-bottom: 8px;">Will also be updated</div>
                ${rows}
                <small style="color: var(--md-sys-color-on-surface-variant); font-size: 0.8rem; display: block; margin-top: 4px;">
                    These values are recomputed automatically to stay compatible with the selected version.
                </small>`;
            container.style.display = 'block';
        }

        // Generic editable-parameter modal.
        let editParameterData = null;

        function openEditParameterModal(name, namespace, key) {
            const cluster = currentClustersList.find(c => c.name === name && c.namespace === namespace);
            const meta = (allClusterParameters || []).find(p => p.key && p.key.toLowerCase() === key.toLowerCase());
            const editMeta = editableFields[key.toLowerCase()] || {};
            const type = (meta && meta.type) || editMeta.type || 'string';
            // Resolve the current value. The chihiro.io/parameters annotation is
            // the source of truth, but boolean toggles whose value lives in a
            // cluster label (e.g. the Sveltos addon labels for declared params)
            // are not recorded there until first edited. Fall back to reading
            // the live label value via the param's path so the control reflects
            // the cluster's actual state instead of the static default.
            let current;
            const annotationKey = (cluster && cluster.parameters)
                ? Object.keys(cluster.parameters).find(k => k.toLowerCase() === key.toLowerCase())
                : undefined;
            if (annotationKey !== undefined) {
                current = cluster.parameters[annotationKey];
            } else {
                const labelVal = (meta && meta.path && cluster)
                    ? extractLabelValue(meta.path, cluster.labels) : undefined;
                current = (labelVal !== undefined) ? String(labelVal) : (meta ? meta.default : '');
            }

            editParameterData = { name, namespace, key, type };

            document.getElementById('editParameterTitle').textContent =
                'Edit ' + ((meta && meta.label) || parameterLabel(key));
            document.getElementById('editParameterClusterName').textContent = name;
            document.getElementById('editParameterDescription').textContent =
                (meta && meta.description) || '';

            const field = document.getElementById('editParameterField');
            field.innerHTML = '';

            if (type === 'boolean') {
                const on = (current === 'true' || (meta && current === meta.trueValue));
                const label = document.createElement('label');
                label.style.display = 'flex';
                label.style.alignItems = 'center';
                label.style.gap = '8px';
                const cb = document.createElement('input');
                cb.type = 'checkbox';
                cb.id = 'editParameterInput';
                cb.style.width = 'auto';
                cb.checked = on;
                label.appendChild(cb);
                label.appendChild(document.createTextNode((meta && meta.label) || parameterLabel(key)));
                field.appendChild(label);
            } else if (type === 'select' && meta && meta.options && meta.options.length > 0) {
                const sel = document.createElement('select');
                sel.id = 'editParameterInput';
                meta.options.forEach(opt => {
                    // Options may be plain strings or {value,label,constrain}
                    // objects (constrained selects like the node image).
                    const value = (opt && typeof opt === 'object') ? opt.value : opt;
                    const label = (opt && typeof opt === 'object') ? (opt.label || opt.value) : opt;
                    const o = document.createElement('option');
                    o.value = value; o.textContent = label;
                    if (value === current) o.selected = true;
                    sel.appendChild(o);
                });
                sel.onchange = function() { renderParameterImpliedFields(); };
                field.appendChild(sel);
            } else {
                const input = document.createElement('input');
                input.type = type === 'number' ? 'number' : 'text';
                input.id = 'editParameterInput';
                input.value = current || '';
                field.appendChild(input);
            }

            document.getElementById('editParameterModalOverlay').style.display = 'flex';
            if (meta && meta.type === 'select' && Array.isArray(meta.options) &&
                meta.options.some(o => o && typeof o === 'object' && o.constrain &&
                    Object.keys(o.constrain).length > 0)) {
                renderParameterImpliedFields();
            }
        }

        function closeEditParameterModal() {
            document.getElementById('editParameterModalOverlay').style.display = 'none';
            document.getElementById('editParameterImplied').style.display = 'none';
            editParameterData = null;
        }

        // renderParameterImpliedFields shows, for the selected parameter value,
        // what other fields will be auto-set. For select parameters with
        // constrained options, selecting an option that pins a field to a single
        // value implies that value for the field.
        function renderParameterImpliedFields() {
            const container = document.getElementById('editParameterImplied');
            if (!editParameterData || !editParameterData.key) {
                container.style.display = 'none';
                return;
            }
            const meta = (allClusterParameters || []).find(
                p => p.key && p.key.toLowerCase() === editParameterData.key.toLowerCase());
            if (!meta || meta.type !== 'select' || !Array.isArray(meta.options)) {
                container.style.display = 'none';
                return;
            }

            // Auto-detect: does this parameter have constrained options?
            const hasConstraints = meta.options.some(o =>
                o && typeof o === 'object' && o.constrain &&
                Object.keys(o.constrain).length > 0);
            if (!hasConstraints) {
                container.style.display = 'none';
                return;
            }

            const input = document.getElementById('editParameterInput');
            const rawValue = input.value;

            const match = meta.options.find(o => {
                const v = (o && typeof o === 'object') ? o.value : o;
                return v === rawValue;
            });
            if (!match || !match.constrain) {
                container.style.display = 'none';
                return;
            }

            // Any field the selected option pins to exactly one value is implied.
            const implied = Object.entries(match.constrain)
                .filter(([, vals]) => Array.isArray(vals) && vals.length === 1)
                .map(([field, vals]) => {
                    const label = (editableFields && editableFields[field])
                        ? (editableFields[field].label || field)
                        : parameterLabel(field);
                    return `
                        <div class="detail-item">
                            <div class="detail-label">${escapeHtml(label)}</div>
                            <div class="detail-value">${escapeHtml(vals[0])}</div>
                        </div>`;
                });
            if (implied.length === 0) {
                container.style.display = 'none';
                return;
            }
            container.innerHTML = `
                <div class="detail-label" style="margin-bottom: 8px;">Will also be updated</div>
                ${implied.join('')}
                <small style="color: var(--md-sys-color-on-surface-variant); font-size: 0.8rem; display: block; margin-top: 4px;">
                    These values are set automatically to stay consistent with the selected option.
                </small>`;
            container.style.display = 'block';
        }

        function populateUpgradeVersions(currentVersion) {
            const select = document.getElementById('editClusterVersion');
            select.innerHTML = '<option value="">Select a version to upgrade to...</option>';

            // Filter versions to only show newer ones
            const upgradeVersions = availableVersions.filter(version => {
                return compareVersions(version, currentVersion) > 0;
            });

            if (upgradeVersions.length === 0) {
                select.innerHTML = '<option value="">No upgrade versions available</option>';
                select.disabled = true;
            } else {
                select.disabled = false;
                upgradeVersions.forEach(version => {
                    const option = document.createElement('option');
                    option.value = version;
                    option.textContent = version;
                    select.appendChild(option);
                });
            }

            // Refresh the dependent-parameter preview (e.g. node image) whenever
            // the selected target version changes.
            select.onchange = function() { renderVersionDependents(select.value); };
        }

        function compareVersions(version1, version2) {
            // Simple semantic version comparison (v1.2.3 format)
            if (!version1 || !version2) return 0;

            const v1Parts = version1.replace(/^v/, '').split('.').map(Number);
            const v2Parts = version2.replace(/^v/, '').split('.').map(Number);

            for (let i = 0; i < Math.max(v1Parts.length, v2Parts.length); i++) {
                const v1Part = v1Parts[i] || 0;
                const v2Part = v2Parts[i] || 0;

                if (v1Part > v2Part) return 1;
                if (v1Part < v2Part) return -1;
            }
            return 0;
        }

        function openDeleteModal(name, namespace) {
            deleteClusterData = { name, namespace };
            document.getElementById('deleteClusterName').textContent = name;
            document.getElementById('deleteModalOverlay').style.display = 'flex';
        }

        function closeDeleteModal() {
            document.getElementById('deleteModalOverlay').style.display = 'none';
            deleteClusterData = null;
        }

        // Load versions and groups
        function loadVersions() {
            fetch('/api/versions', {
                credentials: 'include'
            })
                .then(response => response.json())
                .then(data => {
                    // Store available versions globally for upgrade filtering
                    availableVersions = data.versions || [];

                    const select = document.getElementById('clusterVersion');
                    select.innerHTML = '<option value="">Select version...</option>';
                    availableVersions.forEach(version => {
                        const option = document.createElement('option');
                        option.value = version;
                        option.textContent = version;
                        select.appendChild(option);
                    });
                    select.addEventListener('change', renderDynamicParameters);
                })
                .catch(error => console.error('Error loading versions:', error));
        }

        function loadLimitsInfo() {
            fetch('/api/limits', {
                credentials: 'include'
            })
                .then(response => response.json())
                .then(data => {
                    const limitsEl = document.getElementById('limitsInfo');
                    const cpInput = document.getElementById('clusterControlPlaneReplicas');

                    if (data.maxClusters > 0 || data.maxTotalNodes > 0 || data.maxTotalCP > 0) {
                        let limitsText = [];

                        if (data.maxClusters > 0) {
                            limitsText.push(`Clusters: ${data.currentClusters}/${data.maxClusters}`);
                        }

                        if (data.maxTotalNodes > 0) {
                            limitsText.push(`Total nodes: ${data.currentTotalNodes}/${data.maxTotalNodes}`);
                            limitsText.push(`Available: ${data.availableNodes}`);
                        }

                        if (data.maxTotalCP > 0) {
                            limitsText.push(`Control plane: ${data.currentTotalCP}/${data.maxTotalCP}`);
                            if (cpInput) cpInput.max = data.availableCP;
                        }

                        limitsEl.textContent = limitsText.join(' | ');

                        // Check if at cluster limit
                        if (data.maxClusters > 0 && data.currentClusters >= data.maxClusters) {
                            limitsEl.style.color = 'var(--md-sys-color-error)';
                            limitsEl.textContent = `Cluster limit reached (${data.currentClusters}/${data.maxClusters}). Cannot create more clusters.`;
                        }
                    } else {
                        limitsEl.textContent = 'No limits configured';
                    }
                })
                .catch(error => {
                    console.error('Error loading limits:', error);
                    document.getElementById('limitsInfo').textContent = 'Failed to load limits';
                });
        }

        function loadUserGroups() {
            fetch('/api/user/groups', {
                credentials: 'include'
            })
                .then(response => response.json())
                .then(data => {
                    const createSelect = document.getElementById('clusterGroups');
                    const editSelect = document.getElementById('editClusterGroups');

                    [createSelect, editSelect].forEach(select => {
                        select.innerHTML = '';
                        data.groups.forEach(group => {
                            const option = document.createElement('option');
                            option.value = group;
                            option.textContent = group;
                            select.appendChild(option);
                        });
                    });
                })
                .catch(error => console.error('Error loading user groups:', error));
        }

        function loadUserPermissions() {
            fetch('/api/user/permissions', {
                credentials: 'include'
            })
                .then(response => response.json())
                .then(data => {
                    canCreate = data.canCreate || false;
                    isCreatorGroupMember = data.canCreate || false; // If can create, user is in creator groups
                    console.log('User permissions loaded:', 'canCreate:', canCreate, 'isAdmin:', data.isAdmin, 'isCreatorGroupMember:', isCreatorGroupMember);

                    // Show or hide create button based on permissions
                    updateCreateButtonVisibility();
                })
                .catch(error => {
                    console.error('Error loading user permissions:', error);
                    canCreate = false;
                    isCreatorGroupMember = false;
                    updateCreateButtonVisibility();
                });
        }

        function updateCreateButtonVisibility() {
            const createButton = document.querySelector('.btn.btn-filled[onclick="openCreateModal()"]');
            if (createButton) {
                if (canCreate) {
                    createButton.style.display = 'inline-flex';
                } else {
                    createButton.style.display = 'none';
                }
            }
        }

        function loadClusterParameters() {
            // Load filtered parameters (for create form) and all parameters
            // (for "More details" read-only display) in parallel.
            Promise.all([
                fetch('/api/cluster/parameters', { credentials: 'include' }).then(r => r.json()),
                fetch('/api/cluster/parameters?all=true', { credentials: 'include' }).then(r => r.json())
            ])
                .then(([filtered, all]) => {
                    clusterParameters = filtered || [];
                    allClusterParameters = all || [];
                })
                .catch(error => {
                    console.error('Error loading cluster parameters:', error);
                    clusterParameters = [];
                    allClusterParameters = [];
                });
        }

        function loadWorkerGroupFields() {
            fetch('/api/cluster/worker-group-fields', {
                credentials: 'include'
            })
                .then(response => response.json())
                .then(data => {
                    workerGroupFields = (data && data.fields) || [];
                })
                .catch(error => {
                    console.error('Error loading worker group fields:', error);
                    workerGroupFields = [];
                });
        }

        function loadEditableFields() {
            return fetch('/api/cluster/editable', {
                credentials: 'include'
            })
                .then(response => response.json())
                .then(fields => {
                    editableFields = {};
                    // Keys may come back in either casing (template tokens keep
                    // their original casing, built-ins are lowercased by config
                    // loading), so index by lowercase for robust lookup.
                    (fields || []).forEach(f => { editableFields[f.key.toLowerCase()] = f; });
                    // Re-render to apply edit-button visibility once config arrives.
                    if (typeof loadClusters === 'function') loadClusters();
                })
                .catch(error => {
                    console.error('Error loading editable fields:', error);
                    editableFields = {};
                });
        }

        // A field's edit button shows only when the user can modify the cluster
        // AND the field is opt-in enabled in config.
        function isFieldEditable(field) {
            const f = editableFields[field.toLowerCase()];
            return !!(f && f.enabled);
        }

        function canEditField(cluster, field) {
            return canEditCluster(cluster) && isFieldEditable(field);
        }

        function resolveParameterValue(value, builtins) {
            if (!value) return value;
            return value.replace(/\{\{\s*chihiro\.(\w+)\s*\}\}/g, function(match, key) {
                return builtins[key.toLowerCase()] || match;
            });
        }

        // filterImageDropdown greys out image options whose version constraint
        // does not include the currently selected Kubernetes version. Pass null
        // to enable all options. Auto-selects the first compatible image if the
        // current selection is no longer compatible.
        function filterImageDropdown(compatibleVersions) {
            // Find all selects that have version metadata.
            document.querySelectorAll('select[data-has-versions]').forEach(sel => {
                const versionMap = sel._resolvedVersionMap || {};
                let foundCompatible = false;
                Array.from(sel.options).forEach(opt => {
                    if (!opt.value) return; // skip placeholder
                    const optVersions = versionMap[opt.value];
                    const isCompatible = !compatibleVersions || !optVersions || optVersions.some(v => compatibleVersions.includes(v));
                    opt.disabled = !isCompatible;
                    opt.style.color = isCompatible ? '' : 'var(--md-sys-color-on-surface-variant)';
                    opt.style.opacity = isCompatible ? '' : '0.5';
                    if (opt.value === sel.value && isCompatible) foundCompatible = true;
                });
                // Auto-select first compatible option if current is no longer valid.
                if (!foundCompatible) {
                    const firstCompatible = Array.from(sel.options).find(o => o.value && !o.disabled);
                    if (firstCompatible) {
                        sel.value = firstCompatible.value;
                        sel.dispatchEvent(new Event('change'));
                    }
                }
            });
        }

        // Tracks the resolved default last applied to each parameter field, so a
        // re-render (e.g. after the version changes) can tell whether the field
        // still holds its default — and may be refreshed — or was edited by the
        // user — and must be preserved.
        const paramResolvedDefaults = {};

        function renderDynamicParameters() {
            const container = document.getElementById('dynamicParamsContainer');
            if (!clusterParameters || clusterParameters.length === 0) {
                container.innerHTML = '';
                return;
            }

            // Snapshot current field values before rebuilding so user input is
            // not lost. Re-rendering is needed because version-derived defaults
            // (e.g. an image name containing a chihiro.version placeholder) must
            // refresh when the selected version changes.
            const previousValues = {};
            clusterParameters.forEach(p => {
                const el = document.getElementById('param_' + p.key);
                if (el) previousValues[p.key] = (el.type === 'checkbox') ? String(el.checked) : el.value;
            });

            container.innerHTML = '';

            const builtins = {
                version: document.getElementById('clusterVersion').value || '',
            };

            clusterParameters.forEach(p => {
                const group = document.createElement('div');
                group.className = 'form-group';

                const label = document.createElement('label');
                label.setAttribute('for', 'param_' + p.key);
                label.textContent = p.label + (p.required ? ' *' : '');
                group.appendChild(label);

                const resolvedDefault = resolveParameterValue(p.default, builtins);

                // Decide the value to show: keep the user's edit, but if the
                // field still matched its previously-resolved default (i.e. it
                // was untouched), refresh it to the new resolved default so
                // version-derived values stay in sync.
                const hadPrevious = Object.prototype.hasOwnProperty.call(previousValues, p.key);
                const previousValue = hadPrevious ? previousValues[p.key] : undefined;
                const previousDefault = paramResolvedDefaults[p.key];
                const isAutoResolved = p.default && /\{\{\s*chihiro\.\w+\s*\}\}/.test(p.default);
                let valueToApply;
                if (!hadPrevious || isAutoResolved) {
                    valueToApply = resolvedDefault;
                } else if (previousValue === '' || previousValue === previousDefault) {
                    valueToApply = resolvedDefault;
                } else {
                    valueToApply = previousValue;
                }
                paramResolvedDefaults[p.key] = resolvedDefault;

                let input;
                if (p.type === 'boolean') {
                    // Render a checkbox; the value collected is "true"/"false".
                    input = document.createElement('input');
                    input.type = 'checkbox';
                    input.id = 'param_' + p.key;
                    input.style.width = 'auto';
                    input.style.marginRight = '8px';
                    // valueToApply is "true"/"false" (string).
                    const isOn = (valueToApply === undefined || valueToApply === '')
                        ? (p.default === 'true')
                        : (valueToApply === 'true' || valueToApply === true);
                    input.checked = isOn;
                    // Put the checkbox before the label text for a natural layout.
                    label.style.display = 'flex';
                    label.style.alignItems = 'center';
                    label.insertBefore(input, label.firstChild);
                } else if (p.type === 'select' || (isAutoResolved && p.options && p.options.length > 0)) {
                    input = document.createElement('select');
                    input.id = 'param_' + p.key;
                    if (!p.required) {
                        const emptyOpt = document.createElement('option');
                        emptyOpt.value = '';
                        emptyOpt.textContent = 'Select...';
                        input.appendChild(emptyOpt);
                    }
                    // Store full option metadata for version filtering.
                    input._optionMeta = p.options || [];
                    p.options.forEach(opt => {
                        const optValue = (typeof opt === 'object' && opt !== null) ? opt.value : opt;
                        const optLabel = (typeof opt === 'object' && opt !== null) ? (opt.label || opt.value) : opt;
                        const resolved = isAutoResolved ? resolveParameterValue(optValue, builtins) : optValue;
                        const resolvedLabel = isAutoResolved ? resolveParameterValue(optLabel, builtins) : optLabel;
                        const option = document.createElement('option');
                        option.value = resolved;
                        option.textContent = resolvedLabel;
                        if (resolved === valueToApply) option.selected = true;
                        input.appendChild(option);
                    });
                    // When a select has options constraining the version field,
                    // store a resolved-value→allowed-versions lookup for
                    // version-based filtering of the create form.
                    const hasVersions = p.options.some(o => optionConstraintValues(o, 'version') !== null);
                    if (hasVersions) {
                        input.setAttribute('data-has-versions', 'true');
                        const resolvedVersionMap = {};
                        p.options.forEach(opt => {
                            const allowed = optionConstraintValues(opt, 'version');
                            if (allowed) {
                                const rv = resolveParameterValue(opt.value, builtins);
                                resolvedVersionMap[rv] = allowed;
                            }
                        });
                        input._resolvedVersionMap = resolvedVersionMap;
                    }
                } else {
                    input = document.createElement('input');
                    input.type = p.type === 'number' ? 'number' : 'text';
                    input.id = 'param_' + p.key;
                    input.placeholder = resolvedDefault || '';
                    if (valueToApply) input.value = valueToApply;
                    if (p.type === 'number') input.min = '0';
                }
                if (p.required && p.type !== 'boolean') input.required = true;
                // Auto-resolved params (defaults containing chihiro variable refs) always
                // resolve the variable part; the user can still edit the non-variable
                // prefix/suffix but the variable is never removable.
                if (isAutoResolved && p.type !== 'boolean' && input.tagName !== 'SELECT') {
                    input.placeholder = p.default;
                    input.value = resolvedDefault;
                    input.style.fontStyle = 'italic';
                    input.style.color = 'var(--md-sys-color-on-surface-variant)';
                }
                // Booleans were already placed inside the label above.
                if (p.type !== 'boolean') {
                    group.appendChild(input);
                }

                if (p.description) {
                    const small = document.createElement('small');
                    small.style.color = 'var(--md-sys-color-on-surface-variant)';
                    small.style.fontSize = '0.8rem';
                    small.textContent = p.description;
                    group.appendChild(small);
                }

                if (isAutoResolved) {
                    const note = document.createElement('small');
                    note.style.color = 'var(--md-sys-color-primary)';
                    note.style.fontSize = '0.75rem';
                    note.style.fontStyle = 'italic';
                    note.textContent = 'Variable ' + p.default.match(/\{\{[^}]+\}\}/)[0] + ' always resolves to the selected version';
                    group.appendChild(note);
                }

                container.appendChild(group);
            });

            // After rendering, apply initial version-based filtering: grey out
            // image options that don't match the current Kubernetes version.
            const versionSelect = document.getElementById('clusterVersion');
            if (versionSelect && versionSelect.value) {
                filterImageDropdown([versionSelect.value]);
            }
        }

        // Form submissions
        // collectCreateClusterPayload reads the create form into the request
        // body shared by both the create and preview endpoints. It validates the
        // inputs and shows an alert + returns null if anything is invalid.
        function collectCreateClusterPayload() {
            const name = document.getElementById('clusterName').value;
            const version = document.getElementById('clusterVersion').value;
            const controlPlaneReplicas = parseInt(document.getElementById('clusterControlPlaneReplicas').value);
            let groups = '';

            if (isAdmin) {
                groups = document.getElementById('clusterGroupsText').value;
            } else {
                const selectedOptions = Array.from(document.getElementById('clusterGroups').selectedOptions);
                groups = selectedOptions.map(option => option.value).join(',');
            }

            // Collect worker groups
            const workerGroups = collectWorkerGroups('create');
            if (workerGroups.length === 0) {
                alert('At least one worker group is required');
                return null;
            }

            // Validate control plane replicas
            if (controlPlaneReplicas < 1) {
                alert('Control plane replicas must be at least 1');
                return null;
            }

            // Non-admin users must select at least one group
            if (!isAdmin && (!groups || groups.trim() === '')) {
                alert('You must assign at least one of your groups to the cluster');
                return null;
            }

            // Collect dynamic template parameters
            const parameters = {};
            const builtins = { version: document.getElementById('clusterVersion').value || '' };
            clusterParameters.forEach(p => {
                const el = document.getElementById('param_' + p.key);
                if (p.type === 'boolean') {
                    // Always send the explicit on/off state for booleans.
                    parameters[p.key] = (el ? el.checked : (p.default === 'true')) ? 'true' : 'false';
                } else if (el && el.tagName === 'SELECT' && el.value) {
                    // Selects always send the user's chosen value.
                    parameters[p.key] = el.value;
                } else if (p.default && /\{\{\s*chihiro\.\w+\s*\}\}/.test(p.default)) {
                    // Auto-resolved params send the resolved value when no
                    // explicit selection was made (e.g. text inputs).
                    parameters[p.key] = resolveParameterValue(p.default, builtins);
                } else if (el && el.value) {
                    parameters[p.key] = el.value;
                } else if (p.default) {
                    parameters[p.key] = p.default;
                }
            });

            return { name, version, controlPlaneReplicas, groups, workerGroups, parameters };
        }

        // previewClusterYaml renders the manifest that would be applied and shows
        // it in a read-only modal. It does not create anything.
        function previewClusterYaml(triggerBtn) {
            const payload = collectCreateClusterPayload();
            if (!payload) return;

            setButtonLoading(triggerBtn, true, 'Rendering…');

            fetch('/api/clusters/preview', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(response => response.json().then(data => {
                if (!response.ok) {
                    throw new Error(data.error || 'Failed to render preview');
                }
                return data;
            }))
            .then(data => {
                document.getElementById('previewYamlContent').textContent = data.yaml || '';
                document.getElementById('previewYamlModalOverlay').style.display = 'flex';
            })
            .catch(error => {
                console.error('Error rendering preview:', error);
                alert('Failed to render preview: ' + error.message);
            })
            .finally(() => {
                setButtonLoading(triggerBtn, false);
            });
        }

        function closePreviewYamlModal() {
            document.getElementById('previewYamlModalOverlay').style.display = 'none';
        }

        function copyPreviewYaml(btn) {
            const text = document.getElementById('previewYamlContent').textContent || '';
            navigator.clipboard.writeText(text).then(() => {
                const original = btn.innerHTML;
                btn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 1.1rem; margin-right: 4px;">check</span>Copied';
                setTimeout(() => { btn.innerHTML = original; }, 1500);
            }).catch(err => {
                console.error('Failed to copy YAML:', err);
                alert('Failed to copy to clipboard');
            });
        }

        document.getElementById('createClusterForm').addEventListener('submit', function(e) {
            e.preventDefault();

            const payload = collectCreateClusterPayload();
            if (!payload) return;

            const submitBtn = e.submitter;
            setButtonLoading(submitBtn, true, 'Creating…');

            fetch('/api/clusters', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(response => {
                if (response.ok) {
                    closeCreateModal();
                    loadClusters(); // Refresh clusters
                } else {
                    return response.json().then(data => {
                        throw new Error(data.error || 'Failed to create cluster');
                    });
                }
            })
            .catch(error => {
                console.error('Error creating cluster:', error);
                alert('Failed to create cluster: ' + error.message);
            })
            .finally(() => {
                setButtonLoading(submitBtn, false);
            });
        });

        document.getElementById('editGroupsForm').addEventListener('submit', function(e) {
            e.preventDefault();

            if (!editClusterData) return;

            let groups = '';
            if (isAdmin) {
                groups = document.getElementById('editClusterGroupsText').value;
            } else {
                // Get selected groups (user's groups only)
                const selectedOptions = Array.from(document.getElementById('editClusterGroups').selectedOptions);
                const selectedUserGroups = selectedOptions.map(option => option.value);

                // Preserve groups the user doesn't belong to
                const currentGroupsList = editClusterData.currentGroups.split(',').filter(g => g.trim());
                const groupsNotOwned = currentGroupsList.filter(g => !userGroups.includes(g));

                // Combine: user's selected groups + groups user doesn't own (preserved)
                const allGroups = [...selectedUserGroups, ...groupsNotOwned];
                groups = allGroups.join(',');

                console.log('Submitting groups:', 'selected:', selectedUserGroups, 'preserved:', groupsNotOwned, 'combined:', groups);
            }

            // Non-admin users must select at least one of their own groups
            if (!isAdmin) {
                const selectedOptions = Array.from(document.getElementById('editClusterGroups').selectedOptions);
                if (selectedOptions.length === 0) {
                    alert('You must assign at least one of your groups to the cluster');
                    return;
                }
            }

            const submitBtn = e.submitter;
            setButtonLoading(submitBtn, true, 'Saving…');

            fetch(`/api/clusters/${editClusterData.name}/groups`, {
                method: 'PUT',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    namespace: editClusterData.namespace,
                    groups: groups
                })
            })
            .then(response => {
                if (response.ok) {
                    closeEditGroupsModal();
                    loadClusters(); // Refresh clusters
                } else {
                    throw new Error('Failed to update groups');
                }
            })
            .catch(error => {
                console.error('Error updating groups:', error);
                alert('Failed to update groups');
            })
            .finally(() => {
                setButtonLoading(submitBtn, false);
            });
        });

        document.getElementById('editWorkerGroupsForm').addEventListener('submit', function(e) {
            e.preventDefault();

            if (!editNodesData) return;

            const workerGroups = collectWorkerGroups('edit');
            if (workerGroups.length === 0) {
                alert('At least one worker group is required');
                return;
            }

            const submitBtn = e.submitter;
            setButtonLoading(submitBtn, true, 'Saving…');

            fetch(`/api/clusters/${editNodesData.name}/worker-groups`, {
                method: 'PUT',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    namespace: editNodesData.namespace,
                    workerGroups: workerGroups
                })
            })
            .then(response => {
                if (response.ok) {
                    closeEditWorkerGroupsModal();
                    loadClusters(); // Refresh clusters
                } else {
                    return response.json().then(data => {
                        throw new Error(data.error || 'Failed to update worker groups');
                    });
                }
            })
            .catch(error => {
                console.error('Error updating worker groups:', error);
                alert('Failed to update worker groups: ' + error.message);
            })
            .finally(() => {
                setButtonLoading(submitBtn, false);
            });
        });

        document.getElementById('editControlPlaneForm').addEventListener('submit', function(e) {
            e.preventDefault();

            if (!editControlPlaneData) return;

            const replicas = parseInt(document.getElementById('editClusterControlPlane').value);

            if (isNaN(replicas) || replicas < 1) {
                alert('Control plane replicas must be at least 1');
                return;
            }

            const submitBtn = e.submitter;
            setButtonLoading(submitBtn, true, 'Saving…');

            fetch(`/api/clusters/${editControlPlaneData.name}/control-plane`, {
                method: 'PUT',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    namespace: editControlPlaneData.namespace,
                    controlPlaneReplicas: replicas
                })
            })
            .then(response => {
                if (response.ok) {
                    closeEditControlPlaneModal();
                    loadClusters();
                } else {
                    return response.json().then(data => {
                        throw new Error(data.error || 'Failed to update control plane replicas');
                    });
                }
            })
            .catch(error => {
                console.error('Error updating control plane replicas:', error);
                alert('Failed to update control plane replicas: ' + error.message);
            })
            .finally(() => {
                setButtonLoading(submitBtn, false);
            });
        });

        document.getElementById('editVersionForm').addEventListener('submit', function(e) {
            e.preventDefault();

            if (!editVersionData) return;

            const newVersion = document.getElementById('editClusterVersion').value;

            if (!newVersion) {
                alert('Please select a version to upgrade to');
                return;
            }

            // Double-check that the selected version is newer
            if (compareVersions(newVersion, editVersionData.currentVersion) <= 0) {
                alert('Selected version must be newer than the current version');
                return;
            }

            const submitBtn = e.submitter;
            setButtonLoading(submitBtn, true, 'Upgrading…');

            fetch(`/api/clusters/${editVersionData.name}/version`, {
                method: 'PUT',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    namespace: editVersionData.namespace,
                    version: newVersion
                })
            })
            .then(response => {
                if (response.ok) {
                    closeEditVersionModal();
                    loadClusters(); // Refresh clusters
                } else {
                    return response.json().then(data => {
                        throw new Error(data.error || 'Failed to update cluster version');
                    });
                }
            })
            .catch(error => {
                console.error('Error updating version:', error);
                alert('Failed to update cluster version: ' + error.message);
            })
            .finally(() => {
                setButtonLoading(submitBtn, false);
            });
        });

        document.getElementById('editParameterForm').addEventListener('submit', function(e) {
            e.preventDefault();
            if (!editParameterData) return;

            const input = document.getElementById('editParameterInput');
            let value;
            if (editParameterData.type === 'boolean') {
                value = input.checked ? 'true' : 'false';
            } else {
                value = input.value;
            }

            const submitBtn = e.submitter;
            setButtonLoading(submitBtn, true, 'Saving…');

            const url = `/api/clusters/${encodeURIComponent(editParameterData.name)}/parameter`
                + `?namespace=${encodeURIComponent(editParameterData.namespace)}`;
            fetch(url, {
                method: 'PUT',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    namespace: editParameterData.namespace,
                    key: editParameterData.key,
                    value: value
                })
            })
            .then(response => {
                if (response.ok) {
                    closeEditParameterModal();
                    loadClusters();
                } else {
                    return response.json().then(data => {
                        throw new Error(data.error || 'Failed to update parameter');
                    });
                }
            })
            .catch(error => {
                console.error('Error updating parameter:', error);
                alert('Failed to update parameter: ' + error.message);
            })
            .finally(() => {
                setButtonLoading(submitBtn, false);
            });
        });

        function confirmDelete(btn) {
            if (!deleteClusterData) return;

            setButtonLoading(btn, true, 'Deleting…');

            fetch(`/api/clusters/${deleteClusterData.name}`, {
                method: 'DELETE',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ namespace: deleteClusterData.namespace })
            })
            .then(response => {
                if (response.ok) {
                    closeDeleteModal();
                    loadClusters(); // Refresh clusters
                } else {
                    throw new Error('Failed to delete cluster');
                }
            })
            .catch(error => {
                console.error('Error deleting cluster:', error);
                alert('Failed to delete cluster');
            })
            .finally(() => {
                setButtonLoading(btn, false);
            });
        }

        // Close modals when clicking outside
        document.querySelectorAll('.modal-overlay').forEach(overlay => {
            overlay.addEventListener('click', function(e) {
                if (e.target === overlay) {
                    overlay.style.display = 'none';
                }
            });
        });
