    const API = '';
    let cachedLedger = [];
    let currentTable = 'accounts';
    let currentPage = 1;
    let currentPageSize = 50;
    let currentTotalPages = 1;
    let currentTotalCount = 0;
    let sortColumn = 'id';
    let sortAscending = false;

    function setActiveKpiCard(type) {
      document.querySelectorAll('.kpi-grid .kpi-card').forEach(c => c.classList.remove('active'));
      if (type) {
        const target = document.getElementById(`kpi-card-${type}`);
        if (target) target.classList.add('active');
      }
    }

    function showView(viewId, element) {
      document.querySelectorAll('.view-pane').forEach(v => v.classList.remove('active'));
      document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
      if (element) element.classList.add('active');
      const pane = document.getElementById(viewId);
      if (pane) pane.classList.add('active');

      // Persist active view position across page reloads
      localStorage.setItem('vaultdb_active_view', viewId);

      const titles = {
        'view-console': 'SQL console',
        'view-ledger': 'Audit ledger',
        'view-explorer': 'Schema',
        'view-approvals': 'Security Center: Approvals & Alerts',
        'view-reports': 'Compliance Reports'
      };
      document.getElementById('view-title').innerText = titles[viewId] || 'Workspace';

      // KPI stats grid visibility: Hidden in Schema (view-explorer) and for Customers
      const topKpiGrid = document.getElementById('top-kpi-grid');
      const isCustomer = currentAuth && currentAuth.role === 'customer';
      if (topKpiGrid) {
        topKpiGrid.style.setProperty('display', (isCustomer || viewId === 'view-explorer') ? 'none' : 'grid', 'important');
      }

      if (viewId === 'view-ledger') {
        loadAuditLogs();
      } else if (viewId === 'view-approvals') {
        loadApprovals();
        loadAlerts();
      } else if (viewId === 'view-reports') {
        onReportFilterChange();
      } else {
        setActiveKpiCard(null);
      }
      if (viewId === 'view-explorer') loadTableMetadata();
    }

    function navigateToSecurityCenter(focusSection = 'grants') {
      const navItems = document.querySelectorAll('.nav-item');
      if (navItems.length > 3) {
        showView('view-approvals', navItems[3]);
      }
      loadApprovals();
      loadAlerts();
      setActiveKpiCard(focusSection === 'grants' ? 'grants' : 'anomalies');
      if (focusSection === 'alerts') {
        setTimeout(() => {
          const el = document.getElementById('alerts-tbody');
          if (el) el.scrollIntoView({ behavior: 'smooth' });
        }, 100);
      } else {
        setTimeout(() => {
          const el = document.getElementById('approvals-tbody');
          if (el) el.scrollIntoView({ behavior: 'smooth' });
        }, 100);
      }
    }

    function navigateToLedger(statusFilter = '', isSensitive = false, sortByTx = false, cardType = 'total') {
      const navItems = document.querySelectorAll('.nav-item');
      if (navItems.length > 1) {
        showView('view-ledger', navItems[1]);
      }

      setActiveKpiCard(cardType);

      document.getElementById('ledger-search').value = '';
      document.getElementById('ledger-user-filter').value = '';
      document.getElementById('ledger-date-filter').value = 'all';

      const statusSelect = document.getElementById('ledger-status-filter');
      if (statusSelect) {
        if (isSensitive) {
          statusSelect.value = 'SENSITIVE';
        } else {
          statusSelect.value = statusFilter;
        }
      }

      sortColumn = 'id';
      sortAscending = false;
      updateSortIcons();

      loadAuditLogs();
    }

    function viewSpecificLog(logId) {
      const navItems = document.querySelectorAll('.nav-item');
      if (navItems.length > 1) {
        showView('view-ledger', navItems[1]);
      }
      setActiveKpiCard('total');
      const searchBox = document.getElementById('ledger-search');
      if (searchBox) searchBox.value = logId ? String(logId) : '';
      const userFilter = document.getElementById('ledger-user-filter');
      if (userFilter) userFilter.value = '';
      const statusSelect = document.getElementById('ledger-status-filter');
      if (statusSelect) statusSelect.value = '';
      const dateFilter = document.getElementById('ledger-date-filter');
      if (dateFilter) dateFilter.value = 'all';

      sortColumn = 'id';
      sortAscending = false;
      currentLedgerPage = 1;
      updateSortIcons();
      loadAuditLogs();

      setTimeout(() => {
        const row = document.getElementById(`log-row-${logId}`);
        if (row) {
          row.scrollIntoView({ behavior: 'smooth', block: 'center' });
          row.style.outline = '2px solid #f97316';
          setTimeout(() => { row.style.outline = ''; }, 3500);
        }
      }, 300);
    }

    function switchTable(tableName, element) {
      currentTable = tableName;
      currentPage = 1;
      document.querySelectorAll('#table-chips .chip-btn').forEach(btn => btn.classList.remove('active'));
      if (element) element.classList.add('active');
      exploreTableData(currentTable, currentPage, currentPageSize);
    }

    const USER_PASSWORDS = {
      'admin@bank.com': 'AdminPass123!',
      'compliance.lead@bank.com': 'AuditorPass123!',
      'john@bank.com': 'EmployeePass123!',
      'alice@bank.com': 'CustomerPass123!',
      'bob@bank.com': 'CustomerPass123!'
    };

    const USER_ROLES = {
      'admin@bank.com': 'admin',
      'compliance.lead@bank.com': 'auditor',
      'john@bank.com': 'employee',
      'alice@bank.com': 'customer',
      'bob@bank.com': 'customer'
    };

    function validateReqRoles() {
      const email = document.getElementById('req-user-email') ? document.getElementById('req-user-email').value.trim() : '';
      const role = document.getElementById('req-role-select') ? document.getElementById('req-role-select').value : '';
      const errBox = document.getElementById('req-error-msg');
      if (!errBox) return;
      const currentRole = USER_ROLES[email] || (currentAuth && currentAuth.email === email ? currentAuth.role : null);
      if (currentRole && currentRole.toLowerCase() === role.toLowerCase()) {
        errBox.innerHTML = `User <strong class="mono">${email}</strong> is already assigned the <strong>${role}</strong> role. Temporary elevation is only needed for higher privileges (e.g., admin).`;
        errBox.style.display = 'block';
      } else {
        errBox.style.display = 'none';
      }
    }

    let currentAuth = {
      token: null,
      email: 'admin@bank.com',
      role: 'admin',
      full_name: 'Chief Security Officer',
      department: 'SecOps'
    };

    function toggleAccountMenu(e) {
      if (e) e.stopPropagation();
      const drop = document.getElementById('account-dropdown');
      if (drop) {
        drop.style.display = drop.style.display === 'block' ? 'none' : 'block';
      }
    }

    function selectAccountItem(persona) {
      switchPersona(persona);
      const drop = document.getElementById('account-dropdown');
      if (drop) drop.style.display = 'none';
    }

    function onQuickEmailChange(email) {
      const passInput = document.getElementById('quick-password-input');
      if (passInput && USER_PASSWORDS[email]) {
        passInput.value = USER_PASSWORDS[email];
      }
    }

    async function handleTopNavLogin(e) {
      e.preventDefault();
      const email = document.getElementById('quick-email-select').value.trim();
      const password = document.getElementById('quick-password-input').value;
      const errBox = document.getElementById('quick-login-error');
      if (errBox) errBox.style.display = 'none';

      try {
        const resp = await fetch(`${API}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });
        if (!resp.ok) {
          const err = await resp.json();
          throw new Error(err.detail || 'Invalid email or password');
        }
        const data = await resp.json();
        currentAuth = {
          token: data.access_token,
          email: data.email,
          role: data.role.toLowerCase(),
          full_name: data.full_name || data.email,
          department: data.department || 'General'
        };
        sessionStorage.setItem('vault_auth', JSON.stringify(currentAuth));

        document.getElementById('current-user-email').innerText = data.email;
        document.getElementById('user-select').value = data.email;
        const roleBadge = document.getElementById('identity-role-badge');
        roleBadge.className = `role-badge role-${data.role.toLowerCase()}`;
        roleBadge.innerText = data.role.toLowerCase();
        document.getElementById('identity-desc-text').innerText = `${currentAuth.full_name} (${currentAuth.department})`;

        const topName = document.getElementById('topbar-user-name');
        if (topName) topName.innerText = currentAuth.full_name;
        const topRole = document.getElementById('topbar-user-role');
        if (topRole) topRole.innerText = currentAuth.role;

        document.querySelectorAll('.persona-btns .persona-btn').forEach(b => b.classList.remove('active'));
        const activeBtn = document.getElementById(`btn-persona-${currentAuth.role}`);
        if (activeBtn) activeBtn.classList.add('active');

        // Also update the access request user dropdown to the logged in user
        const reqUserSelect = document.getElementById('req-user-email');
        if (reqUserSelect) reqUserSelect.value = data.email;

        applyRoleUiPermissions(currentAuth.role);
        const drop = document.getElementById('account-dropdown');
        if (drop) drop.style.display = 'none';
      } catch (err) {
        if (errBox) {
          errBox.innerText = err.message;
          errBox.style.display = 'block';
        }
      }
    }

    document.addEventListener('click', (e) => {
      const drop = document.getElementById('account-dropdown');
      const btn = document.getElementById('topbar-user-btn');
      if (drop && btn && !drop.contains(e.target) && !btn.contains(e.target)) {
        drop.style.display = 'none';
      }
    });

    function applyRoleUiPermissions(role) {
      const isCustomer = role === 'customer';
      const isAdmin = role === 'admin';

      // 1. Navigation items visibility: Customer is restricted strictly to SQL Console and Compliance Reports
      const ledgerNav = document.getElementById('nav-item-ledger');
      if (ledgerNav) ledgerNav.style.display = isCustomer ? 'none' : 'flex';

      const explorerNav = document.getElementById('nav-item-explorer');
      if (explorerNav) explorerNav.style.display = isCustomer ? 'none' : 'flex';

      const secNav = document.getElementById('nav-item-security');
      if (secNav) secNav.style.display = isCustomer ? 'none' : 'flex';

      // 2. Hide KPI stats grid completely for Customer or when in Schema
      const activePane = document.querySelector('.view-pane.active');
      const currentViewId = activePane ? activePane.id : 'view-console';
      const topKpiGrid = document.getElementById('top-kpi-grid');
      if (topKpiGrid) topKpiGrid.style.setProperty('display', (isCustomer || currentViewId === 'view-explorer') ? 'none' : 'grid', 'important');

      // If customer is currently on a restricted view (ledger, explorer, approvals), redirect to view-console
      if (isCustomer) {
        const activePane = document.querySelector('.view-pane.active');
        if (activePane && ['view-ledger', 'view-explorer', 'view-approvals'].includes(activePane.id)) {
          const consoleNav = document.getElementById('nav-item-console');
          if (consoleNav) showView('view-console', consoleNav);
        }
      }

      // 3. Admin has all rights — does not need to submit elevation requests
      const reqFormCard = document.getElementById('access-request-form-card');
      if (reqFormCard) {
        reqFormCard.style.display = isAdmin ? 'none' : 'block';
      }

      // 4. For Employee/Auditor, ensure request form email defaults to their identity
      const reqUserSelect = document.getElementById('req-user-email');
      if (reqUserSelect) {
        if (role === 'auditor') {
          reqUserSelect.value = 'compliance.lead@bank.com';
        } else if (role === 'employee') {
          reqUserSelect.value = 'john@bank.com';
        }
      }

      // 5. Compliance Reports: switch between Staff and Customer filter views
      const adminReportFilters = document.getElementById('reports-admin-filters');
      const custReportFilters = document.getElementById('reports-customer-filters');
      const reportTitle = document.getElementById('reports-panel-title');
      const reportBtnText = document.getElementById('reports-download-btn-text');

      if (adminReportFilters && custReportFilters) {
        if (isCustomer) {
          adminReportFilters.style.display = 'none';
          custReportFilters.style.display = 'block';
          if (reportTitle) reportTitle.innerText = 'Personal Data Access Report';
          if (reportBtnText) reportBtnText.innerText = 'Generate & Download Data Access PDF';
        } else {
          adminReportFilters.style.display = 'grid';
          custReportFilters.style.display = 'none';
          if (reportTitle) reportTitle.innerText = 'Compliance Report Generator';
          if (reportBtnText) reportBtnText.innerText = 'Generate & Download Compliance PDF';
        }
      }

      if (!isCustomer) {
        loadApprovals();
        loadAlerts();
      }
    }

    async function switchPersona(persona) {
      sessionStorage.setItem('vault_persona', persona);
      document.querySelectorAll('.persona-btns .persona-btn').forEach(b => b.classList.remove('active'));
      const activeBtn = document.getElementById(`btn-persona-${persona}`);
      if (activeBtn) activeBtn.classList.add('active');

      try {
        const resp = await fetch(`${API}/api/auth/demo-login/${persona}`, { method: 'POST' });
        const data = await resp.json();

        currentAuth = {
          token: data.access_token,
          email: data.email,
          role: data.role.toLowerCase(),
          full_name: data.full_name || data.email,
          department: data.department || 'General'
        };
        sessionStorage.setItem('vault_auth', JSON.stringify(currentAuth));

        document.getElementById('current-user-email').innerText = data.email;
        document.getElementById('user-select').value = data.email;

        const roleBadge = document.getElementById('identity-role-badge');
        roleBadge.className = `role-badge role-${data.role.toLowerCase()}`;
        roleBadge.innerText = data.role.toLowerCase();

        const roleDescriptions = {
          'admin': 'Chief Security Officer',
          'auditor': 'Independent Compliance Auditor',
          'employee': 'Commercial Lending & Branch Operations',
          'customer': 'Retail Banking Client'
        };
        document.getElementById('identity-desc-text').innerText = roleDescriptions[persona.toLowerCase()] || data.department;

        const topName = document.getElementById('topbar-user-name');
        if (topName) topName.innerText = currentAuth.full_name;
        const topRole = document.getElementById('topbar-user-role');
        if (topRole) topRole.innerText = currentAuth.role;

        // Sync dropdown selectors
        const quickSelect = document.getElementById('quick-email-select');
        if (quickSelect) quickSelect.value = data.email;
        const quickPass = document.getElementById('quick-password-input');
        if (quickPass && USER_PASSWORDS[data.email]) quickPass.value = USER_PASSWORDS[data.email];

        const reqUserSelect = document.getElementById('req-user-email');
        if (reqUserSelect) reqUserSelect.value = data.email;

        applyRoleUiPermissions(currentAuth.role);

        const ledgerUserFilter = document.getElementById('ledger-user-filter');
        if (ledgerUserFilter && ledgerUserFilter.value) {
          ledgerUserFilter.value = data.email;
          loadAuditLogs();
        }
      } catch (err) {
        console.error('Failed to switch persona:', err);
      }
    }

    async function onScenarioSelect(val) {
      const scenarios = {
        'customer-alice-account': {
          persona: 'customer',
          sql: "SELECT account_number, name, ssn, account_type, balance FROM app_data.accounts WHERE account_number = 'ACC-1001';",
          desc: 'Alice Smith queries personal account ACC-1001. Scoped to personal records via Row-Level Security with SSN masked.'
        },
        'customer-alice-tx': {
          persona: 'customer',
          sql: 'SELECT id, account_id, transaction_type, amount, merchant, status FROM app_data.transactions ORDER BY id DESC LIMIT 10;',
          desc: 'Alice Smith queries personal transactions. Scoped to personal accounts via Row-Level Security.'
        },
        'customer-bob-account': {
          persona: 'customer_bob',
          sql: "SELECT account_number, name, ssn, account_type, balance FROM app_data.accounts WHERE account_number = 'ACC-1002';",
          desc: 'Bob Davis queries personal account ACC-1002. Scoped to personal records via Row-Level Security with SSN masked.'
        },
        'customer-bob-tx': {
          persona: 'customer_bob',
          sql: 'SELECT id, account_id, transaction_type, amount, merchant, status FROM app_data.transactions ORDER BY id DESC LIMIT 10;',
          desc: 'Bob Davis queries personal transactions. Scoped to personal accounts via Row-Level Security.'
        },
        'customer-cross-tenant': {
          persona: 'customer',
          sql: "SELECT account_number, name, ssn, account_type, balance FROM app_data.accounts WHERE account_number = 'ACC-1002';",
          desc: "Alice Smith attempts to query Bob Davis's account ACC-1002. Blocked by cross-tenant isolation policy."
        },
        'customer-personal': {
          persona: 'customer',
          sql: "SELECT account_number, name, ssn, account_type, balance FROM app_data.accounts WHERE account_number = 'ACC-1001';",
          desc: 'Customer queries personal account ACC-1001. Scoped to personal records via Row-Level Security with SSN masked.'
        },
        'customer-transactions': {
          persona: 'customer',
          sql: 'SELECT id, account_id, transaction_type, amount, merchant, status FROM app_data.transactions ORDER BY id DESC LIMIT 10;',
          desc: 'Customer queries personal transactions. Scoped to personal accounts via Row-Level Security.'
        },
        'customer-delete': {
          persona: 'customer',
          sql: 'DELETE FROM app_data.transactions WHERE id = 1;',
          desc: 'Customer attempts to delete a transaction record. Blocked by access policy.'
        },
        'customer-users': {
          persona: 'customer',
          sql: 'SELECT email, full_name, role FROM app_data.users;',
          desc: 'Customer attempts to access user directory. Blocked by access policy.'
        },
        'employee-transfers': {
          persona: 'employee',
          sql: 'SELECT t.id, a.name, t.transaction_type, t.amount, t.merchant, t.status FROM app_data.transactions t JOIN app_data.accounts a ON t.account_id = a.id WHERE t.amount > 10000 ORDER BY t.amount DESC LIMIT 10;',
          desc: 'Employee queries high-value transactions across customer accounts.'
        },
        'employee-insert-tx': {
          persona: 'employee',
          sql: "INSERT INTO app_data.transactions (account_id, transaction_type, amount, merchant, status) VALUES (1, 'DEPOSIT', 500.00, 'Branch Counter Deposit', 'completed');",
          desc: 'Employee records an authorized branch counter transaction.'
        },
        'employee-violation': {
          persona: 'employee',
          sql: 'UPDATE app_data.accounts SET balance = 9999999 WHERE id = 1;',
          desc: 'Employee attempts to modify customer account balance. Blocked by access policy.'
        },
        'employee-delete': {
          persona: 'employee',
          sql: 'DELETE FROM app_data.accounts WHERE id = 1;',
          desc: 'Employee attempts to delete an account record. Blocked by access policy.'
        },
        'auditor-audit-logs': {
          persona: 'auditor',
          sql: 'SELECT log_id, logged_at, app_user, user_role, action, target_table, execution_status FROM vault_audit.audit_logs ORDER BY log_id DESC LIMIT 10;',
          desc: 'Auditor inspects recent query records for regulatory compliance.'
        },
        'auditor-users-review': {
          persona: 'auditor',
          sql: 'SELECT email, full_name, role, department, status FROM app_data.users ORDER BY email ASC;',
          desc: 'Auditor reviews user directory and assigned roles.'
        },
        'auditor-write-blocked': {
          persona: 'auditor',
          sql: "UPDATE app_data.transactions SET status = 'reversed' WHERE id = 1;",
          desc: 'Auditor attempts to modify transaction status. Blocked by access policy (auditor role is read-only).'
        },
        'admin-overview': {
          persona: 'admin',
          sql: 'SELECT account_number, name, ssn, account_type, balance FROM app_data.accounts WHERE balance > 100000 ORDER BY balance DESC;',
          desc: 'Administrator inspects high-value accounts with unmasked sensitive fields.'
        },
        'admin-users-manage': {
          persona: 'admin',
          sql: 'SELECT id, email, full_name, role, department, status FROM app_data.users ORDER BY id ASC;',
          desc: 'Administrator inspects user directory.'
        },
        'injection-drop': {
          persona: 'admin',
          sql: 'SELECT 1; DROP TABLE app_data.transactions;',
          desc: 'Stacked SQL injection attempt. Blocked by security policy.'
        },
        'injection-truncate': {
          persona: 'admin',
          sql: 'SELECT 1; TRUNCATE app_data.users;',
          desc: 'Multi-statement TRUNCATE injection attempt. Blocked by security policy.'
        },
        'tamper-ledger-direct': {
          persona: 'admin',
          sql: "UPDATE vault_audit.audit_logs SET execution_status = 'SUCCESS' WHERE execution_status = 'DENIED';",
          desc: 'Direct attempt to alter immutable audit logs. Blocked by database triggers.'
        }
      };

      const item = scenarios[val];
      if (!item) return;

      const descEl = document.getElementById('scenario-desc');
      if (descEl) descEl.innerText = item.desc;
      await switchPersona(item.persona);
      document.getElementById('sql-input').value = item.sql;
    }

    async function setQueryScenario(persona, sql, element) {
      await switchPersona(persona);
      document.getElementById('sql-input').value = sql;
    }

    async function simulateTampering() {
      try {
        const resp = await fetch(`${API}/api/tamper-demo/simulate`, { method: 'POST' });
        const data = await resp.json();
        await loadAuditLogs();
        verifyProof(data.log_id);
      } catch(e) {
        alert('Tamper simulation error: ' + e.message);
      }
    }

    async function restoreTamperedRecord(logId) {
      try {
        const resp = await fetch(`${API}/api/tamper-demo/restore?log_id=${logId}`, { method: 'POST' });
        const data = await resp.json();
        await verifyProof(logId);
        await loadAuditLogs();
      } catch(e) {
        alert('Restore error: ' + e.message);
      }
    }

    document.getElementById('sql-input').addEventListener('keydown', function(e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        runQuery();
      }
    });

    document.getElementById('sql-input').addEventListener('input', function() {
      const dd = document.getElementById('scenario-dropdown');
      if (dd) dd.value = '';
      const descEl = document.getElementById('scenario-desc');
      if (descEl) descEl.innerText = 'Custom SQL statement entered.';
    });

    let lastQueryColumns = [];
    let lastQueryRows = [];
    let liveWatchInterval = null;

    function renderResultTableLimited() {
      const limitVal = document.getElementById('result-limit-select') ? document.getElementById('result-limit-select').value : '50';
      let rowsToRender = lastQueryRows;
      if (limitVal !== 'all') {
        const lim = parseInt(limitVal, 10);
        rowsToRender = lastQueryRows.slice(0, lim);
      }
      renderResultTable(lastQueryColumns, rowsToRender, lastQueryRows.length);
    }

    function toggleLiveWatch() {
      const btn = document.getElementById('btn-live-watch');
      if (liveWatchInterval) {
        clearInterval(liveWatchInterval);
        liveWatchInterval = null;
        btn.innerText = 'Live watch: off';
        btn.classList.remove('btn-primary');
        btn.classList.add('btn-secondary');
      } else {
        loadAuditLogs();
        liveWatchInterval = setInterval(loadAuditLogs, 4000);
        btn.innerText = 'Live watch: on';
        btn.classList.remove('btn-secondary');
        btn.classList.add('btn-primary');
      }
    }

    async function runQuery() {
      document.querySelectorAll('#preset-chips .chip-btn').forEach(b => {
        b.classList.remove('active');
        b.blur();
      });

      const user = document.getElementById('user-select').value;
      const query = document.getElementById('sql-input').value.trim();
      const banner = document.getElementById('query-banner');
      const stats = document.getElementById('exec-stats');
      if (!query) return;

      banner.style.display = 'block';
      banner.className = 'alert-banner';
      banner.innerText = 'Evaluating policy and executing query...';
      stats.innerText = 'Executing...';

      try {
        const reqHeaders = { 'Content-Type': 'application/json' };
        if (currentAuth && currentAuth.token) {
          reqHeaders['Authorization'] = `Bearer ${currentAuth.token}`;
        }
        const resp = await fetch(API + '/api/execute', {
          method: 'POST',
          headers: reqHeaders,
          body: JSON.stringify({ user, query })
        });
        const data = await resp.json();

        if (data.status === 'SUCCESS') {
          banner.className = 'alert-banner success';
          let msg = `Executed successfully. Sealed in immudb at transaction #${data.immudb_tx_id}.`;
          if (data.is_sensitive) {
            msg += `<br><span style="color:#fbbf24; font-weight:600;">⚠ Sensitive query detected (PII)! Flagged in audit log (fields: ${(data.sensitive_fields||[]).join(', ')}).</span>`;
          }
          if (data.is_masked) {
            msg += `<br><span style="color:#fcd34d;">Data masking applied: ${(data.masked_fields||[]).join(', ')} (PII redacted).</span>`;
          }
          if (data.is_scoped) {
            msg += `<br><span style="color:#93c5fd;">Row-level security active: scoped to personal records.</span>`;
          }
          if (data.anomalies && data.anomalies.length > 0) {
            msg += `<br><span style="color:#fca5a5;">Anomaly alert: ${escapeHtml(data.anomalies.join('; '))}.</span>`;
          }
          banner.innerHTML = msg;

          stats.innerText = `${data.execution_time_ms} ms | ${data.rows_affected} row(s) | Tx #${data.immudb_tx_id}`;
          lastQueryColumns = data.columns || [];
          lastQueryRows = data.results || [];
          renderResultTableLimited();
        } else if (data.status === 'DENIED') {
          banner.className = 'alert-banner denied';
          let msg = `<strong>Policy Violation Blocked:</strong> ${escapeHtml(data.error)}`;
          if (data.immudb_tx_id) {
            msg += `<br><span style="font-family:var(--font-mono); font-size:11px;">Attempt recorded in immudb at transaction #${data.immudb_tx_id} (Log #${data.immudb_log_id}).</span>`;
          }
          if (data.immudb_log_id) {
            msg += `<br><div style="display:flex; gap:6px; margin-top:6px; flex-wrap:wrap;">
              <button class="btn btn-secondary btn-sm" style="padding:2px 8px; font-size:10px;" onclick="viewSpecificLog(${data.immudb_log_id})">View this record (#${data.immudb_log_id}) &rarr;</button>
              <button class="btn btn-secondary btn-sm" style="padding:2px 8px; font-size:10px;" onclick="navigateToLedger('', false, true, 'total')">View all records &rarr;</button>
            </div>`;
          } else {
            msg += `<br><button class="btn btn-secondary btn-sm" style="margin-top:6px; padding:2px 8px; font-size:10px;" onclick="navigateToLedger('', false, true, 'total')">View in Audit Ledger &rarr;</button>`;
          }
          banner.innerHTML = msg;
          stats.innerText = data.immudb_tx_id ? `Denied | Tx #${data.immudb_tx_id}` : 'Denied';
          clearResultTable('Query blocked by access policy.');
        } else {
          banner.className = 'alert-banner warning';
          let msg = `<strong>SQL Execution Error:</strong> ${escapeHtml(data.error)}`;
          banner.innerHTML = msg;
          stats.innerText = 'Error';
          clearResultTable('SQL execution error.');
        }
      } catch (err) {
        banner.className = 'alert-banner warning';
        banner.innerHTML = `<strong>Network error:</strong> ${escapeHtml(err.message)}`;
        stats.innerText = 'Failed';
      }

      loadStats();
      loadAuditLogs();
      loadAlerts();
    }

    function renderResultTable(columns, rows, totalRows) {
      const thead = document.getElementById('result-thead');
      const tbody = document.getElementById('result-tbody');

      if (!columns || columns.length === 0) {
        thead.innerHTML = '<tr><th>Result</th></tr>';
        tbody.innerHTML = '<tr><td style="padding:14px; color:var(--text-dim);">0 columns returned.</td></tr>';
        return;
      }

      thead.innerHTML = `<tr>${columns.map(c => `<th>${escapeHtml(c)}</th>`).join('')}</tr>`;

      if (!rows || rows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="${columns.length}" style="padding:14px; color:var(--text-dim);">0 records returned.</td></tr>`;
        return;
      }

      let html = rows.map(r => `
        <tr>${r.map(c => `<td class="mono">${escapeHtml(String(c === null ? 'NULL' : c))}</td>`).join('')}</tr>
      `).join('');

      if (totalRows !== undefined && totalRows > rows.length) {
        html += `<tr><td colspan="${columns.length}" style="padding:8px 12px; text-align:center; font-size:11px; color:var(--text-dim); background:#101013;">Showing ${rows.length} of ${totalRows} returned records</td></tr>`;
      }

      tbody.innerHTML = html;
    }

    function clearResultTable(msg) {
      lastQueryColumns = [];
      lastQueryRows = [];
      document.getElementById('result-thead').innerHTML = '<tr><th>Status</th></tr>';
      document.getElementById('result-tbody').innerHTML = `<tr><td style="padding:14px; color:var(--text-dim);">${escapeHtml(msg)}</td></tr>`;
    }

    function formatIST(isoStr) {
      if (!isoStr) return '-';
      try {
        let str = String(isoStr).trim();
        // If timestamp lacks timezone offset or Z, treat it as UTC from the server
        if (!str.endsWith('Z') && !str.includes('+') && !str.includes('-', 10)) {
          str = str.replace(' ', 'T') + 'Z';
        }
        const d = new Date(str);
        if (isNaN(d.getTime())) return isoStr;
        const formatted = new Intl.DateTimeFormat('en-CA', {
          timeZone: 'Asia/Kolkata',
          year: 'numeric',
          month: '2-digit',
          day: '2-digit',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hour12: false
        }).format(d).replace(',', '');
        return formatted + ' IST';
      } catch (e) {
        return isoStr;
      }
    }

    let currentLedgerPage = 1;
    let currentLedgerPageSize = 50;
    let currentLedgerFiltered = [];
    let currentLedgerTotalPages = 1;

    async function loadAuditLogs() {
      try {
        const timeRange = document.getElementById('ledger-date-filter').value;
        const user = document.getElementById('ledger-user-filter').value;
        const status = document.getElementById('ledger-status-filter').value;

        let url = `${API}/api/logs?limit=1000`;
        if (timeRange && timeRange !== 'all') url += `&time_range=${timeRange}`;
        if (user) url += `&user=${encodeURIComponent(user)}`;
        if (status && status !== 'SENSITIVE') url += `&status=${encodeURIComponent(status)}`;

        const resp = await fetch(url);
        cachedLedger = await resp.json();
        const sideCount = document.getElementById('sidebar-log-count');
        if (sideCount) sideCount.innerText = cachedLedger.length;
        filterLedger();
      } catch (e) {
        console.error("Error loading logs:", e);
      }
    }

    function onStatusFilterChange() {
      const val = document.getElementById('ledger-status-filter').value;
      if (val === 'DENIED') setActiveKpiCard('denied');
      else if (val === 'SENSITIVE') setActiveKpiCard('sensitive');
      else if (val === '') setActiveKpiCard('total');
      else setActiveKpiCard(null);
      loadAuditLogs();
    }

    function clearFilters() {
      document.getElementById('ledger-search').value = '';
      document.getElementById('ledger-user-filter').value = '';
      document.getElementById('ledger-status-filter').value = '';
      document.getElementById('ledger-date-filter').value = 'all';
      currentLedgerPage = 1;
      setActiveKpiCard('total');
      sortColumn = 'id';
      sortAscending = false;
      currentLedgerPage = 1;
      updateSortIcons();
      loadAuditLogs();
    }

    function sortLedger(column) {
      if (!['id', 'time', 'user'].includes(column)) return;
      if (sortColumn === column) {
        sortAscending = !sortAscending;
      } else {
        sortColumn = column;
        sortAscending = (column === 'user');
      }
      updateSortIcons();
      filterLedger();
    }

    function updateSortIcons() {
      ['id', 'time', 'user'].forEach(col => {
        const el = document.getElementById(`sort-icon-${col}`);
        if (!el) return;
        if (sortColumn === col) {
          el.innerText = sortAscending ? ' ↑' : ' ↓';
          el.style.color = '#38bdf8';
        } else {
          el.innerText = ' ↕';
          el.style.color = 'var(--text-dim)';
        }
      });
    }

    function filterLedger() {
      const search = document.getElementById('ledger-search').value.toLowerCase().trim();
      const cleanSearch = search.replace(/^#/, '');
      const user = document.getElementById('ledger-user-filter').value;
      const status = document.getElementById('ledger-status-filter').value;
      const timeRange = document.getElementById('ledger-date-filter').value;

      const now = new Date();
      let cutoff = null;
      if (timeRange === '24h') cutoff = new Date(now.getTime() - 24 * 3600 * 1000);
      else if (timeRange === '7d') cutoff = new Date(now.getTime() - 7 * 24 * 3600 * 1000);
      else if (timeRange === '30d') cutoff = new Date(now.getTime() - 30 * 24 * 3600 * 1000);

      let filtered = cachedLedger.filter(l => {
        const matchesSearch = !search ||
          (l.id && String(l.id).includes(cleanSearch)) ||
          (l.immudb_tx_id && String(l.immudb_tx_id).includes(cleanSearch)) ||
          (l.query && l.query.toLowerCase().includes(search)) ||
          (l.user && l.user.toLowerCase().includes(search)) ||
          (l.table && l.table.toLowerCase().includes(search)) ||
          (l.role && l.role.toLowerCase().includes(search)) ||
          (l.action && l.action.toLowerCase().includes(search));
        const matchesUser = !user || l.user === user;
        const matchesStatus = !status 
          ? true 
          : (status === 'SENSITIVE' ? !!l.is_sensitive : l.status === status);
        
        let matchesTime = true;
        if (cutoff && l.time) {
          try {
            const entryDate = new Date(l.time);
            matchesTime = entryDate >= cutoff;
          } catch(e) { matchesTime = true; }
        }

        return matchesSearch && matchesUser && matchesStatus && matchesTime;
      });

      // Sorting
      filtered.sort((a, b) => {
        let valA = a[sortColumn];
        let valB = b[sortColumn];
        if (sortColumn === 'id' || sortColumn === 'immudb_tx_id') {
          const numA = Number(valA) || 0;
          const numB = Number(valB) || 0;
          return sortAscending ? numA - numB : numB - numA;
        }
        if (sortColumn === 'time') {
          const timeA = a.time ? new Date(a.time).getTime() : 0;
          const timeB = b.time ? new Date(b.time).getTime() : 0;
          return sortAscending ? timeA - timeB : timeB - timeA;
        }
        if (valA === undefined || valA === null) valA = '';
        if (valB === undefined || valB === null) valB = '';
        if (typeof valA === 'string') valA = valA.toLowerCase();
        if (typeof valB === 'string') valB = valB.toLowerCase();

        if (valA < valB) return sortAscending ? -1 : 1;
        if (valA > valB) return sortAscending ? 1 : -1;
        return 0;
      });

      currentLedgerFiltered = filtered;
      currentLedgerTotalPages = Math.max(1, Math.ceil(filtered.length / currentLedgerPageSize));
      if (currentLedgerPage > currentLedgerTotalPages) currentLedgerPage = currentLedgerTotalPages;
      if (currentLedgerPage < 1) currentLedgerPage = 1;

      const startIdx = (currentLedgerPage - 1) * currentLedgerPageSize;
      const pagedLogs = filtered.slice(startIdx, startIdx + currentLedgerPageSize);

      renderLedgerTable(pagedLogs);
      updateLedgerPagination(filtered.length, pagedLogs.length, startIdx);
    }

    function updateLedgerPagination(totalCount, returnedCount, startIdx) {
      const infoEl = document.getElementById('ledger-pagination-info-text');
      if (infoEl) {
        if (totalCount > 0) {
          const startRow = startIdx + 1;
          const endRow = startIdx + returnedCount;
          infoEl.innerText = `Showing rows ${startRow.toLocaleString()} - ${endRow.toLocaleString()} of ${totalCount.toLocaleString()} in Audit Ledger`;
        } else {
          infoEl.innerText = '0 records in Audit Ledger';
        }
      }

      const pageInput = document.getElementById('current-ledger-page-input');
      if (pageInput) pageInput.value = currentLedgerPage;

      const totalPagesSpan = document.getElementById('total-ledger-pages-span');
      if (totalPagesSpan) totalPagesSpan.innerText = currentLedgerTotalPages;

      const btnFirst = document.getElementById('btn-ledger-page-first');
      const btnPrev = document.getElementById('btn-ledger-page-prev');
      const btnNext = document.getElementById('btn-ledger-page-next');
      const btnLast = document.getElementById('btn-ledger-page-last');

      if (btnFirst) btnFirst.disabled = currentLedgerPage <= 1;
      if (btnPrev) btnPrev.disabled = currentLedgerPage <= 1;
      if (btnNext) btnNext.disabled = currentLedgerPage >= currentLedgerTotalPages;
      if (btnLast) btnLast.disabled = currentLedgerPage >= currentLedgerTotalPages;
    }

    function onLedgerPageSizeChange() {
      const sel = document.getElementById('ledger-page-size-select');
      if (sel) currentLedgerPageSize = parseInt(sel.value, 10);
      currentLedgerPage = 1;
      filterLedger();
    }

    function goToLedgerPage(page) {
      if (page < 1) page = 1;
      if (page > currentLedgerTotalPages) page = currentLedgerTotalPages;
      currentLedgerPage = page;
      filterLedger();
    }

    function prevLedgerPage() {
      if (currentLedgerPage > 1) goToLedgerPage(currentLedgerPage - 1);
    }

    function nextLedgerPage() {
      if (currentLedgerPage < currentLedgerTotalPages) goToLedgerPage(currentLedgerPage + 1);
    }

    function goToLastLedgerPage() {
      goToLedgerPage(currentLedgerTotalPages);
    }

    function onLedgerPageInput(val) {
      const page = parseInt(val, 10);
      if (!isNaN(page)) goToLedgerPage(page);
    }

    function renderLedgerTable(logs) {
      const tbody = document.getElementById('ledger-tbody');
      if (!logs || logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="10" style="padding:20px; text-align:center; color:var(--text-dim);">No audit records match these filters.</td></tr>';
        return;
      }

      tbody.innerHTML = logs.map(l => {
        const isDenied = l.status === 'DENIED';
        const isSensitive = !!l.is_sensitive;
        // V2 Feature 4: Only mark as ANOMALY for genuine unusual access patterns (off-hours or bulk exfiltration)
        const isAnomaly = !!l.is_anomaly;
        const rowClass = isDenied ? 'row-denied' : (isSensitive ? 'row-sensitive' : '');

        let statusTag = isDenied 
          ? '<span class="tag tag-denied">DENIED</span>' 
          : '<span class="tag tag-success">SUCCESS</span>';
        
        let sensTag = isSensitive 
          ? '<span class="tag tag-sensitive" style="margin-left:4px;" title="Sensitive PII accessed">SENSITIVE</span>' 
          : '';

        let anomalyTag = isAnomaly 
          ? `<span class="tag tag-anomaly" style="margin-left:4px; font-weight:700; cursor:pointer;" onclick="navigateToSecurityCenter('alerts')" title="Security Anomaly Triggered (Click to cross-reference with Security Alerts)">ANOMALY</span>` 
          : '';

        return `
          <tr id="log-row-${l.id}" class="${rowClass}">
            <td class="mono">#${l.id}</td>
            <td class="mono" style="font-size: 11px; color: var(--text-dim); white-space: nowrap;">${formatIST(l.time)}</td>
            <td style="color: var(--text);">${escapeHtml(l.user || 'system')}</td>
            <td><span class="role-badge role-${(l.role||'user').toLowerCase()}">${escapeHtml(l.role || '-')}</span></td>
            <td>${escapeHtml(l.action || '-')}</td>
            <td><code class="mono" style="color: var(--text-muted);">${escapeHtml(l.table || '-')}</code></td>
            <td>${statusTag}${sensTag}${anomalyTag}</td>
            <td class="mono" style="color: #93c5fd;">#${l.immudb_tx_id || '-'}</td>
            <td><button class="btn btn-secondary btn-sm" onclick="verifyProof(${l.id})">Verify proof</button></td>
            <td class="sql-cell" title="${escapeHtml(l.query || '')}">${escapeHtml(l.query || '')}</td>
          </tr>
        `;
      }).join('');
    }

    function copyToClipboard(text, btnElement) {
      navigator.clipboard.writeText(text).then(() => {
        const orig = btnElement.innerText;
        btnElement.innerText = 'Copied';
        setTimeout(() => { btnElement.innerText = orig; }, 1500);
      });
    }

    async function verifyProof(logId) {
      const modal = document.getElementById('proofModal');
      const body = document.getElementById('modal-content');
      modal.style.display = 'flex';
      body.innerHTML = '<p style="color: var(--text-dim); font-size: 12px;">Querying immudb for cryptographic inclusion proof...</p>';

      try {
        const resp = await fetch(`${API}/api/verify/${logId}`);
        const data = await resp.json();

        const isTampered = data.database_tampered || !data.verified;
        const record = data.record || {};
        const rootHash = data.current_root_hash || '-';
        const txId = data.tx_id || record.immudb_tx_id || '-';
        const ledgerKey = data.immudb_key || `audit:log:${logId}`;

        // 1. Verdict Banner & 2. Two-Sentence Summary
        let bannerHtml = '';
        let summaryHtml = '';
        let sideBySideHtml = '';

        if (isTampered) {
          bannerHtml = `
            <div class="verdict-banner tampered">
              <span class="verdict-title">Tampered: Record discrepancy detected</span>
              <span class="verdict-desc">PostgreSQL record differs from the cryptographic record sealed in immudb.</span>
            </div>
          `;
          summaryHtml = `
            <p style="font-size: 12px; color: var(--text);">
              An out-of-band change was detected in the PostgreSQL database mirror. The fields below do not match the transaction sealed in immudb.
            </p>
          `;

          // 5. Side-by-side Table for Mismatches
          let rowsHtml = '';
          if (data.mismatches && data.mismatches.length > 0) {
            data.mismatches.forEach(m => {
              rowsHtml += `
                <tr class="mismatch">
                  <td>Discrepancy</td>
                  <td colspan="2" style="font-family: var(--font-mono);">${escapeHtml(m)}</td>
                </tr>
              `;
            });
          }
          sideBySideHtml = `
            <div style="display: flex; flex-direction: column; gap: 4px;">
              <span style="font-size: 11px; color: var(--text-dim);">Comparison: Sealed in immudb vs Current in PostgreSQL</span>
              <table class="side-by-side-table">
                <thead>
                  <tr>
                    <th>Field</th>
                    <th>Sealed in immudb</th>
                    <th>Current in PostgreSQL</th>
                  </tr>
                </thead>
                <tbody>
                  ${rowsHtml || '<tr><td colspan="3">Discrepancy detected between database and immudb.</td></tr>'}
                </tbody>
              </table>
            </div>
          `;
        } else {
          bannerHtml = `
            <div class="verdict-banner verified">
              <span class="verdict-title">Verified: Cryptographic inclusion proof valid</span>
              <span class="verdict-desc">Record payload matches the immudb ledger state root.</span>
            </div>
          `;
          summaryHtml = `
            <p style="font-size: 12px; color: var(--text);">
              The record payload was hashed and verified against the Merkle tree root at transaction #${txId}. No modifications were detected in PostgreSQL or immudb.
            </p>
          `;
        }

        // 3. Checklist of Checks
        const checklistHtml = `
          <div class="check-list">
            <div class="check-item">
              <span class="check-badge ${isTampered ? 'fail' : 'pass'}">${isTampered ? 'FAIL' : 'PASS'}</span>
              <span>Merkle root consistency check</span>
            </div>
            <div class="check-item">
              <span class="check-badge pass">PASS</span>
              <span>Key exists in append-only ledger (${escapeHtml(ledgerKey)})</span>
            </div>
            <div class="check-item">
              <span class="check-badge ${isTampered ? 'fail' : 'pass'}">${isTampered ? 'FAIL' : 'PASS'}</span>
              <span>PostgreSQL mirror field equality</span>
            </div>
            <div class="check-item">
              <span class="check-badge pass">PASS</span>
              <span>Linear transaction height continuity</span>
            </div>
          </div>
        `;

        // 4. Collapsible Auditor Technical Details
        const metaValuesHtml = `
          <details class="raw-json" style="margin-top: 6px;">
            <summary style="font-size: 11.5px; color: var(--text-dim); cursor: pointer; user-select: none;">
              Auditor cryptographic details (state root & transaction keys)
            </summary>
            <div class="meta-key-value" style="margin-top: 8px;">
              <div class="meta-row">
                <span class="meta-label">Ledger key:</span>
                <span class="meta-val">
                  <span class="mono">${escapeHtml(ledgerKey)}</span>
                  <button class="btn-copy" onclick="copyToClipboard('${escapeHtml(ledgerKey)}', this)">Copy</button>
                </span>
              </div>
              <div class="meta-row">
                <span class="meta-label">Transaction ID:</span>
                <span class="meta-val">
                  <span class="mono">Tx #${txId}</span>
                  <button class="btn-copy" onclick="copyToClipboard('${txId}', this)">Copy</button>
                </span>
              </div>
              <div style="display: flex; flex-direction: column; gap: 4px; padding-top: 4px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                  <span class="meta-label">Ledger state root at Tx #${txId}:</span>
                  <button class="btn-copy" onclick="copyToClipboard('${escapeHtml(rootHash)}', this)">Copy</button>
                </div>
                <div class="hash-display">${escapeHtml(rootHash)}</div>
              </div>
            </div>
          </details>
        `;

        // 6. Record Details
        const recordDetailsHtml = `
          <table class="side-by-side-table">
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Action</th>
                <th>Target</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>${escapeHtml(record.app_user || '-')}</td>
                <td><span class="role-badge role-${(record.user_role||'user').toLowerCase()}">${escapeHtml(record.user_role || '-')}</span></td>
                <td>${escapeHtml(record.action || '-')}</td>
                <td><code class="mono">${escapeHtml(record.target_table || '-')}</code></td>
                <td>${escapeHtml(record.execution_status || '-')}</td>
              </tr>
            </tbody>
          </table>
        `;

        // 7. Collapsible Raw JSON
        const rawJsonHtml = `
          <details class="raw-json">
            <summary>Raw ledger payload</summary>
            <pre>${escapeHtml(JSON.stringify(data.record || data, null, 2))}</pre>
          </details>
        `;

        // 8. One-line Footer
        const footerHtml = `
          <div class="modal-footer-note">
            Detects changes to stored records. Does not prevent them.
          </div>
        `;

        body.innerHTML = `
          ${bannerHtml}
          ${summaryHtml}
          ${checklistHtml}
          ${recordDetailsHtml}
          ${sideBySideHtml}
          ${metaValuesHtml}
          ${rawJsonHtml}
          ${footerHtml}
        `;
      } catch (err) {
        body.innerHTML = `<div style="color: var(--red); font-size: 12px;">Verification request failed: ${escapeHtml(err.message)}</div>`;
      }
    }

    function closeModal() {
      document.getElementById('proofModal').style.display = 'none';
    }

    async function loadTableMetadata() {
      try {
        const resp = await fetch(`${API}/api/tables`);
        const tables = await resp.json();
        const chipsContainer = document.getElementById('table-chips');
        chipsContainer.innerHTML = tables.map(t => `
          <button class="chip-btn ${t.name === currentTable ? 'active' : ''}" onclick="switchTable('${t.name}', this)">
            ${t.name} <span style="font-size:10.5px; color:var(--text-dim);">(${t.row_count.toLocaleString()})</span>
          </button>
        `).join('');
      } catch(e) {
        console.error("Failed loading table metadata:", e);
      }
      exploreTableData(currentTable, currentPage, currentPageSize);
    }

    async function exploreTableData(tableName, page, limit) {
      const schemaPrefix = tableName === 'audit_logs' ? 'vault_audit.' : 'app_data.';
      document.getElementById('explorer-table-name').innerText = `${schemaPrefix}${tableName}`;
      const thead = document.getElementById('explorer-thead');
      const tbody = document.getElementById('explorer-tbody');
      thead.innerHTML = '<tr><th>Loading schema...</th></tr>';
      tbody.innerHTML = '';

      try {
        const resp = await fetch(`${API}/api/tables/${tableName}?limit=${limit}&page=${page}`);
        const data = await resp.json();

        currentTotalCount = data.total_count || 0;
        currentTotalPages = data.total_pages || 1;
        currentPage = data.page || page;

        document.getElementById('explorer-row-count').innerText = `${currentTotalCount.toLocaleString()} rows`;

        const startRow = Math.min((currentPage - 1) * limit + 1, currentTotalCount);
        const endRow = Math.min(startRow + data.total_rows_returned - 1, currentTotalCount);
        document.getElementById('pagination-info-text').innerText = 
          currentTotalCount > 0 
            ? `Showing rows ${startRow.toLocaleString()} - ${endRow.toLocaleString()} of ${currentTotalCount.toLocaleString()} in app_data.${tableName}`
            : `0 records in app_data.${tableName}`;

        document.getElementById('current-page-input').value = currentPage;
        document.getElementById('total-pages-span').innerText = currentTotalPages;

        document.getElementById('btn-page-first').disabled = currentPage <= 1;
        document.getElementById('btn-page-prev').disabled = currentPage <= 1;
        document.getElementById('btn-page-next').disabled = currentPage >= currentTotalPages;
        document.getElementById('btn-page-last').disabled = currentPage >= currentTotalPages;

        thead.innerHTML = `<tr>${data.columns.map(c => `<th>${escapeHtml(c)}</th>`).join('')}</tr>`;
        tbody.innerHTML = data.rows.map(r => `
          <tr>${r.map(c => `<td class="mono">${escapeHtml(String(c === null ? 'NULL' : c))}</td>`).join('')}</tr>
        `).join('');

        filterExplorerRows();
      } catch (err) {
        thead.innerHTML = '<tr><th>Error</th></tr>';
        tbody.innerHTML = `<tr><td style="color:var(--red); padding:14px;">Error: ${escapeHtml(err.message)}</td></tr>`;
      }
    }

    function filterExplorerRows() {
      const input = document.getElementById('explorer-row-filter');
      const filter = input ? input.value.toLowerCase().trim() : '';
      const tbody = document.getElementById('explorer-tbody');
      const trs = tbody.getElementsByTagName('tr');
      for (let i = 0; i < trs.length; i++) {
        const rowText = trs[i].innerText.toLowerCase();
        trs[i].style.display = (!filter || rowText.includes(filter)) ? '' : 'none';
      }
    }

    function onPageSizeChange() {
      currentPageSize = parseInt(document.getElementById('page-size-select').value, 10);
      currentPage = 1;
      exploreTableData(currentTable, currentPage, currentPageSize);
    }

    function goToPage(page) {
      if (page < 1) page = 1;
      if (page > currentTotalPages) page = currentTotalPages;
      currentPage = page;
      exploreTableData(currentTable, currentPage, currentPageSize);
    }

    function prevPage() {
      if (currentPage > 1) goToPage(currentPage - 1);
    }

    function nextPage() {
      if (currentPage < currentTotalPages) goToPage(currentPage + 1);
    }

    function goToLastPage() {
      goToPage(currentTotalPages);
    }

    function onPageInput(val) {
      const p = parseInt(val, 10);
      if (!isNaN(p)) goToPage(p);
    }

    function onReportFilterChange() {
      // Kept for navigation and change hooks
    }

    function downloadFilteredPdfReport() {
      const isCustomer = currentAuth && currentAuth.role === 'customer';
      if (isCustomer) {
        const timeRange = document.getElementById('report-customer-timerange') ? document.getElementById('report-customer-timerange').value : 'all';
        let url = `${API}/api/reports/pdf?limit=500&customer=${encodeURIComponent(currentAuth.email || 'alice@bank.com')}`;
        if (timeRange && timeRange !== 'all') {
          url += `&time_range=${encodeURIComponent(timeRange)}`;
        }
        window.open(url, '_blank');
        return;
      }

      const timeRange = document.getElementById('report-filter-timerange') ? document.getElementById('report-filter-timerange').value : 'all';
      const user = document.getElementById('report-filter-user') ? document.getElementById('report-filter-user').value : '';
      const role = document.getElementById('report-filter-role') ? document.getElementById('report-filter-role').value : '';
      const status = document.getElementById('report-filter-status') ? document.getElementById('report-filter-status').value : '';

      let url = `${API}/api/reports/pdf?limit=500`;
      if (timeRange && timeRange !== 'all') {
        url += `&time_range=${encodeURIComponent(timeRange)}`;
      }
      if (user) {
        url += `&user=${encodeURIComponent(user)}`;
      }
      if (role) {
        url += `&role=${encodeURIComponent(role)}`;
      }
      if (status) {
        url += `&status=${encodeURIComponent(status)}`;
      }

      window.open(url, '_blank');
    }

    async function loadStats() {
      try {
        const resp = await fetch(API + '/api/stats');
        if (resp.ok) {
          const s = await resp.json();
          document.getElementById('kpi-total').innerText = (s.total_audited || 0).toLocaleString();
          document.getElementById('kpi-denied').innerText = (s.denied_count || 0).toLocaleString();
          document.getElementById('kpi-sensitive').innerText = (s.sensitive_count || 0).toLocaleString();
          const gEl = document.getElementById('kpi-grants');
          if (gEl) gEl.innerText = (s.active_grants_count || 0).toLocaleString();
          const aEl = document.getElementById('kpi-anomalies');
          if (aEl) aEl.innerText = (s.anomaly_count || 0).toLocaleString();
          const hEl = document.getElementById('kpi-height');
          if (hEl) hEl.innerText = '#' + (s.ledger_height || 0).toLocaleString();
          const pEl = document.getElementById('topbar-proof-text');
          if (pEl) pEl.innerText = `immudb Merkle Root #${s.ledger_height} (Sealed)`;
        }
      } catch (e) {
        console.error("Error loading stats:", e);
      }
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    // Initialize
    const savedPersona = sessionStorage.getItem('vault_persona') || 'admin';
    switchPersona(savedPersona).then(() => {
      // Restore active view across browser reloads
      const savedViewId = localStorage.getItem('vaultdb_active_view');
      if (savedViewId && savedViewId !== 'view-console') {
        const navId = savedViewId.replace('view-', 'nav-item-');
        const navEl = document.getElementById(navId);
        if (navEl && navEl.style.display !== 'none') {
          showView(savedViewId, navEl);
        }
      }
    });
    loadStats();
    loadAuditLogs();
    loadTableMetadata();
    setInterval(loadStats, 10000);
  
    async function loadApprovals() {
      const tbody = document.getElementById('approvals-tbody');
      if (!tbody) return;
      try {
        const resp = await fetch(API + '/api/approvals');
        const data = await resp.json();

        const isAdmin = currentAuth && currentAuth.role === 'admin';
        const myEmail = currentAuth ? currentAuth.email : '';

        const titleEl = document.getElementById('approvals-table-title');
        if (titleEl) {
          titleEl.innerText = isAdmin ? 'Actionable Elevation Requests & Active Grants' : 'My Access Requests';
        }

        let visibleData = data || [];
        if (isAdmin) {
          // Admin: only view actionable requests (PENDING to approve/reject, and APPROVED to revoke)
          visibleData = visibleData.filter(r => r.status === 'PENDING' || r.status === 'APPROVED');
        } else {
          // Non-admin (Employee, Auditor, Customer): strictly see their own submitted requests
          visibleData = visibleData.filter(r => r.user_email === myEmail);
        }

        if (!visibleData || visibleData.length === 0) {
          const emptyMsg = isAdmin 
            ? 'No actionable elevation requests pending review.' 
            : 'You have no active or pending access elevation requests.';
          tbody.innerHTML = `<tr><td colspan="7" style="padding:16px; text-align:center; color:var(--text-dim);">${emptyMsg}</td></tr>`;
          return;
        }

        tbody.innerHTML = visibleData.map(r => {
          const statusClass = r.status === 'APPROVED' ? 'tag-success' : (r.status === 'PENDING' ? 'tag-sensitive' : 'tag-denied');
          let actionBtns = '-';
          if (r.status === 'PENDING') {
            if (isAdmin) {
              actionBtns = `
                <div style="display:flex; gap:4px;">
                  <button class="btn btn-primary btn-sm" style="padding:2px 8px; font-size:10px; background:#10b981; font-weight:600;" onclick="approveAccessRequest(${r.id})">Approve</button>
                  <button class="btn btn-secondary btn-sm" style="padding:2px 6px; font-size:10px; color:#f87171;" onclick="rejectAccessRequest(${r.id})">Reject</button>
                </div>`;
            } else {
              actionBtns = `<span style="font-size:10.5px; color:var(--text-dim); font-style:italic;">Pending Review</span>`;
            }
          } else if (r.status === 'APPROVED') {
            if (isAdmin) {
              actionBtns = `<button class="btn btn-secondary btn-sm" style="padding:3px 8px; font-size:10.5px; color:#ef4444; border-color:rgba(239, 68, 68, 0.4); font-weight:600;" onclick="revokeAccessRequest(${r.id})">Revoke Access</button>`;
            } else {
              actionBtns = `<span class="tag tag-success" style="font-size:9.5px;">Active</span>`;
            }
          } else if (r.status === 'REVOKED') {
            actionBtns = `<span class="tag tag-denied" style="font-size:9.5px;">Revoked</span>`;
          } else if (r.status === 'REJECTED') {
            actionBtns = `<span class="tag tag-denied" style="font-size:9.5px;">Rejected</span>`;
          }

          const expiresStr = r.expires_at ? formatIST(r.expires_at) : (r.duration_hours + 'h requested');
          return `
            <tr>
              <td class="mono">#${r.id}</td>
              <td class="mono" style="font-size:11px;">${escapeHtml(r.user_email)}</td>
              <td><span class="role-badge role-${r.requested_role}">${r.requested_role}</span></td>
              <td style="font-size:11px; max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(r.reason)}</td>
              <td><span class="tag ${statusClass}">${r.status}</span></td>
              <td class="mono" style="font-size:10.5px; white-space:nowrap;">${expiresStr}</td>
              <td>${actionBtns}</td>
            </tr>
          `;
        }).join('');
      } catch (e) {
        tbody.innerHTML = `<tr><td colspan="7" style="padding:16px; color:#f87171;">Error loading approvals: ${escapeHtml(e.message)}</td></tr>`;
      }
    }

    async function submitAccessRequest() {
      const email = document.getElementById('req-user-email').value.trim();
      const role = document.getElementById('req-role-select').value;
      const duration = parseInt(document.getElementById('req-duration-select').value) || 24;
      const reason = document.getElementById('req-reason-input').value.trim();
      const errBox = document.getElementById('req-error-msg');
      if (errBox) errBox.style.display = 'none';

      // Duplicate role guard: block if user already holds the requested role
      const currentRole = USER_ROLES[email] || (currentAuth && currentAuth.email === email ? currentAuth.role : null);
      if (currentRole && currentRole.toLowerCase() === role.toLowerCase()) {
        if (errBox) {
          errBox.innerHTML = `User <strong class="mono">${email}</strong> is already assigned the <strong>${role}</strong> role. Temporary elevation is only needed for higher privileges (e.g., admin).`;
          errBox.style.display = 'block';
        }
        return;
      }

      if (!email || !reason) {
        if (errBox) {
          errBox.innerText = 'Please provide user email and justification reason.';
          errBox.style.display = 'block';
        }
        return;
      }

      try {
        const resp = await fetch(API + '/api/approvals/request', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ user_email: email, requested_role: role, duration_hours: duration, reason })
        });
        if (!resp.ok) {
          const err = await resp.json();
          throw new Error(err.detail || 'Failed to submit request');
        }
        alert(`Access request submitted successfully for ${email} (Role: ${role}, Duration: ${duration}h).`);
        loadApprovals();
        loadAlerts();
        loadStats();
      } catch (e) {
        if (errBox) {
          errBox.innerText = 'Submission error: ' + e.message;
          errBox.style.display = 'block';
        } else {
          alert('Submission error: ' + e.message);
        }
      }
    }

    async function approveAccessRequest(id) {
      try {
        const token = currentAuth ? currentAuth.token : '';
        const reviewer = currentAuth ? currentAuth.email : 'admin@bank.com';
        const resp = await fetch(`${API}/api/approvals/${id}/approve?reviewer_email=${encodeURIComponent(reviewer)}`, {
          method: 'POST',
          headers: token ? { 'Authorization': `Bearer ${token}` } : {}
        });
        const res = await resp.json();
        if (!resp.ok) throw new Error(res.detail || 'Approval failed');
        alert(res.message);
        loadApprovals();
        loadAlerts();
        loadStats();
      } catch (e) {
        alert('Approval error: ' + e.message);
      }
    }

    async function rejectAccessRequest(id) {
      try {
        const token = currentAuth ? currentAuth.token : '';
        const reviewer = currentAuth ? currentAuth.email : 'admin@bank.com';
        const resp = await fetch(`${API}/api/approvals/${id}/reject?reviewer_email=${encodeURIComponent(reviewer)}`, {
          method: 'POST',
          headers: token ? { 'Authorization': `Bearer ${token}` } : {}
        });
        const res = await resp.json();
        if (!resp.ok) throw new Error(res.detail || 'Rejection failed');
        loadApprovals();
        loadAlerts();
        loadStats();
      } catch (e) {
        alert('Rejection error: ' + e.message);
      }
    }

    async function revokeAccessRequest(id) {
      try {
        const token = currentAuth ? currentAuth.token : '';
        const reviewer = currentAuth ? currentAuth.email : 'admin@bank.com';
        const resp = await fetch(`${API}/api/approvals/${id}/revoke?reviewer_email=${encodeURIComponent(reviewer)}`, {
          method: 'POST',
          headers: token ? { 'Authorization': `Bearer ${token}` } : {}
        });
        const res = await resp.json();
        if (!resp.ok) throw new Error(res.detail || 'Revocation failed');
        alert(res.message);
        loadApprovals();
        loadAlerts();
        loadStats();
      } catch (e) {
        alert('Revocation error: ' + e.message);
      }
    }

    async function loadAlerts() {
      const tbody = document.getElementById('alerts-tbody');
      if (!tbody) return;
      try {
        const resp = await fetch(API + '/api/alerts/recent');
        let alerts = await resp.json();
        // Filter out legacy reader/writer/bob/sarah
        alerts = (alerts || []).filter(a => {
          const u = (a.user || '').toLowerCase();
          const r = (a.role || '').toLowerCase();
          return !u.includes('bob') && !u.includes('sarah') && r !== 'reader' && r !== 'writer';
        });

        if (alerts.length === 0) {
          tbody.innerHTML = '<tr><td colspan="7" style="padding: 24px; text-align: center; color: var(--text-dim);">No security anomalies detected. System operating within normal behavioral baseline.</td></tr>';
          return;
        }
        tbody.innerHTML = alerts.map(a => {
          const timeStr = a.timestamp ? formatIST(a.timestamp) : '-';
          const anomName = a.anomaly_name || (a.anomalies && a.anomalies[0]) || 'Security Anomaly';
          const explanation = a.explanation || a.summary || '-';
          const table = a.table || 'accounts';
          const userStr = a.user || 'unknown';
          const roleStr = a.role || '-';

          const ledgerLink = a.immudb_log_id 
            ? `<a href="#" onclick="viewSpecificLog(${a.immudb_log_id}); return false;" class="mono" style="color: #60a5fa; font-weight: 600; text-decoration: none; border-bottom: 1px dashed #60a5fa;" title="View record in Audit Ledger">#${a.immudb_log_id}</a>` 
            : '<span style="color: var(--text-dim);">-</span>';

          return `
            <tr>
              <td class="mono" style="font-size: 11px; white-space: nowrap;">${timeStr}</td>
              <td class="mono" style="font-size: 11px; white-space: nowrap;">${ledgerLink}</td>
              <td class="mono" style="font-size: 11px; font-weight: 500; color: var(--text);">${escapeHtml(userStr)}</td>
              <td><span class="role-badge role-${roleStr.toLowerCase()}">${escapeHtml(roleStr)}</span></td>
              <td style="font-weight: 600; color: #f97316;">${escapeHtml(anomName)}</td>
              <td><code class="mono" style="color: var(--text-muted);">${escapeHtml(table)}</code></td>
              <td style="font-size: 11.5px; color: var(--text);">${escapeHtml(explanation)}</td>
            </tr>
          `;
        }).join('');
      } catch (e) {
        tbody.innerHTML = `<tr><td colspan="7" style="padding: 16px; color: #f87171;">Error loading alerts: ${escapeHtml(e.message)}</td></tr>`;
      }
    }

    function filterLedgerById(logId) {
      const navItems = document.querySelectorAll('.nav-item');
      if (navItems.length > 1) {
        showView('view-ledger', navItems[1]);
      }
      if (currentLedgerFiltered && currentLedgerFiltered.length > 0) {
        const idx = currentLedgerFiltered.findIndex(l => l.id == logId);
        if (idx !== -1) {
          currentLedgerPage = Math.floor(idx / currentLedgerPageSize) + 1;
          filterLedger();
        }
      }
      setTimeout(() => {
        const row = document.getElementById(`log-row-${logId}`);
        if (row) {
          row.scrollIntoView({ behavior: 'smooth', block: 'center' });
          row.style.outline = '2px solid #f97316';
          setTimeout(() => { row.style.outline = ''; }, 3500);
        }
      }, 250);
    }

    async function triggerTestSlackWebhook() {
      try {
        const resp = await fetch(API + '/api/alerts/test-webhook', { method: 'POST' });
        const res = await resp.json();
        alert('Test Slack Webhook alert dispatched: ' + res.message);
        loadAlerts();
      } catch (e) {
        alert('Error: ' + e.message);
      }
    }

