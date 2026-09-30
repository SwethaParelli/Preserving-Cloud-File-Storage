/**
 * Privacy-Preserving Cloud File Storage
 * Frontend Application Controller
 */

class PrivacyVaultApp {
  constructor() {
    this.currentUser = null;
    this.files = [];
    this.sharedFiles = [];
    this.expiringLinks = [];
    this.auditLogs = [];
    this.registeredUsers = [];
    this.selectedFile = null;
    this.activeShareFileId = null;
    this.currentAuthTab = 'login';
    
    this.init();
  }

  async init() {
    this.setupDropzone();
    await this.checkAuth();
  }

  /* -------------------------------------------------------------
     Authentication & Session Management
  ------------------------------------------------------------- */

  async checkAuth() {
    try {
      const res = await fetch('/api/auth/me');
      const data = await res.json();
      
      // Update system status badges
      if (data.storage_mode) {
        document.getElementById('storage-mode-text').textContent = data.storage_mode;
      }
      if (data.database_mode) {
        document.getElementById('db-mode-text').textContent = data.database_mode;
      }

      if (data.authenticated && data.user) {
        this.currentUser = data.user;
        this.renderAuthenticatedUI();
        await this.loadAllDashboardData();
      } else {
        this.currentUser = null;
        this.renderUnauthenticatedUI();
      }
    } catch (err) {
      console.error('Auth verification failed:', err);
      this.renderUnauthenticatedUI();
    }
  }

  renderAuthenticatedUI() {
    document.getElementById('auth-view').style.display = 'none';
    document.getElementById('dashboard-view').style.display = 'block';
    document.getElementById('nav-user-section').style.display = 'flex';
    
    document.getElementById('nav-user-name').textContent = this.currentUser.name;
    document.getElementById('nav-user-email').textContent = this.currentUser.email;
  }

  renderUnauthenticatedUI() {
    document.getElementById('auth-view').style.display = 'flex';
    document.getElementById('dashboard-view').style.display = 'none';
    document.getElementById('nav-user-section').style.display = 'none';
  }

  switchAuthTab(tab) {
    this.currentAuthTab = tab;
    const loginBtn = document.getElementById('tab-btn-login');
    const regBtn = document.getElementById('tab-btn-register');
    const loginForm = document.getElementById('login-form');
    const regForm = document.getElementById('register-form');

    if (tab === 'login') {
      loginBtn.classList.add('active');
      regBtn.classList.remove('active');
      loginForm.style.display = 'block';
      regForm.style.display = 'none';
    } else {
      regBtn.classList.add('active');
      loginBtn.classList.remove('active');
      regForm.style.display = 'block';
      loginForm.style.display = 'none';
    }
  }

  async handleLogin(e) {
    e.preventDefault();
    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;
    const submitBtn = document.getElementById('login-submit-btn');

    submitBtn.disabled = true;
    submitBtn.textContent = 'Verifying Credentials...';

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();

      if (data.success) {
        this.showToast('Login successful! Welcome to your secure vault.', 'success');
        this.currentUser = data.user;
        this.renderAuthenticatedUI();
        await this.loadAllDashboardData();
      } else {
        this.showToast(data.error || 'Invalid credentials.', 'error');
      }
    } catch (err) {
      this.showToast('Connection failed. Please check backend server.', 'error');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Unlock Vault';
    }
  }

  async handleRegister(e) {
    e.preventDefault();
    const name = document.getElementById('reg-name').value.trim();
    const email = document.getElementById('reg-email').value.trim();
    const password = document.getElementById('reg-password').value;
    const submitBtn = document.getElementById('register-submit-btn');

    submitBtn.disabled = true;
    submitBtn.textContent = 'Hashing Password with bcrypt...';

    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password })
      });
      const data = await res.json();

      if (data.success) {
        this.showToast('Account registered successfully!', 'success');
        this.currentUser = data.user;
        this.renderAuthenticatedUI();
        await this.loadAllDashboardData();
      } else {
        this.showToast(data.error || 'Registration failed.', 'error');
      }
    } catch (err) {
      this.showToast('Server connection failed.', 'error');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Create Encrypted Account';
    }
  }

  async handleLogout() {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
      this.currentUser = null;
      this.showToast('Logged out securely.', 'info');
      this.renderUnauthenticatedUI();
    } catch (err) {
      this.showToast('Logout error.', 'error');
    }
  }

  fillDemoAccount() {
    document.getElementById('login-email').value = 'alice@college.edu';
    document.getElementById('login-password').value = 'Password123!';
    this.showToast('Demo credentials auto-filled. Click Unlock Vault.', 'info');
  }

  /* -------------------------------------------------------------
     Dashboard Data & Tabs
  ------------------------------------------------------------- */

  async loadAllDashboardData() {
    await Promise.all([
      this.loadStats(),
      this.loadMyFiles(),
      this.loadSharedWithMe(),
      this.loadExpiringLinks(),
      this.loadAuditLogs(),
      this.loadRegisteredUsers()
    ]);
  }

  async loadStats() {
    try {
      const res = await fetch('/api/audit/stats');
      const data = await res.json();
      if (data.success && data.stats) {
        document.getElementById('stat-total-files').textContent = data.stats.total_files;
        document.getElementById('stat-storage-used').textContent = this.formatBytes(data.stats.total_encrypted_bytes);
        document.getElementById('stat-shared-count').textContent = data.stats.shared_with_me;
        document.getElementById('stat-audit-count').textContent = data.stats.total_events;
      }
    } catch (err) {
      console.error('Failed to load stats:', err);
    }
  }

  switchMainTab(tabId) {
    const tabBtns = document.querySelectorAll('.main-tabs .tab-btn');
    tabBtns.forEach(btn => btn.classList.remove('active'));
    
    const contents = document.querySelectorAll('.tab-content');
    contents.forEach(content => content.classList.remove('active'));

    document.getElementById(`tab-btn-${tabId}`).classList.add('active');
    document.getElementById(`view-${tabId}`).classList.add('active');

    if (tabId === 'audit-logs') {
      this.loadAuditLogs();
    } else if (tabId === 'expiring-links') {
      this.loadExpiringLinks();
    } else if (tabId === 'shared-files') {
      this.loadSharedWithMe();
    } else if (tabId === 'my-files') {
      this.loadMyFiles();
    }
  }

  /* -------------------------------------------------------------
     File Management (My Files)
  ------------------------------------------------------------- */

  async loadMyFiles() {
    try {
      const res = await fetch('/api/files/my-files');
      const data = await res.json();
      
      if (data.success) {
        this.files = data.files || [];
        this.renderMyFilesTable(this.files);
      }
    } catch (err) {
      console.error('Failed to load files:', err);
    }
  }

  renderMyFilesTable(filesToRender) {
    const tbody = document.getElementById('my-files-tbody');
    const emptyState = document.getElementById('my-files-empty');
    tbody.innerHTML = '';

    if (filesToRender.length === 0) {
      emptyState.style.display = 'block';
      return;
    }
    emptyState.style.display = 'none';

    filesToRender.forEach(file => {
      const tr = document.createElement('tr');
      const storageBadgeClass = file.storage_type === 's3' ? 'badge-s3' : 'badge-local';
      const storageBadgeText = file.storage_type === 's3' ? 'AWS S3' : 'Local Disk';
      const shortSha = file.sha256_hash ? file.sha256_hash.substring(0, 12) + '...' : '-';
      const dateFormatted = new Date(file.upload_date).toLocaleDateString() + ' ' + new Date(file.upload_date).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

      tr.innerHTML = `
        <td>
          <div class="file-name-cell">
            <div class="file-icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
            </div>
            <div>
              <div class="file-title">${this.escapeHtml(file.filename)}</div>
              <div class="file-sub">${file.content_type || 'binary'}</div>
            </div>
          </div>
        </td>
        <td>${this.formatBytes(file.file_size)}</td>
        <td>
          <span class="crypto-badge badge-gcm">AES-256-GCM</span>
          <div style="font-size: 0.7rem; color: var(--text-muted); margin-top: 2px;">Enc: ${this.formatBytes(file.encrypted_size)}</div>
        </td>
        <td>
          <span class="hash-pill" onclick="app.copyText('${file.sha256_hash}')" title="Click to copy full SHA-256 hash">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
            ${shortSha}
          </span>
        </td>
        <td><span class="crypto-badge ${storageBadgeClass}">${storageBadgeText}</span></td>
        <td style="font-size: 0.775rem; color: var(--text-muted);">${dateFormatted}</td>
        <td style="text-align: right;">
          <div class="table-actions" style="justify-content: flex-end;">
            <button class="btn btn-secondary btn-icon" onclick="app.downloadFile('${file.file_id}')" title="Decrypt & Download">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
            </button>
            <button class="btn btn-secondary btn-icon" onclick="app.previewFile('${file.file_id}', '${this.escapeHtml(file.filename)}')" title="Preview Decrypted">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
            </button>
            <button class="btn btn-secondary btn-icon" onclick="app.openShareModal('${file.file_id}', '${this.escapeHtml(file.filename)}')" title="Share with User">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"></circle><circle cx="6" cy="12" r="3"></circle><circle cx="18" cy="19" r="3"></circle><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line></svg>
            </button>
            <button class="btn btn-secondary btn-icon" onclick="app.openExpiringLinkModal('${file.file_id}', '${this.escapeHtml(file.filename)}')" title="Create Expiring Link">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
            </button>
            <button class="btn btn-secondary btn-icon" onclick="app.openCryptoDetails('${file.file_id}')" title="Cryptographic Details">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            </button>
            <button class="btn btn-danger btn-icon" onclick="app.deleteFile('${file.file_id}', '${this.escapeHtml(file.filename)}')" title="Delete File">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
            </button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  filterFiles() {
    const q = document.getElementById('file-search-input').value.toLowerCase().trim();
    if (!q) {
      this.renderMyFilesTable(this.files);
      return;
    }
    const filtered = this.files.filter(f => 
      f.filename.toLowerCase().includes(q) || 
      (f.sha256_hash && f.sha256_hash.toLowerCase().includes(q))
    );
    this.renderMyFilesTable(filtered);
  }

  /* -------------------------------------------------------------
     Drag & Drop and Encrypted Upload Pipeline
  ------------------------------------------------------------- */

  setupDropzone() {
    const dropzone = document.getElementById('dropzone');
    if (!dropzone) return;

    ['dragenter', 'dragover'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove('dragover');
      });
    });

    dropzone.addEventListener('drop', (e) => {
      const dt = e.dataTransfer;
      const files = dt.files;
      if (files.length > 0) {
        this.selectFile(files[0]);
      }
    });
  }

  handleFileSelect(e) {
    const file = e.target.files[0];
    if (file) {
      this.selectFile(file);
    }
  }

  selectFile(file) {
    this.selectedFile = file;
    document.getElementById('selected-filename').textContent = file.name;
    document.getElementById('selected-filesize').textContent = this.formatBytes(file.size);
    document.getElementById('selected-file-info').style.display = 'block';
    document.getElementById('upload-btn-submit').disabled = false;
    this.resetCryptoPipeline();
  }

  resetCryptoPipeline() {
    for (let i = 1; i <= 5; i++) {
      const step = document.getElementById(`pipe-step-${i}`);
      step.className = 'pipeline-step';
      step.querySelector('.step-icon').textContent = '○';
    }
  }

  async animateStep(stepNum, delayMs = 250) {
    const step = document.getElementById(`pipe-step-${stepNum}`);
    step.className = 'pipeline-step active';
    step.querySelector('.step-icon').textContent = '⚡';
    await new Promise(r => setTimeout(r, delayMs));
    step.className = 'pipeline-step completed';
    step.querySelector('.step-icon').textContent = '✓';
  }

  openUploadModal() {
    this.selectedFile = null;
    document.getElementById('selected-file-info').style.display = 'none';
    document.getElementById('upload-btn-submit').disabled = true;
    document.getElementById('file-input').value = '';
    this.resetCryptoPipeline();
    this.openModal('upload-modal');
  }

  async submitFileUpload() {
    if (!this.selectedFile) return;

    const uploadBtn = document.getElementById('upload-btn-submit');
    uploadBtn.disabled = true;
    uploadBtn.textContent = 'Encrypting & Uploading...';

    try {
      // 1. In-memory read
      await this.animateStep(1, 200);
      // 2. SHA-256 Calculation
      await this.animateStep(2, 200);
      // 3. 96-bit Nonce generation
      await this.animateStep(3, 200);
      // 4. AES-256-GCM AEAD encryption
      await this.animateStep(4, 250);

      const formData = new FormData();
      formData.append('file', this.selectedFile);

      const res = await fetch('/api/files/upload', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();

      if (data.success) {
        // 5. Cloud Storage confirmation
        await this.animateStep(5, 200);
        this.showToast(`'${this.selectedFile.name}' encrypted with AES-256-GCM & stored!`, 'success');
        this.closeModal('upload-modal');
        await this.loadAllDashboardData();
      } else {
        this.showToast(data.error || 'Upload failed.', 'error');
      }
    } catch (err) {
      this.showToast('Upload error occurred.', 'error');
    } finally {
      uploadBtn.disabled = false;
      uploadBtn.textContent = 'Start Encrypted Upload';
    }
  }

  /* -------------------------------------------------------------
     File Operations: Download, Preview, Delete, Details
  ------------------------------------------------------------- */

  downloadFile(fileId) {
    this.showToast('Initiating AES-256-GCM decryption & SHA-256 verification...', 'info');
    window.location.href = `/api/files/${fileId}/download`;
  }

  async previewFile(fileId, filename) {
    try {
      const res = await fetch(`/api/files/${fileId}/preview`);
      if (!res.ok) {
        const data = await res.json();
        this.showToast(data.error || 'Unable to preview file.', 'error');
        return;
      }
      
      const contentType = res.headers.get('Content-Type') || '';
      const previewContainer = document.getElementById('preview-container');
      document.getElementById('preview-modal-title').textContent = `Preview: ${filename}`;
      
      document.getElementById('preview-download-btn').onclick = () => {
        this.downloadFile(fileId);
      };

      if (contentType.startsWith('image/')) {
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        previewContainer.innerHTML = `<img src="${url}" style="max-width: 100%; border-radius: 8px; margin: 0 auto; display: block;" />`;
      } else {
        const text = await res.text();
        previewContainer.textContent = text.length > 5000 ? text.substring(0, 5000) + '\n\n[... Truncated for preview ...]' : text;
      }

      this.openModal('preview-modal');
    } catch (err) {
      this.showToast('Preview error.', 'error');
    }
  }

  async deleteFile(fileId, filename) {
    if (!confirm(`Are you sure you want to securely delete "${filename}"?\nThe ciphertext will be shredded from cloud storage and all share links revoked.`)) {
      return;
    }

    try {
      const res = await fetch(`/api/files/${fileId}`, { method: 'DELETE' });
      const data = await res.json();

      if (data.success) {
        this.showToast(`"${filename}" securely deleted.`, 'info');
        await this.loadAllDashboardData();
      } else {
        this.showToast(data.error || 'Failed to delete file.', 'error');
      }
    } catch (err) {
      this.showToast('Deletion error.', 'error');
    }
  }

  openCryptoDetails(fileId) {
    const file = this.files.find(f => f.file_id === fileId);
    if (!file) return;

    document.getElementById('crypto-modal-filename').textContent = file.filename;
    document.getElementById('crypto-modal-nonce').textContent = file.nonce_hex || 'Not Recorded';
    document.getElementById('crypto-modal-sha256').textContent = file.sha256_hash || 'Not Recorded';
    document.getElementById('crypto-modal-storage').textContent = file.storage_type === 's3' ? 'AWS S3 Cloud Object (Encrypted)' : 'Local Encrypted Storage (AES Encrypted File)';

    this.openModal('crypto-details-modal');
  }

  /* -------------------------------------------------------------
     File Sharing & Expiring Links
  ------------------------------------------------------------- */

  async loadRegisteredUsers() {
    try {
      const res = await fetch('/api/users');
      const data = await res.json();
      if (data.success) {
        this.registeredUsers = data.users || [];
        const datalist = document.getElementById('users-datalist');
        datalist.innerHTML = '';
        this.registeredUsers.forEach(u => {
          const opt = document.createElement('option');
          opt.value = u.email;
          opt.textContent = `${u.name} (${u.email})`;
          datalist.appendChild(opt);
        });
      }
    } catch (err) {
      console.error('Failed to load users for sharing:', err);
    }
  }

  async openShareModal(fileId, filename) {
    this.activeShareFileId = fileId;
    document.getElementById('share-modal-filename').textContent = filename;
    document.getElementById('share-recipient-input').value = '';
    
    await this.loadFileShares(fileId);
    this.openModal('share-user-modal');
  }

  async loadFileShares(fileId) {
    try {
      const res = await fetch(`/api/shares/file/${fileId}/manage`);
      const data = await res.json();
      const sharesList = document.getElementById('file-current-shares-list');
      sharesList.innerHTML = '';

      if (data.success && data.shares && data.shares.length > 0) {
        data.shares.forEach(s => {
          const item = document.createElement('div');
          item.style.display = 'flex';
          item.style.justifyContent = 'space-between';
          item.style.alignItems = 'center';
          item.style.padding = '0.4rem 0';
          item.style.borderBottom = '1px solid rgba(255,255,255,0.05)';
          
          item.innerHTML = `
            <span>${this.escapeHtml(s.shared_to_email)} <span style="color: var(--accent-cyan);">(${s.permission.toUpperCase()})</span></span>
            <button class="btn btn-danger btn-sm" style="padding: 0.2rem 0.5rem; font-size: 0.7rem;" onclick="app.revokeUserShare('${s._id}')">Revoke</button>
          `;
          sharesList.appendChild(item);
        });
      } else {
        sharesList.innerHTML = '<div style="color: var(--text-subtle);">No active direct shares on this file.</div>';
      }
    } catch (err) {
      console.error('Failed to load active file shares:', err);
    }
  }

  async submitUserShare() {
    const recipient_email = document.getElementById('share-recipient-input').value.trim();
    const permission = document.querySelector('input[name="share-permission"]:checked').value;

    if (!recipient_email) {
      this.showToast('Please enter recipient email.', 'error');
      return;
    }

    try {
      const res = await fetch('/api/shares/share-user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          file_id: this.activeShareFileId,
          recipient_email,
          permission
        })
      });
      const data = await res.json();

      if (data.success) {
        this.showToast(data.message, 'success');
        document.getElementById('share-recipient-input').value = '';
        await this.loadFileShares(this.activeShareFileId);
        await this.loadStats();
      } else {
        this.showToast(data.error || 'Failed to share file.', 'error');
      }
    } catch (err) {
      this.showToast('Sharing failed.', 'error');
    }
  }

  async revokeUserShare(shareId) {
    try {
      const res = await fetch('/api/shares/revoke-user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ share_id: shareId })
      });
      const data = await res.json();

      if (data.success) {
        this.showToast('Access revoked.', 'info');
        await this.loadFileShares(this.activeShareFileId);
        await this.loadStats();
      } else {
        this.showToast(data.error || 'Failed to revoke access.', 'error');
      }
    } catch (err) {
      this.showToast('Revocation failed.', 'error');
    }
  }

  async loadSharedWithMe() {
    try {
      const res = await fetch('/api/files/shared-with-me');
      const data = await res.json();
      
      if (data.success) {
        this.sharedFiles = data.shared_files || [];
        this.renderSharedFilesTable(this.sharedFiles);
      }
    } catch (err) {
      console.error('Failed to load shared files:', err);
    }
  }

  renderSharedFilesTable(files) {
    const tbody = document.getElementById('shared-files-tbody');
    const emptyState = document.getElementById('shared-files-empty');
    tbody.innerHTML = '';

    if (files.length === 0) {
      emptyState.style.display = 'block';
      return;
    }
    emptyState.style.display = 'none';

    files.forEach(file => {
      const tr = document.createElement('tr');
      const shortSha = file.sha256_hash ? file.sha256_hash.substring(0, 12) + '...' : '-';
      const dateFormatted = new Date(file.shared_at).toLocaleDateString() + ' ' + new Date(file.shared_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

      tr.innerHTML = `
        <td>
          <div class="file-name-cell">
            <div class="file-icon" style="color: var(--accent-emerald); background: rgba(16, 185, 129, 0.15);">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
            </div>
            <div>
              <div class="file-title">${this.escapeHtml(file.filename)}</div>
              <div class="file-sub">AES-256-GCM AEAD</div>
            </div>
          </div>
        </td>
        <td>${this.formatBytes(file.file_size)}</td>
        <td style="color: #c7d2fe;">${this.escapeHtml(file.shared_by_email)}</td>
        <td>
          <span class="crypto-badge ${file.permission === 'view' ? 'badge-local' : 'badge-gcm'}">
            ${file.permission.toUpperCase()}
          </span>
        </td>
        <td>
          <span class="hash-pill" onclick="app.copyText('${file.sha256_hash}')" title="Copy SHA-256 Hash">
            ${shortSha}
          </span>
        </td>
        <td style="font-size: 0.775rem; color: var(--text-muted);">${dateFormatted}</td>
        <td style="text-align: right;">
          <div class="table-actions" style="justify-content: flex-end;">
            ${file.permission === 'download' ? `
              <button class="btn btn-secondary btn-icon" onclick="app.downloadFile('${file.file_id}')" title="Decrypt & Download">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
              </button>
            ` : ''}
            <button class="btn btn-secondary btn-icon" onclick="app.previewFile('${file.file_id}', '${this.escapeHtml(file.filename)}')" title="Preview">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
            </button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  /* -------------------------------------------------------------
     Expiring Links Management
  ------------------------------------------------------------- */

  openExpiringLinkModal(fileId, filename) {
    this.activeShareFileId = fileId;
    document.getElementById('generated-link-container').style.display = 'none';
    document.getElementById('generate-link-btn').style.display = 'inline-block';
    this.openModal('expiring-link-modal');
  }

  async submitCreateExpiringLink() {
    const duration_minutes = parseInt(document.getElementById('link-duration').value, 10);
    const max_access_count = parseInt(document.getElementById('link-max-downloads').value, 10);

    try {
      const res = await fetch('/api/shares/create-link', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          file_id: this.activeShareFileId,
          duration_minutes,
          max_access_count
        })
      });
      const data = await res.json();

      if (data.success) {
        const fullUrl = window.location.origin + data.share_url;
        document.getElementById('generated-share-url').value = fullUrl;
        document.getElementById('generated-link-expiry-hint').textContent = `Expires at: ${new Date(data.expires_at).toLocaleString()}`;
        document.getElementById('generated-link-container').style.display = 'block';
        document.getElementById('generate-link-btn').style.display = 'none';
        this.showToast('Secure expiring link created!', 'success');
        await this.loadExpiringLinks();
        await this.loadStats();
      } else {
        this.showToast(data.error || 'Failed to create link.', 'error');
      }
    } catch (err) {
      this.showToast('Link generation error.', 'error');
    }
  }

  copyGeneratedLink() {
    const input = document.getElementById('generated-share-url');
    this.copyText(input.value);
  }

  async loadExpiringLinks() {
    try {
      // Gather active links across user's files
      const res = await fetch('/api/files/my-files');
      const data = await res.json();
      
      let allLinks = [];
      if (data.success && data.files) {
        for (const file of data.files) {
          const linkRes = await fetch(`/api/shares/file/${file.file_id}/manage`);
          const linkData = await linkRes.json();
          if (linkData.success && linkData.links) {
            allLinks = allLinks.concat(linkData.links);
          }
        }
      }

      this.expiringLinks = allLinks;
      this.renderExpiringLinksTable(this.expiringLinks);
    } catch (err) {
      console.error('Failed to load expiring links:', err);
    }
  }

  renderExpiringLinksTable(links) {
    const tbody = document.getElementById('expiring-links-tbody');
    const emptyState = document.getElementById('expiring-links-empty');
    tbody.innerHTML = '';

    if (links.length === 0) {
      emptyState.style.display = 'block';
      return;
    }
    emptyState.style.display = 'none';

    links.forEach(link => {
      const tr = document.createElement('tr');
      const expiresAt = new Date(link.expires_at);
      const isExpired = new Date() > expiresAt;
      const fullUrl = `${window.location.origin}/share/${link.token}`;
      const downloadsLeft = link.max_access_count > 0 ? `${Math.max(0, link.max_access_count - link.access_count)} / ${link.max_access_count}` : 'Unlimited';

      tr.innerHTML = `
        <td>
          <div class="file-name-cell">
            <div class="file-icon" style="color: var(--accent-cyan); background: rgba(6, 182, 212, 0.15);">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
            </div>
            <div>
              <div class="file-title">${this.escapeHtml(link.filename)}</div>
              <div class="file-sub font-mono">${link.token.substring(0, 10)}...</div>
            </div>
          </div>
        </td>
        <td>
          <span class="hash-pill" onclick="app.copyText('${fullUrl}')" title="Click to copy full public URL">
            Copy URL 📋
          </span>
        </td>
        <td style="font-size: 0.8rem; color: ${isExpired ? '#f43f5e' : '#fbbf24'};">
          ${expiresAt.toLocaleString()}
        </td>
        <td style="font-size: 0.85rem;">${downloadsLeft}</td>
        <td>
          <span class="crypto-badge ${isExpired ? 'badge-local' : 'badge-gcm'}" style="${isExpired ? 'color: #f43f5e; border-color: rgba(244,63,94,0.3); background: rgba(244,63,94,0.1);' : ''}">
            ${isExpired ? 'EXPIRED' : 'ACTIVE'}
          </span>
        </td>
        <td style="text-align: right;">
          <button class="btn btn-danger btn-sm" onclick="app.revokeExpiringLink('${link.token}')">Revoke Link</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  async revokeExpiringLink(token) {
    try {
      const res = await fetch('/api/shares/revoke-link', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });
      const data = await res.json();

      if (data.success) {
        this.showToast('Expiring link revoked.', 'info');
        await this.loadExpiringLinks();
        await this.loadStats();
      } else {
        this.showToast(data.error || 'Failed to revoke link.', 'error');
      }
    } catch (err) {
      this.showToast('Revocation failed.', 'error');
    }
  }

  /* -------------------------------------------------------------
     Audit Logs
  ------------------------------------------------------------- */

  async loadAuditLogs() {
    const filter = document.getElementById('audit-filter-action')?.value || '';
    try {
      const res = await fetch(`/api/audit/logs?action=${filter}&limit=60`);
      const data = await res.json();
      
      if (data.success) {
        this.auditLogs = data.logs || [];
        this.renderAuditLogsTable(this.auditLogs);
      }
    } catch (err) {
      console.error('Failed to load audit logs:', err);
    }
  }

  renderAuditLogsTable(logs) {
    const tbody = document.getElementById('audit-logs-tbody');
    tbody.innerHTML = '';

    if (logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem;">No audit records found matching criteria.</td></tr>';
      return;
    }

    logs.forEach(log => {
      const tr = document.createElement('tr');
      const actionBadge = this.getActionBadge(log.action);
      const statusBadge = log.status === 'SUCCESS' 
        ? '<span style="color: var(--accent-emerald); font-weight: 600;">SUCCESS</span>' 
        : '<span style="color: var(--accent-rose); font-weight: 600;">FAILURE</span>';
      const timeFormatted = new Date(log.timestamp).toLocaleString();

      tr.innerHTML = `
        <td style="font-size: 0.775rem; color: var(--text-muted); font-family: var(--font-mono);">${timeFormatted}</td>
        <td>${actionBadge}</td>
        <td>${statusBadge}</td>
        <td>
          <div style="font-size: 0.8rem; font-weight: 500;">${this.escapeHtml(log.user_email)}</div>
          <div style="font-size: 0.7rem; color: var(--text-subtle); font-family: var(--font-mono);">${log.ip_address}</div>
        </td>
        <td style="font-size: 0.8rem; font-weight: 500;">${this.escapeHtml(log.filename || '-')}</td>
        <td style="font-size: 0.8rem; color: var(--text-muted);">${this.escapeHtml(log.details || '-')}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  getActionBadge(action) {
    switch (action) {
      case 'UPLOAD': return '<span class="crypto-badge badge-gcm">UPLOAD (AES-256)</span>';
      case 'DOWNLOAD': return '<span class="crypto-badge badge-cyan">DOWNLOAD (SHA-256)</span>';
      case 'SHARE': return '<span class="crypto-badge" style="background: rgba(168,85,247,0.15); color: #c084fc; border: 1px solid rgba(168,85,247,0.3);">SHARE</span>';
      case 'REVOKE_SHARE': return '<span class="crypto-badge" style="background: rgba(244,63,94,0.15); color: #fb7185; border: 1px solid rgba(244,63,94,0.3);">REVOKE_SHARE</span>';
      case 'CREATE_LINK': return '<span class="crypto-badge badge-s3">CREATE_LINK</span>';
      case 'ACCESS_LINK': return '<span class="crypto-badge badge-local">ACCESS_LINK</span>';
      case 'DELETE': return '<span class="crypto-badge" style="background: rgba(244,63,94,0.2); color: #f43f5e; border: 1px solid rgba(244,63,94,0.4);">DELETE (SHRED)</span>';
      case 'LOGIN': return '<span class="crypto-badge" style="background: rgba(99,102,241,0.15); color: #818cf8; border: 1px solid rgba(99,102,241,0.3);">LOGIN</span>';
      default: return `<span class="crypto-badge badge-local">${action}</span>`;
    }
  }

  /* -------------------------------------------------------------
     Modal Helpers & Utility Functions
  ------------------------------------------------------------- */

  openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.add('active');
    }
  }

  closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.remove('active');
    }
  }

  copyText(text) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      this.showToast('Copied to clipboard!', 'info');
    }).catch(() => {
      this.showToast('Failed to copy text.', 'error');
    });
  }

  showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    let iconSvg = '';
    if (type === 'success') {
      iconSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>';
    } else if (type === 'error') {
      iconSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#f43f5e" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>';
    } else {
      iconSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#06b6d4" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';
    }

    toast.innerHTML = `${iconSvg} <span>${this.escapeHtml(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }

  formatBytes(bytes, decimals = 2) {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  }

  escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}

// Instantiate global app
window.app = new PrivacyVaultApp();
