// WeChat Exporter - Frontend Application

const API_BASE = '';

const state = {
    conversations: [],
    currentCid: null,
    currentOffset: 0,
    currentLimit: 50,
    totalMessages: 0,
    convOffset: 0,
    convLimit: 50,
    myWxid: '',
    snapshotId: null,
};

async function apiGet(path) {
    const resp = await fetch(API_BASE + path);
    if (!resp.ok) throw await buildApiError(resp);
    return resp.json();
}

async function apiPost(path) {
    const resp = await fetch(API_BASE + path, { method: 'POST' });
    if (!resp.ok) throw await buildApiError(resp);
    return resp.json();
}

async function buildApiError(resp) {
    let message = `API error: ${resp.status}`;
    try {
        const data = await resp.json();
        if (data && typeof data.detail === 'string' && data.detail.trim()) {
            message = data.detail.trim();
        }
    } catch (e) {}
    return new Error(message);
}

function formatTime(ts) {
    if (!ts) return '';
    const d = new Date(ts);
    const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function formatRelativeTime(ts) {
    if (!ts) return '';
    const diff = Date.now() - ts;
    if (diff < 60000) return '刚刚';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}分钟前`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}小时前`;
    if (diff < 604800000) return `${Math.floor(diff / 86400000)}天前`;
    return formatTime(ts);
}

function formatSize(bytes) {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0;
    while (bytes >= 1024 && i < units.length - 1) {
        bytes /= 1024;
        i++;
    }
    return `${bytes.toFixed(1)} ${units[i]}`;
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function formatPlainMultiline(text) {
    if (!text) return '';
    return escapeHtml(text).replace(/\n/g, '<br>');
}

function clampText(text, maxLength = 1200) {
    if (!text) return '';
    return text.length > maxLength ? `${text.slice(0, maxLength)}...` : text;
}

function _getWeekday(ts) {
    if (!ts) return '';
    const days = ['星期日', '星期一', '星期二', '星期三', '星期四', '星期五', '星期六'];
    try { return days[new Date(ts).getDay()]; } catch { return ''; }
}

// --- Conversations ---
let _convTotal = 0;
let _convLoading = false;
let _convFilter = 'all';
let _convSearch = '';

async function loadConversations(reset = false) {
    if (reset) {
        state.convOffset = 0;
        state.conversations = [];
        _convTotal = 0;
    }
    if (_convTotal > 0 && state.conversations.length >= _convTotal) return;
    if (_convLoading) return;
    _convLoading = true;

    const params = new URLSearchParams({
        limit: state.convLimit,
        offset: state.convOffset,
    });
    if (_convSearch) params.set('keyword', _convSearch);

    try {
        const data = await apiGet(`/api/conversations?${params}`);
        _convTotal = data.total;
        state.snapshotId = data.snapshot_id || state.snapshotId;
        state.conversations = reset ? data.conversations : [...state.conversations, ...data.conversations];
        state.convOffset += data.conversations.length;
        renderConversations(_convTotal);
    } catch (e) {
        if (reset) {
            document.getElementById('convList').innerHTML = `<div class="loading">${escapeHtml(e.message)}</div>`;
        }
        throw e;
    } finally {
        _convLoading = false;
    }
}

function _onConvListScroll() {
    const el = document.getElementById('convList');
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 40 && !_convLoading && state.conversations.length < _convTotal) {
        loadConversations(false);
    }
}

function _getFilteredConversations() {
    let list = state.conversations;
    if (_convFilter === 'group') list = list.filter(c => c.type === 'group');
    else if (_convFilter === 'single') list = list.filter(c => c.type === 'single');
    return list;
}

function renderConversations(total) {
    const list = document.getElementById('convList');
    const count = document.getElementById('convCount');
    const filtered = _getFilteredConversations();
    count.textContent = `${filtered.length}/${total}`;

    if (filtered.length === 0) {
        list.innerHTML = '<div style="padding:20px;text-align:center;color:#999">无匹配会话</div>';
        return;
    }

    list.innerHTML = filtered.map(conv => {
        const unread = conv.unread_count > 0 ? `<span class="unread-badge">${conv.unread_count > 99 ? '99+' : conv.unread_count}</span>` : '';
        return `
        <div class="conv-item ${conv.cid === state.currentCid ? 'active' : ''}" data-cid="${escapeHtml(conv.cid)}">
            <div class="conv-title">
                <span class="conv-type-badge ${conv.type}">${conv.type === 'group' ? '群' : '单聊'}</span>
                ${escapeHtml(conv.title || conv.cid)}
                ${unread}
            </div>
            <div class="conv-subtitle">
                <span class="conv-summary">${escapeHtml(conv.summary || (conv.member_count ? conv.member_count + '人' : ''))}</span>
                <span>${formatRelativeTime(conv.last_modify)}</span>
            </div>
        </div>`;
    }).join('');

    list.removeEventListener('scroll', _onConvListScroll);
    list.addEventListener('scroll', _onConvListScroll);
    list.querySelectorAll('.conv-item').forEach(el => {
        el.addEventListener('click', () => selectConversation(el.dataset.cid));
    });
}

async function selectConversation(cid) {
    state.currentCid = cid;
    state.currentOffset = 0;

    document.querySelectorAll('.conv-item').forEach(el => {
        el.classList.toggle('active', el.dataset.cid === cid);
    });

    document.getElementById('emptyState').style.display = 'none';
    document.getElementById('searchView').style.display = 'none';
    document.getElementById('messageView').style.display = 'flex';

    const conv = state.conversations.find(c => c.cid === cid);
    document.getElementById('convTitle').textContent = conv ? conv.title : cid;
    document.getElementById('convMeta').textContent = conv
        ? `${conv.type === 'group' ? '群聊' : '单聊'}${conv.member_count ? ' · ' + conv.member_count + '人' : ''}`
        : '';

    await loadMessages();
}

// --- Messages ---

async function loadMessages() {
    if (!state.currentCid) return;
    const params = new URLSearchParams({
        limit: state.currentLimit,
        offset: state.currentOffset,
    });
    const data = await apiGet(`/api/conversations/${encodeURIComponent(state.currentCid)}/messages?${params}`);
    state.totalMessages = data.total;
    state.snapshotId = data.snapshot_id || state.snapshotId;
    renderMessages(data.messages);
    renderPagination();
}

function renderMessageBody(msg) {
    if (msg.content_type === 3) {
        const imgInfo = msg.image_info || {};
        if (imgInfo.src) {
            return `<img class="msg-image" src="${imgInfo.src}" alt="图片">`;
        }
        return '<div class="msg-image-placeholder">[图片未缓存到本地]</div>';
    }
    if (msg.content_type === 34) {
        const audio = msg.audio_info || {};
        const sec = audio.duration_ms ? Math.max(1, Math.round(audio.duration_ms / 1000)) : 0;
        const meta = `<div class="msg-audio-meta">语音消息${sec ? ` · ${sec}秒` : ''}</div>`;
        const tr = audio.transcript ? `<div class="msg-audio-transcript">${formatPlainMultiline(audio.transcript)}</div>` : '';
        return `${meta}${tr}`;
    }
    if (msg.message_subtype === 'reply' && msg.quote_info) {
        const q = msg.quote_info;
        return `
            <div class="msg-reply">
                <div class="msg-reply-source">
                    <div class="msg-reply-name">${escapeHtml(q.source_sender_name || '原消息')}</div>
                    <div class="msg-reply-preview">${formatPlainMultiline(clampText(q.source_preview || '', 300))}</div>
                </div>
                <div class="msg-reply-body">${formatPlainMultiline(clampText(msg.text || '', 1600))}</div>
            </div>`;
    }
    if (msg.message_subtype === 'forwarded' && msg.forwarded_info) {
        const fi = msg.forwarded_info;
        return `
            <div class="msg-forwarded" data-cid="${escapeHtml(msg.cid)}" data-mid="${escapeHtml(String(msg.id))}">
                <div class="msg-forwarded-title">${escapeHtml(fi.title || '聊天记录')}</div>
                <div class="msg-forwarded-summary">${formatPlainMultiline(clampText(fi.summary || '', 260))}</div>
                <div class="msg-forwarded-footer">合并转发 · 共 ${fi.total || 0} 条（点击查看）</div>
            </div>`;
    }
    if (msg.message_subtype === 'file' && msg.attachments && msg.attachments.length > 0) {
        const f = msg.attachments[0];
        const fname = escapeHtml(f.filename || '文件');
        const fsize = formatSize(f.file_size || 0);
        if (f.local_available && f.local_path) {
            const dl = `/api/local-file?path=${encodeURIComponent(f.local_path)}`;
            return `<div class="msg-file"><span class="msg-file-icon">&#128206;</span><div class="msg-file-info"><a class="msg-file-name msg-file-link" href="${dl}" target="_blank">${fname}</a><div class="msg-file-size">${fsize} · 本地可打开</div></div></div>`;
        }
        return `<div class="msg-file"><span class="msg-file-icon">&#128206;</span><div class="msg-file-info"><div class="msg-file-name">${fname}</div><div class="msg-file-size">${fsize} · 未缓存</div></div></div>`;
    }
    if (msg.link_info) {
        const lk = msg.link_info;
        const linkEl = lk.url ? `<a class="msg-card-link" href="${escapeHtml(lk.url)}" target="_blank" rel="noopener">打开链接</a>` : '';
        const srcEl = lk.from ? `<div style="font-size:11px;color:#888;margin-top:4px">来源: ${escapeHtml(lk.from)}</div>` : '';
        return `<div class="msg-card"><div class="msg-card-title">${escapeHtml(lk.title || msg.text)}</div>${lk.desc ? `<div>${formatPlainMultiline(clampText(lk.desc, 300))}</div>` : ''}${srcEl}${linkEl}</div>`;
    }
    if (msg.message_subtype === 'transfer' || msg.message_subtype === 'red_packet' || msg.message_subtype === 'announcement') {
        return `<div class="msg-card">${formatPlainMultiline(clampText(msg.text, 1600))}</div>`;
    }
    return formatPlainMultiline(clampText(msg.text || `[${msg.content_type_name || '消息'}]`, 4000));
}

function renderMessages(messages) {
    const list = document.getElementById('messageList');
    let html = '';
    let lastDateStr = '';

    messages.forEach(msg => {
        const msgDate = msg.created_at_str ? msg.created_at_str.split(' ')[0] : '';
        if (msgDate && msgDate !== lastDateStr) {
            lastDateStr = msgDate;
            html += `<div class="msg-date-sep"><span>${escapeHtml(msgDate)} ${_getWeekday(msg.created_at)}</span></div>`;
        }

        if (msg.content_type === 10000 || msg.content_type === 10002 || msg.message_subtype === 'pat') {
            html += `<div class="msg-item system"><span class="msg-system-pill">${escapeHtml(msg.text)}</span></div>`;
            return;
        }

        const isSelf = Boolean(msg.is_self);
        const contentHtml = renderMessageBody(msg);
        html += `
            <div class="msg-item ${isSelf ? 'self' : ''}">
                <div class="msg-sender">${escapeHtml(msg.sender_name || msg.sender_id)}</div>
                <div class="msg-bubble">${contentHtml}</div>
                <div class="msg-time">${escapeHtml(msg.created_at_str || formatTime(msg.created_at))}</div>
            </div>`;
    });

    list.innerHTML = html || '<div class="loading">该会话暂无消息</div>';

    list.querySelectorAll('.msg-image').forEach(img => {
        img.addEventListener('click', function () { openLightbox(this.src); });
        img.addEventListener('error', function () {
            this.outerHTML = '<div class="msg-image-placeholder">[图片解密失败或未缓存]</div>';
        });
    });

    list.querySelectorAll('.msg-forwarded').forEach(el => {
        el.addEventListener('click', () => openForwardedModal(el.dataset.cid, el.dataset.mid));
    });

    list.scrollTop = list.scrollHeight;
}

async function openForwardedModal(cid, mid) {
    const modal = document.getElementById('forwardedModal');
    const titleEl = document.getElementById('forwardedModalTitle');
    const bodyEl = document.getElementById('forwardedModalBody');
    modal.style.display = 'flex';
    titleEl.textContent = '合并转发聊天记录';
    bodyEl.innerHTML = '<div class="loading">加载中...</div>';
    try {
        const data = await apiGet(`/api/conversations/${encodeURIComponent(cid)}/messages/${encodeURIComponent(mid)}/forwarded?limit=200`);
        titleEl.textContent = `${data.title || '合并转发聊天记录'} (${data.total || 0} 条)`;
        if (!data.messages || data.messages.length === 0) {
            bodyEl.innerHTML = '<div class="loading">无子消息内容</div>';
            return;
        }
        bodyEl.innerHTML = data.messages.map(m => {
            const indent = Math.max(0, ((m.path || []).length - 1) * 16);
            return `
                <div class="fwd-row" style="padding-left:${indent}px">
                    <div class="fwd-meta">${escapeHtml(m.sender_name || '')} · ${escapeHtml(m.created_at_str || '')}</div>
                    <div class="fwd-body">${formatPlainMultiline(m.content || m.text || '')}</div>
                </div>`;
        }).join('');
    } catch (e) {
        bodyEl.innerHTML = `<div class="loading" style="color:#d64545">加载失败: ${escapeHtml(e.message)}</div>`;
    }
}

function renderPagination() {
    const container = document.getElementById('messagePagination');
    const totalPages = Math.ceil(state.totalMessages / state.currentLimit);
    const currentPage = Math.floor(state.currentOffset / state.currentLimit) + 1;
    if (totalPages <= 1) {
        container.innerHTML = `<span>共 ${state.totalMessages} 条消息</span>`;
        return;
    }
    let html = '';
    if (currentPage < totalPages) html += `<button onclick="goToPage(${currentPage + 1})">更早的消息</button>`;
    const startPage = Math.max(1, currentPage - 2);
    const endPage = Math.min(totalPages, currentPage + 2);
    for (let p = startPage; p <= endPage; p++) {
        html += `<button class="${p === currentPage ? 'active' : ''}" onclick="goToPage(${p})">${p}</button>`;
    }
    if (currentPage > 1) html += `<button onclick="goToPage(${currentPage - 1})">最新消息</button>`;
    html += ` <span>第${currentPage}/${totalPages}页 共${state.totalMessages}条</span>`;
    container.innerHTML = html;
}

function goToPage(page) {
    state.currentOffset = (page - 1) * state.currentLimit;
    loadMessages();
}

// --- Search ---

async function doSearch() {
    const query = document.getElementById('searchInput').value.trim();
    if (!query) return;

    document.getElementById('emptyState').style.display = 'none';
    document.getElementById('messageView').style.display = 'none';
    document.getElementById('searchView').style.display = 'flex';
    document.getElementById('searchTitle').textContent = `搜索: "${query}" (检索中...)`;
    const results = document.getElementById('searchResults');
    results.innerHTML = '<div class="loading">首次搜索正在构建本地正文索引，请稍候...</div>';

    try {
        const data = await apiGet(`/api/search?q=${encodeURIComponent(query)}`);
        document.getElementById('searchTitle').textContent = `搜索: "${query}" (共 ${data.total} 条)`;
        if (data.messages.length === 0) {
            results.innerHTML = '<div class="loading">没有找到匹配的消息</div>';
            return;
        }
        results.innerHTML = data.messages.map(msg => `
            <div class="msg-item" style="max-width:100%">
                <div class="msg-sender">
                    ${escapeHtml(msg.sender_name || msg.sender_id)}
                    <span style="margin-left:8px;font-size:11px;color:#999">${escapeHtml(msg.created_at_str || '')} · ${escapeHtml(msg.cid || '')}</span>
                </div>
                <div class="msg-bubble">${highlightSearch(formatPlainMultiline(msg.content || msg.text), query)}</div>
            </div>`).join('');
    } catch (e) {
        results.innerHTML = `<div class="loading" style="color:#d64545">搜索失败: ${escapeHtml(e.message)}</div>`;
    }
}

function highlightSearch(text, query) {
    if (!text || !query) return text;
    const regex = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
    return text.replace(regex, '<mark>$1</mark>');
}

// --- Sync & Jobs ---

async function loadSyncStatus() {
    try {
        const s = await apiGet('/api/sync/status');
        const el = document.getElementById('syncStatus');
        if (s.is_syncing) {
            el.textContent = '任务执行中...';
        } else if (s.last_error) {
            el.textContent = `上次异常: ${s.last_error}`;
        } else if (!s.database_ready && s.database_error) {
            el.textContent = s.database_error;
        } else if (s.last_refresh_time) {
            el.textContent = `快照就绪 · 最近刷新: ${formatTime(new Date(s.last_refresh_time).getTime())}`;
        } else if (s.database_ready) {
            el.textContent = '快照就绪';
        } else {
            el.textContent = '尚未刷新';
        }
    } catch (e) {
        document.getElementById('syncStatus').textContent = '状态未知';
    }
}

async function waitForJob(started, interval = 1500) {
    if (!started || started.status !== 'started' || !started.job_id) {
        throw new Error(started?.error || '任务未启动，请等待当前任务完成后重试');
    }
    while (true) {
        const job = await apiGet(`/api/jobs/${encodeURIComponent(started.job_id)}`);
        if (job.status === 'failed') throw new Error(job.error || '任务失败');
        if (job.status === 'succeeded') {
            const result = job.result || {};
            if (result.outcome === 'fallback' || result.outcome === 'failed') {
                throw new Error(result.error || '刷新失败，仍使用原有快照');
            }
            return result;
        }
        if (job.status !== 'running') throw new Error('无法识别任务状态');
        await new Promise(resolve => setTimeout(resolve, interval));
    }
}

async function triggerRefresh() {
    const btn = document.getElementById('refreshBtn');
    btn.disabled = true;
    btn.textContent = '刷新中...';
    try {
        const started = await apiPost('/api/database/refresh');
        document.getElementById('syncStatus').textContent = '正在解密微信数据库...';
        await waitForJob(started);
        await loadSyncStatus();
        await loadConversations(true);
        if (state.currentCid) await loadMessages();
    } catch (e) {
        alert('刷新失败: ' + e.message);
    } finally {
        btn.disabled = false;
        btn.textContent = '刷新快照';
    }
}

async function triggerSync() {
    const btn = document.getElementById('syncBtn');
    btn.disabled = true;
    btn.textContent = '同步中...';
    try {
        const started = await apiPost('/api/sync/trigger');
        document.getElementById('syncStatus').textContent = '正在同步并导出...';
        await waitForJob(started);
        await loadSyncStatus();
        await loadConversations(true);
        if (state.currentCid) await loadMessages();
    } catch (e) {
        alert('同步失败: ' + e.message);
    } finally {
        btn.disabled = false;
        btn.textContent = '手动同步';
    }
}

// --- Exports ---

let _exportAllConvs = [];
let _exportSelected = {};
let _exportFilter = 'all';

async function loadExports() {
    const data = await apiGet('/api/exports');
    const list = document.getElementById('exportList');
    if (data.exports.length === 0) {
        list.innerHTML = '<div style="color:#888;padding:20px 0">暂无导出文件</div>';
        return;
    }
    list.innerHTML = data.exports.map(exp => {
        const isDir = exp.type === 'directory';
        const badge = isDir ? '<span style="font-size:11px;padding:1px 5px;border-radius:3px;background:#e8f8ef;color:#07c160;margin-right:6px">含附件</span>' : '';
        const dlUrl = exp.download_url || `/api/exports/${encodeURIComponent(exp.filename)}`;
        const folderLinkHtml = isDir
            ? `<a class="export-size js-open-export-folder" href="#" data-name="${escapeHtml(exp.filename)}">打开目录</a>`
            : `<span class="export-meta">${formatSize(exp.size)}</span>`;
        return `
        <div class="export-item">
            <div>
                <div class="export-name">${badge}${escapeHtml(exp.filename)}</div>
                <div class="export-time">${formatTime(exp.modified * 1000)}</div>
            </div>
            <div class="export-actions">
                ${folderLinkHtml}
                <a class="export-download" href="${dlUrl}" download>下载 ZIP</a>
                <button class="export-delete js-delete-export" type="button" data-name="${escapeHtml(exp.filename)}">删除</button>
            </div>
        </div>`;
    }).join('');

    list.querySelectorAll('.js-open-export-folder').forEach(link => {
        link.addEventListener('click', async e => {
            e.preventDefault();
            try {
                const resp = await fetch(`/api/exports/${encodeURIComponent(link.dataset.name)}/open-folder`, { method: 'POST' });
                if (!resp.ok) throw await buildApiError(resp);
            } catch (err) {
                alert('打开导出目录失败: ' + err.message);
            }
        });
    });

    list.querySelectorAll('.js-delete-export').forEach(btn => {
        btn.addEventListener('click', async () => {
            const name = btn.dataset.name;
            if (!confirm(`确认删除导出项“${name}”吗？`)) return;
            btn.disabled = true;
            try {
                const resp = await fetch(`/api/exports/${encodeURIComponent(name)}`, { method: 'DELETE' });
                if (!resp.ok) throw await buildApiError(resp);
                await loadExports();
            } catch (err) {
                btn.disabled = false;
                alert('删除失败: ' + err.message);
            }
        });
    });
}

async function loadExportConvList(keyword) {
    const el = document.getElementById('exportConvList');
    el.innerHTML = '<div class="loading">加载会话列表...</div>';
    try {
        let all = [];
        let offset = 0;
        const limit = 200;
        while (true) {
            const data = await apiGet(`/api/conversations?limit=${limit}&offset=${offset}`);
            all = all.concat(data.conversations);
            if (!data.has_more || all.length >= data.total) break;
            offset = data.next_offset;
        }
        _exportAllConvs = all;
        renderExportConvList(keyword || '');
    } catch (e) {
        el.innerHTML = `<div style="padding:20px;color:#d64545">加载会话列表失败: ${escapeHtml(e.message)}</div>`;
    }
}

function renderExportConvList(keyword) {
    const el = document.getElementById('exportConvList');
    let filtered = _exportAllConvs;
    if (_exportFilter === 'group') filtered = filtered.filter(c => c.type === 'group');
    else if (_exportFilter === 'single') filtered = filtered.filter(c => c.type === 'single');
    if (keyword) {
        const kw = keyword.toLowerCase();
        filtered = filtered.filter(c => (c.title || '').toLowerCase().includes(kw) || (c.cid || '').toLowerCase().includes(kw));
    }

    const selectedNum = Object.values(_exportSelected).filter(Boolean).length;
    document.getElementById('selectedCount').textContent = `已选 ${selectedNum} 个`;
    document.getElementById('exportSelectedBtn').disabled = selectedNum === 0;
    document.getElementById('selectAllCbs').checked = filtered.length > 0 && filtered.every(c => _exportSelected[c.cid]);

    if (filtered.length === 0) {
        el.innerHTML = '<div style="padding:20px;color:#888">无匹配会话</div>';
        return;
    }

    el.innerHTML = filtered.map(c => `
        <div class="export-conv-row" data-cid="${escapeHtml(c.cid)}">
            <input type="checkbox" class="ecr-cb" data-cid="${escapeHtml(c.cid)}" ${_exportSelected[c.cid] ? 'checked' : ''}>
            <span class="ecr-badge ${c.type}">${c.type === 'group' ? '群' : '单'}</span>
            <span class="ecr-title">${escapeHtml(c.title || c.cid)}</span>
        </div>`).join('');

    el.querySelectorAll('.ecr-cb').forEach(cb => {
        cb.addEventListener('change', e => {
            e.stopPropagation();
            _exportSelected[cb.dataset.cid] = cb.checked;
            const n = Object.values(_exportSelected).filter(Boolean).length;
            document.getElementById('selectedCount').textContent = `已选 ${n} 个`;
            document.getElementById('exportSelectedBtn').disabled = n === 0;
        });
    });

    el.querySelectorAll('.export-conv-row').forEach(row => {
        row.addEventListener('click', e => {
            if (e.target.tagName === 'INPUT') return;
            const cb = row.querySelector('.ecr-cb');
            cb.checked = !cb.checked;
            cb.dispatchEvent(new Event('change'));
        });
    });
}

function openLightbox(src) {
    document.getElementById('lightboxImg').src = src;
    document.getElementById('lightbox').style.display = 'flex';
}

function init() {
    apiGet('/api/config').then(data => {
        state.myWxid = String(data.user_wxid || '');
    }).catch(() => {});

    loadConversations(true).catch(() => {});
    loadSyncStatus();

    let convSearchTimer = null;
    document.getElementById('convSearchInput').addEventListener('input', e => {
        _convSearch = e.target.value.trim();
        clearTimeout(convSearchTimer);
        convSearchTimer = setTimeout(() => loadConversations(true).catch(() => {}), 250);
    });

    document.querySelectorAll('#sidebarTabs .sidebar-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('#sidebarTabs .sidebar-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            _convFilter = tab.dataset.filter;
            renderConversations(_convTotal);
        });
    });

    document.getElementById('searchBtn').addEventListener('click', doSearch);
    document.getElementById('searchInput').addEventListener('keydown', e => {
        if (e.key === 'Enter') doSearch();
    });
    document.getElementById('searchCloseBtn').addEventListener('click', () => {
        document.getElementById('searchView').style.display = 'none';
        document.getElementById(state.currentCid ? 'messageView' : 'emptyState').style.display = 'flex';
    });

    document.getElementById('refreshBtn').addEventListener('click', triggerRefresh);
    document.getElementById('syncBtn').addEventListener('click', triggerSync);

    document.getElementById('exportBtn').addEventListener('click', () => {
        document.getElementById('exportModal').style.display = 'flex';
        _exportSelected = {};
        _exportFilter = 'all';
        document.querySelectorAll('#exportFilterTabs .sidebar-tab').forEach(t => t.classList.toggle('active', t.dataset.filter === 'all'));
        loadExportConvList();
        loadExports();
        document.querySelectorAll('.export-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === 'select'));
        document.getElementById('exportPanelSelect').style.display = '';
        document.getElementById('exportPanelFiles').style.display = 'none';
    });
    document.getElementById('exportModalClose').addEventListener('click', () => {
        document.getElementById('exportModal').style.display = 'none';
    });
    document.getElementById('forwardedModalClose').addEventListener('click', () => {
        document.getElementById('forwardedModal').style.display = 'none';
    });

    document.querySelectorAll('.export-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.export-tab').forEach(t => t.classList.toggle('active', t === tab));
            document.getElementById('exportPanelSelect').style.display = tab.dataset.tab === 'select' ? '' : 'none';
            document.getElementById('exportPanelFiles').style.display = tab.dataset.tab === 'files' ? '' : 'none';
        });
    });

    document.getElementById('selectAllCbs').addEventListener('change', e => {
        const checked = e.target.checked;
        const keyword = document.getElementById('exportSearchInput').value.trim().toLowerCase();
        let filtered = _exportAllConvs;
        if (_exportFilter === 'group') filtered = filtered.filter(c => c.type === 'group');
        else if (_exportFilter === 'single') filtered = filtered.filter(c => c.type === 'single');
        if (keyword) filtered = filtered.filter(c => (c.title || '').toLowerCase().includes(keyword));
        filtered.forEach(c => { _exportSelected[c.cid] = checked; });
        renderExportConvList(document.getElementById('exportSearchInput').value.trim());
    });

    document.querySelectorAll('#exportFilterTabs .sidebar-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('#exportFilterTabs .sidebar-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            _exportFilter = tab.dataset.filter;
            renderExportConvList(document.getElementById('exportSearchInput').value.trim());
        });
    });

    document.getElementById('exportSearchInput').addEventListener('input', e => {
        renderExportConvList(e.target.value.trim());
    });

    const exportTimeRangeEl = document.getElementById('exportTimeRange');
    const customTimeRangeEl = document.getElementById('customTimeRange');
    const sinceTimeEl = document.getElementById('sinceTime');
    const untilTimeEl = document.getElementById('untilTime');

    function toTimestampMs(value) {
        if (!value) return null;
        const ts = new Date(value).getTime();
        return Number.isNaN(ts) ? null : ts;
    }

    exportTimeRangeEl.addEventListener('change', () => {
        customTimeRangeEl.hidden = exportTimeRangeEl.value !== '999';
    });

    document.getElementById('exportSelectedBtn').addEventListener('click', async () => {
        const cids = Object.entries(_exportSelected).filter(([_, v]) => v).map(([k]) => k);
        if (cids.length === 0) return;

        const btn = document.getElementById('exportSelectedBtn');
        btn.disabled = true;
        btn.textContent = '导出中...';

        const rangeValue = exportTimeRangeEl.value;
        let sinceTime = null;
        let untilTime = null;
        if (rangeValue === '999') {
            sinceTime = toTimestampMs(sinceTimeEl.value);
            untilTime = toTimestampMs(untilTimeEl.value);
            if (!sinceTime || !untilTime || sinceTime > untilTime) {
                btn.disabled = false;
                btn.textContent = '导出选中会话';
                alert('请选择有效的开始和结束时间');
                return;
            }
        } else if (rangeValue === '1w') {
            sinceTime = Date.now() - 7 * 24 * 3600 * 1000;
        } else if (rangeValue !== '0') {
            const months = parseInt(rangeValue, 10);
            if (months > 0) sinceTime = Date.now() - months * 30 * 24 * 3600 * 1000;
        }

        try {
            const resp = await fetch('/api/export/selected', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cids, since_time: sinceTime, until_time: untilTime }),
            });
            if (!resp.ok) throw await buildApiError(resp);
            const result = await waitForJob(await resp.json());
            if (!result.export_path) throw new Error('任务结束，但没有生成导出文件');
            document.querySelectorAll('.export-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === 'files'));
            document.getElementById('exportPanelSelect').style.display = 'none';
            document.getElementById('exportPanelFiles').style.display = '';
            loadExports();
        } catch (e) {
            alert('导出失败: ' + e.message);
        } finally {
            btn.disabled = false;
            btn.textContent = '导出选中会话';
        }
    });

    document.getElementById('fullExportBtn').addEventListener('click', async () => {
        const btn = document.getElementById('fullExportBtn');
        const progress = document.getElementById('exportProgress');
        btn.disabled = true;
        progress.textContent = '正在触发全量导出...';
        try {
            const started = await apiPost('/api/sync/trigger?full=true');
            progress.textContent = '导出中，请稍候...';
            const result = await waitForJob(started);
            if (!result.export_path) throw new Error('任务结束，但没有生成导出文件');
            progress.textContent = '导出完成';
            loadExports();
            setTimeout(() => { progress.textContent = ''; }, 5000);
        } catch (e) {
            progress.textContent = '导出失败: ' + e.message;
        } finally {
            btn.disabled = false;
        }
    });

    document.getElementById('lightboxClose').addEventListener('click', () => {
        document.getElementById('lightbox').style.display = 'none';
    });
    document.getElementById('lightbox').addEventListener('click', e => {
        if (e.target === e.currentTarget) document.getElementById('lightbox').style.display = 'none';
    });

    setInterval(loadSyncStatus, 60000);
}

window.goToPage = goToPage;
window.openLightbox = openLightbox;
document.addEventListener('DOMContentLoaded', init);
