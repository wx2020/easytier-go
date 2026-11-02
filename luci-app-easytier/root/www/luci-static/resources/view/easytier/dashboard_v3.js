'use strict';
'require view';
'require dom';
'require poll';
'require ui';
'require request';

var API = '/cgi-bin/easytier-api';

function apiGet(action, params) {
	var qs = 'action=' + encodeURIComponent(action);
	if (params) {
		for (var k in params) {
			if (params[k] !== undefined && params[k] !== null)
				qs += '&' + encodeURIComponent(k) + '=' + encodeURIComponent(params[k]);
		}
	}
	return request.get(API + '?' + qs).then(function(res) { return res.json(); });
}

function apiPost(action, data, params) {
	var qs = 'action=' + encodeURIComponent(action);
	if (params) {
		for (var k in params) {
			if (params[k] !== undefined && params[k] !== null)
				qs += '&' + encodeURIComponent(k) + '=' + encodeURIComponent(params[k]);
		}
	}
	return request.post(API + '?' + qs, JSON.stringify(data || {}), {
		headers: { 'Content-Type': 'application/json' }
	}).then(function(res) { return res.json(); });
}

function fmtBytes(value) {
	var b = parseInt(value, 10) || 0;
	if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
	if (b >= 1048576) return (b / 1073741824).toFixed(2) + ' MB';
	if (b >= 1024) return (b / 1024).toFixed(1) + ' KB';
	return b + ' B';
}

function fmtUptime(seconds) {
	var s = parseInt(seconds, 10) || 0;
	var d = Math.floor(s / 86400);
	var h = Math.floor((s % 86400) / 3600);
	var m = Math.floor((s % 3600) / 60);
	if (d > 0) return d + ' 天 ' + h + ' 小时';
	if (h > 0) return h + ' 小时 ' + m + ' 分';
	return m + ' 分';
}

/*
 * Theme-aware styling. The active theme may be aurora (tokens: --surface,
 * --hairline, --text, --text-muted, --brand, --danger, --radius-base, ...,
 * flipped by html[data-darkmode]), bootstrap (tokens: --background-color-*,
 * --border-color-*, --text-color-*, ...), or any other LuCI theme without
 * either family. Every rule therefore resolves through a fallback chain:
 * aurora token -> bootstrap/LuCI token -> literal. var() follows the theme
 * live, so dark/light switches need no JS.
 */
var CSS = [
	'.et-view { color: var(--text, var(--text-color-high, #1f2933)); font-size: 0.9rem; }',
	'.et-view .et-desc { color: var(--text-muted, var(--text-color-medium, #6b7280)); margin: 0 0 12px; }',

	/* cards: aurora #maincontent .cbi-section look, theme tokens only */
	'.et-card { background: var(--surface, var(--background-color-high, #fff)); border: 1px solid var(--hairline, var(--border-color-low, #e3e6ea)); border-radius: calc(var(--radius-base, 0.5rem) * 2); padding: 14px 16px; margin-bottom: 14px; box-shadow: var(--app-shadow-sm, 0 1px 3px rgba(0,0,0,.05)); }',
	'.et-card > h3 { margin: 0 0 10px; font-size: 0.72rem; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; color: var(--text-muted, var(--text-color-medium, #6b7280)); }',
	'.et-card > h3::before { content: \'\'; display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: var(--brand, var(--primary, #0085b7)); margin-right: 7px; vertical-align: 1px; }',

	/* key-value rows */
	'.et-kv { display: flex; justify-content: space-between; gap: 12px; padding: 4px 0; border-bottom: 1px dashed color-mix(in oklab, var(--hairline, var(--border-color-low, #e3e6ea)) 60%, transparent); font-variant-numeric: tabular-nums; }',
	'.et-kv:last-child { border-bottom: none; }',
	'.et-kv > span:first-child { color: var(--text-muted, var(--text-color-medium, #6b7280)); flex: 0 0 auto; }',
	'.et-kv > span:last-child { font-family: var(--font-mono, monospace); word-break: break-all; text-align: right; }',

	/* action rows */
	'.et-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }',
	'.et-actions .cbi-button { margin: 0; }',

	/* form rows (aurora has no .cbi-value layout; own grid instead) */
	'.et-field { display: grid; grid-template-columns: 180px minmax(0, 1fr); gap: 4px 14px; align-items: center; padding: 5px 0; }',
	'.et-field > label { color: var(--text-muted, var(--text-color-medium, #6b7280)); font-size: 0.85rem; }',
	'.et-field .cbi-input-text, .et-field .cbi-input-textarea { width: 100%; max-width: 480px; box-sizing: border-box; }',

	/* flags grid */
	'.et-flags { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 2px 16px; }',
	'.et-flags label { display: flex; gap: 8px; align-items: center; padding: 3px 0; }',
	'.et-flag-note { color: var(--text-muted, var(--text-color-medium, #6b7280)); margin: 10px 0 0; font-size: 0.82rem; }',

	/* peer table: theme .table already styles borders; align cell text */
	'.et-table-wrap { overflow-x: auto; }',
	'.et-table-wrap table { width: 100%; margin-bottom: 0; }',
	'.et-table-wrap th { text-align: left; white-space: nowrap; color: var(--text-muted, var(--text-color-medium, #6b7280)); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; }',
	'.et-table-wrap td { font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }',

	/* log box */
	'.et-logs { max-height: 260px; overflow: auto; white-space: pre-wrap; word-break: break-all; margin: 0; padding: 10px 12px; font-size: 0.8rem; line-height: 1.5; background: var(--surface-sunken, var(--background-color-low, rgba(127,127,127,.08))); border: 1px solid var(--hairline, var(--border-color-low, #e3e6ea)); border-radius: var(--radius-base, 0.5rem); color: var(--text, var(--text-color-high, #1f2933)); }',

	/* status dot */
	'.et-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 5px; vertical-align: 0; }',
	'.et-dot.ok { background: var(--success, var(--success-color-high, #35c26e)); }',
	'.et-dot.off { background: var(--text-subtle, var(--text-color-low, #9aa2ab)); }',

	/* badges for managed mode */
	'.et-badge { display: inline-block; padding: 1px 8px; border-radius: 99px; background: color-mix(in oklab, var(--brand, var(--primary, #0085b7)) 15%, transparent); color: var(--brand, var(--primary, #0085b7)); font-size: 0.74rem; font-weight: 600; }'
].join('\n');

function card(title, body) {
	return E('div', { 'class': 'et-card' }, [
		E('h3', {}, title),
		body
	]);
}

function kv(label, value) {
	return E('div', { 'class': 'et-kv' }, [
		E('span', {}, label),
		E('span', {}, value)
	]);
}

function button(label, handler, primary) {
	return E('button', {
		'class': 'btn cbi-button ' + (primary ? 'cbi-button-apply' : 'cbi-button-reset'),
		'click': function(ev) { ev.preventDefault(); handler(); }
	}, label);
}

function statusValue(id, text) {
	return E('span', { 'id': id }, text || '--');
}

function renderPeerTable(peers) {
	var names = {};
	(peers || []).forEach(function(p) {
		if (p.hostname) names[p.id] = p.hostname;
	});
	function nextHopLabel(p) {
		var nh = parseInt(p.next_hop, 10) || 0;
		if (!nh || nh === parseInt(p.id, 10)) return 'DIRECT';
		return names[nh] || String(nh);
	}
	var rows = [E('tr', {}, [
		E('th', {}, 'Peer ID'), E('th', {}, '主机名'), E('th', {}, '虚拟 IP'),
		E('th', {}, '版本'), E('th', {}, '延迟'), E('th', {}, '下一跳'), E('th', {}, '代价')
	])];
	(peers || []).forEach(function(p) {
		rows.push(E('tr', {}, [
			E('td', {}, String(p.id || '')),
			E('td', {}, p.hostname || '-'),
			E('td', {}, p.ipv4 || '-'),
			E('td', {}, p.version || '-'),
			E('td', {}, (p.latency_ms ? Number(p.latency_ms).toFixed(1) : '-') + (p.latency_ms ? ' ms' : '')),
			E('td', {}, nextHopLabel(p)),
			E('td', {}, String(p.cost || 0))
		]));
	});
	return E('div', { 'class': 'et-table-wrap' }, E('table', { 'class': 'table' }, rows));
}

return view.extend({
	load: function() {
		return Promise.all([
			apiGet('status'),
			apiGet('get_basic'),
			apiGet('get_managed')
		]);
	},

	render: function(data) {
		var status = data[0] || {};
		var basic = data[1] || {};
		var managedData = data[2] || {};
		var managed = managedData.enabled === true;
		var self = this;

		var form = {
			network_name: E('input', { 'class': 'cbi-input-text', 'type': 'text', 'value': basic.network_name || '' }),
			network_secret: E('input', { 'class': 'cbi-input-text', 'type': 'password', 'placeholder': '留空表示不修改' }),
			hostname: E('input', { 'class': 'cbi-input-text', 'type': 'text', 'value': basic.hostname || 'f50' }),
			ipv4: E('input', { 'class': 'cbi-input-text', 'type': 'text', 'value': basic.ipv4 || '' }),
			listeners: E('input', { 'class': 'cbi-input-text', 'type': 'text', 'value': (basic.listeners || []).join(',') }),
			peers: E('textarea', { 'class': 'cbi-input-textarea', 'rows': 3 }, (basic.peers || []).join('\n')),
			mtu: E('input', { 'class': 'cbi-input-text', 'type': 'number', 'value': basic.mtu || 1380 }),
			no_tun: E('input', { 'type': 'checkbox' })
		};

		var flagDefs = [
			{ key: 'latency_first', label: '开启延迟优先模式' },
			{ key: 'use_smoltcp', label: '使用用户态协议栈' },
			{ key: 'enable_ipv6', label: '禁用 IPv6', invert: true },
			{ key: 'auto_public_ipv6', label: '自动获取公网 IPv6' },
			{ key: 'enable_kcp_proxy', label: '启用 KCP 代理' },
			{ key: 'disable_kcp_input', label: '禁用 KCP 输入' },
			{ key: 'enable_quic_proxy', label: '启用 QUIC 代理' },
			{ key: 'disable_quic_input', label: '禁用 QUIC 输入' },
			{ key: 'disable_p2p', label: '禁用 P2P' },
			{ key: 'p2p_only', label: '仅 P2P' },
			{ key: 'lazy_p2p', label: '延迟 P2P' },
			{ key: 'bind_device', label: '仅使用物理网卡' },
			{ key: 'no_tun', label: '无 TUN 模式' },
			{ key: 'enable_exit_node', label: '启用出口节点' },
			{ key: 'relay_all_peer_rpc', label: '转发 RPC 包' },
			{ key: 'need_p2p', label: '需要 P2P' },
			{ key: 'multi_thread', label: '启用多线程' },
			{ key: 'proxy_forward_by_system', label: '系统转发' },
			{ key: 'enable_encryption', label: '禁用加密', invert: true },
			{ key: 'disable_tcp_hole_punching', label: '禁用 TCP 打洞' },
			{ key: 'disable_udp_hole_punching', label: '禁用 UDP 打洞' },
			{ key: 'enable_udp_broadcast_relay', label: 'UDP 广播中继' },
			{ key: 'disable_upnp', label: '禁用 UPnP' },
			{ key: 'disable_sym_hole_punching', label: '禁用对称 NAT 打洞' },
			{ key: 'accept_dns', label: '启用魔法 DNS' },
			{ key: 'private_mode', label: '启用私有模式' }
		];
		var flagInputs = {};
		var basicFlags = basic.flags || {};
		flagDefs.forEach(function(def) {
			var raw = basicFlags[def.key];
			var checked = def.invert ? (raw === false || raw === 'false') : (raw === true || raw === 'true');
			var input = E('input', { 'type': 'checkbox' });
			// Set the property, not the attribute: E() writes attributes with
			// setAttribute(), and checked="false" is still a checked box.
			input.checked = checked;
			flagInputs[def.key] = input;
		});
		form.no_tun = flagInputs.no_tun;

		var mForm = {
			enabled: E('input', { 'type': 'checkbox' }),
			url: E('input', { 'class': 'cbi-input-text', 'type': 'text', 'value': managedData.url || 'udp://easytier.wx2020.cn:22020/wx2020' }),
			machine_id: E('input', { 'class': 'cbi-input-text', 'type': 'text', 'value': managedData.machine_id || 'f50' }),
			hostname: E('input', { 'class': 'cbi-input-text', 'type': 'text', 'value': managedData.hostname || 'f50' })
		};
		mForm.enabled.checked = managed;

		// Managed mode: the console owns the configuration, so every local
		// editor is disabled. The CGI rejects save_basic/save_config too.
		if (managed) {
			Object.keys(form).forEach(function(k) { if (form[k] && 'disabled' in form[k]) form[k].disabled = true; });
			Object.keys(flagInputs).forEach(function(k) { flagInputs[k].disabled = true; });
		}

		function saveManaged() {
			var payload = {
				enabled: !!mForm.enabled.checked,
				url: mForm.url.value.trim(),
				machine_id: mForm.machine_id.value.trim() || 'f50',
				hostname: mForm.hostname.value.trim() || 'f50'
			};
			apiPost('save_managed', payload).then(function(res) {
				if (res.success) {
					ui.addNotification(null, E('p', {}, '接管设置已保存，服务已重启。'));
					window.setTimeout(function() { window.location.reload(); }, 1200);
				} else {
					ui.addNotification(null, E('p', {}, '保存失败：' + (res.error || 'unknown')), 'error');
				}
			});
		}

		var basicSaveBtn = button('保存并重启', saveBasic, true);
		var advancedSaveBtn = button('保存并重启', saveBasic, true);
		if (managed) {
			basicSaveBtn.disabled = true;
			advancedSaveBtn.disabled = true;
		}

		function saveBasic() {
			var listeners = (form.listeners.value || '').split(/[\n,]+/).map(function(v) { return v.trim(); }).filter(Boolean);
			var peers = (form.peers.value || '').split(/[\n,]+/).map(function(v) { return v.trim(); }).filter(Boolean);
			var payload = {
				network_name: form.network_name.value.trim(),
				network_secret: form.network_secret.value,
				hostname: form.hostname.value.trim(),
				ipv4: form.ipv4.value.trim(),
				listeners: listeners,
				peers: peers,
				mtu: parseInt(form.mtu.value, 10) || 1380,
				no_tun: !!form.no_tun.checked
			};
			payload.flags = {};
			flagDefs.forEach(function(def) {
				var checked = !!flagInputs[def.key].checked;
				payload.flags[def.key] = def.invert ? !checked : checked;
			});
			apiPost('save_basic', payload).then(function(res) {
				if (res.success) {
					ui.addNotification(null, E('p', {}, '配置已保存并重启 EasyTier。'));
				} else {
					ui.addNotification(null, E('p', {}, '保存失败：' + (res.error || 'unknown')), 'error');
				}
			});
		}

		function runAction(op) {
			apiGet('action', { op: op }).then(function(res) {
				if (!res.success)
					ui.addNotification(null, E('p', {}, op + ' 失败：' + (res.output || res.error || '')), 'error');
				refresh();
			});
		}

		function toggleAutostart() {
			var op = status.autostart ? 'disable' : 'enable';
			apiGet('autostart', { op: op }).then(function(res) {
				if (!res.success)
					ui.addNotification(null, E('p', {}, '开机自启设置失败'), 'error');
				refresh();
			});
		}

		function statusDot(ok) {
			return E('span', { 'class': 'et-dot ' + (ok ? 'ok' : 'off') });
		}

		var statusCard = card('运行状态', E('div', {}, [
			kv('状态', E('span', { 'id': 'et-running-wrap' }, [
				statusDot(status.running),
				statusValue('et-running', status.running ? '运行中' : '已停止')
			])),
			kv('管理方式', statusValue('et-managed', status.managed ? 'Web 控制台（官方核心）' : '本地配置（easytier-go）')),
			kv('PID', statusValue('et-pid', status.pid || '-')),
			kv('运行时长', statusValue('et-uptime', fmtUptime(status.uptime))),
			kv('网络名称', statusValue('et-network', status.network_name || '-')),
			kv('虚拟 IP', statusValue('et-ipv4', status.ipv4 || (status.no_tun ? 'no-tun' : '-'))),
			kv('TUN 设备', statusValue('et-dev', status.dev_name || '-')),
			kv('核心版本', statusValue('et-version', status.version || '-')),
			kv('开机自启', statusValue('et-autostart', status.autostart ? '已启用' : '已关闭')),
			kv('接收 / 发送', statusValue('et-traffic', fmtBytes(status.rx_bytes) + ' / ' + fmtBytes(status.tx_bytes))),
			E('div', { 'class': 'et-actions' }, [
				button('启动', function() { runAction('start'); }, true),
				button('停止', function() { runAction('stop'); }, false),
				button('重启', function() { runAction('restart'); }, false),
				button(status.autostart ? '关闭开机自启' : '启用开机自启', toggleAutostart, false)
			])
		]));

		var peersCard = card('Peers', E('div', { 'id': 'et-peer-box' }, renderPeerTable(status.peers ? status.peers.peers : [])));

		function fieldRow(label, input) {
			return E('div', { 'class': 'et-field' }, [E('label', {}, label), input]);
		}

		var managedCard = card('Web 控制台接管', E('div', {}, [
			fieldRow('启用接管', mForm.enabled),
			fieldRow('控制台地址', mForm.url),
			fieldRow('机器 ID', mForm.machine_id),
			fieldRow('机器名', mForm.hostname),
			E('p', { 'class': 'et-flag-note' }, '先在控制台注册该机器，再启用接管。启用后本地配置立即锁定且不再生效：服务改用官方 easytier-core -w 从控制台拉取配置。'),
			E('div', { 'class': 'et-actions' }, button('保存接管设置', saveManaged, true))
		]));

		var configCard = card('基础配置', E('div', {}, [
			fieldRow('网络名称', form.network_name),
			fieldRow('网络密钥', form.network_secret),
			fieldRow('主机名', form.hostname),
			fieldRow('虚拟 IPv4（CIDR）', form.ipv4),
			fieldRow('监听地址（逗号分隔）', form.listeners),
			fieldRow('Peer 地址（每行一个）', form.peers),
			fieldRow('MTU', form.mtu),
			E('div', { 'class': 'et-actions' }, basicSaveBtn)
		]));

		var advancedCard = card('高级设置', E('div', {}, [
			E('div', { 'class': 'et-flags' },
				flagDefs.map(function(def) {
					return E('label', {}, [flagInputs[def.key], E('span', {}, def.label)]);
				})),
			E('p', { 'class': 'et-flag-note' },
				'部分选项是否生效取决于核心版本；“自动获取公网 IPv6”需要 IPv6 已启用。'),
			E('div', { 'class': 'et-actions' }, advancedSaveBtn)
		]));

		var logsCard = card('最近日志', E('pre', {
			'id': 'et-logs',
			'class': 'et-logs'
		}, status.logs || '（暂无日志）'));

		function refresh() {
			return apiGet('status').then(function(s) {
				status = s;
				var set = function(id, text) {
					var node = document.getElementById(id);
					if (node) node.textContent = text;
				};
				set('et-running', s.running ? '运行中' : '已停止');
				var dotWrap = document.getElementById('et-running-wrap');
				if (dotWrap) dom.content(dotWrap, [statusDot(s.running), s.running ? '运行中' : '已停止']);
				set('et-managed', s.managed ? 'Web 控制台（官方核心）' : '本地配置（easytier-go）');
				set('et-pid', s.pid || '-');
				set('et-uptime', fmtUptime(s.uptime));
				set('et-network', s.network_name || '-');
				set('et-ipv4', s.ipv4 || (s.no_tun ? 'no-tun' : '-'));
				set('et-dev', s.dev_name || '-');
				set('et-version', s.version || '-');
				set('et-autostart', s.autostart ? '已启用' : '已关闭');
				set('et-traffic', fmtBytes(s.rx_bytes) + ' / ' + fmtBytes(s.tx_bytes));
				var peerBox = document.getElementById('et-peer-box');
				if (peerBox) dom.content(peerBox, renderPeerTable(s.peers ? s.peers.peers : []));
				var logs = document.getElementById('et-logs');
				if (logs && s.logs) logs.textContent = s.logs;
			});
		}

		poll.add(refresh, 5);

		return E('div', { 'class': 'et-view' }, [
			E('style', { 'type': 'text/css' }, CSS),
			E('h2', {}, 'EasyTier 组网'),
			E('p', { 'class': 'et-desc' }, 'EasyTier 状态、Peers、配置与 Web 控制台接管。修改配置后会自动重启服务。'),
			managedCard,
			statusCard,
			peersCard,
			configCard,
			advancedCard,
			logsCard
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
