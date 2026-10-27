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
	if (b >= 1048576) return (b / 1048576).toFixed(2) + ' MB';
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

function card(title, body) {
	return E('div', {
		'style': 'background: var(--background-color-medium, #f5f5f5); border-radius: 8px; padding: 14px; margin-bottom: 14px;'
	}, [
		E('h3', { 'style': 'margin: 0 0 10px 0; font-size: 1rem;' }, title),
		body
	]);
}

function kv(label, value) {
	return E('div', { 'style': 'display: flex; justify-content: space-between; gap: 12px; padding: 3px 0; border-bottom: 1px solid var(--border-color, #e5e7eb);' }, [
		E('span', { 'style': 'color: var(--text-color-low, #6b7280);' }, label),
		E('span', { 'style': 'font-family: var(--font-mono, monospace); word-break: break-all; text-align: right;' }, value)
	]);
}

function button(label, handler, primary) {
	return E('button', {
		'class': 'btn cbi-button ' + (primary ? 'cbi-button-apply' : 'cbi-button-reset'),
		'style': 'margin-right: 8px; margin-top: 6px;',
		'click': function(ev) { ev.preventDefault(); handler(); }
	}, label);
}

function statusValue(id, text) {
	return E('span', { 'id': id, 'style': 'font-family: var(--font-mono, monospace);' }, text || '--');
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
	return E('div', { 'style': 'overflow-x: auto;' }, E('table', { 'class': 'table', 'style': 'width: 100%;' }, rows));
}

return view.extend({
	load: function() {
		return Promise.all([
			apiGet('status'),
			apiGet('get_basic')
		]);
	},

	render: function(data) {
		var status = data[0] || {};
		var basic = data[1] || {};
		var self = this;

		var form = {
			network_name: E('input', { 'class': 'cbi-input-text', 'type': 'text', 'value': basic.network_name || '' }),
			network_secret: E('input', { 'class': 'cbi-input-text', 'type': 'password', 'placeholder': '留空表示不修改' }),
			hostname: E('input', { 'class': 'cbi-input-text', 'type': 'text', 'value': basic.hostname || 'f50' }),
			ipv4: E('input', { 'class': 'cbi-input-text', 'type': 'text', 'value': basic.ipv4 || '' }),
			listeners: E('input', { 'class': 'cbi-input-text', 'type': 'text', 'value': (basic.listeners || []).join(',') }),
			peers: E('textarea', { 'class': 'cbi-input-textarea', 'rows': 3, 'style': 'width: 100%;' }, (basic.peers || []).join('\n')),
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
					ui.addNotification(null, E('p', { 'style': 'color: #ef4444;' }, '保存失败：' + (res.error || 'unknown')));
				}
			});
		}

		function runAction(op) {
			apiGet('action', { op: op }).then(function(res) {
				if (!res.success)
					ui.addNotification(null, E('p', { 'style': 'color: #ef4444;' }, op + ' 失败：' + (res.output || res.error || '')));
				refresh();
			});
		}

		function toggleAutostart() {
			var op = status.autostart ? 'disable' : 'enable';
			apiGet('autostart', { op: op }).then(function(res) {
				if (!res.success)
					ui.addNotification(null, E('p', { 'style': 'color: #ef4444;' }, '开机自启设置失败'));
				refresh();
			});
		}

		var statusCard = card('运行状态', E('div', {}, [
			kv('状态', statusValue('et-running', status.running ? '● 运行中' : '○ 已停止')),
			kv('PID', statusValue('et-pid', status.pid || '-')),
			kv('运行时长', statusValue('et-uptime', fmtUptime(status.uptime))),
			kv('网络名称', statusValue('et-network', status.network_name || '-')),
			kv('虚拟 IP', statusValue('et-ipv4', status.ipv4 || (status.no_tun ? 'no-tun' : '-'))),
			kv('TUN 设备', statusValue('et-dev', status.dev_name || '-')),
			kv('核心版本', statusValue('et-version', status.version || '-')),
			kv('开机自启', statusValue('et-autostart', status.autostart ? '已启用' : '已关闭')),
			kv('接收 / 发送', statusValue('et-traffic', fmtBytes(status.rx_bytes) + ' / ' + fmtBytes(status.tx_bytes))),
			E('div', { 'style': 'margin-top: 10px;' }, [
				button('启动', function() { runAction('start'); }, true),
				button('停止', function() { runAction('stop'); }, false),
				button('重启', function() { runAction('restart'); }, false),
				button(status.autostart ? '关闭开机自启' : '启用开机自启', toggleAutostart, false)
			])
		]));

		var peersCard = card('Peers', E('div', { 'id': 'et-peer-box' }, renderPeerTable(status.peers ? status.peers.peers : [])));

		var configCard = card('基础配置', E('div', {}, [
			E('div', { 'class': 'cbi-value' }, [E('label', { 'class': 'cbi-value-title' }, '网络名称'), E('div', { 'class': 'cbi-value-field' }, form.network_name)]),
			E('div', { 'class': 'cbi-value' }, [E('label', { 'class': 'cbi-value-title' }, '网络密钥'), E('div', { 'class': 'cbi-value-field' }, form.network_secret)]),
			E('div', { 'class': 'cbi-value' }, [E('label', { 'class': 'cbi-value-title' }, '主机名'), E('div', { 'class': 'cbi-value-field' }, form.hostname)]),
			E('div', { 'class': 'cbi-value' }, [E('label', { 'class': 'cbi-value-title' }, '虚拟 IPv4（CIDR）'), E('div', { 'class': 'cbi-value-field' }, form.ipv4)]),
			E('div', { 'class': 'cbi-value' }, [E('label', { 'class': 'cbi-value-title' }, '监听地址（逗号分隔）'), E('div', { 'class': 'cbi-value-field' }, form.listeners)]),
			E('div', { 'class': 'cbi-value' }, [E('label', { 'class': 'cbi-value-title' }, 'Peer 地址（每行一个）'), E('div', { 'class': 'cbi-value-field' }, form.peers)]),
			E('div', { 'class': 'cbi-value' }, [E('label', { 'class': 'cbi-value-title' }, 'MTU'), E('div', { 'class': 'cbi-value-field' }, form.mtu)]),
			E('div', { 'style': 'margin-top: 10px;' }, button('保存并重启', saveBasic, true))
		]));

		var advancedCard = card('高级设置', E('div', {}, [
			E('div', { 'style': 'display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 2px 16px;' },
				flagDefs.map(function(def) {
					return E('label', { 'style': 'display: flex; gap: 8px; align-items: center; padding: 3px 0;' }, [
						flagInputs[def.key],
						E('span', {}, def.label)
					]);
				})),
			E('p', { 'style': 'color: var(--text-color-low, #6b7280); margin: 10px 0 0 0;' },
				'部分选项是否生效取决于核心版本；“自动获取公网 IPv6”需要 IPv6 已启用。'),
			E('div', { 'style': 'margin-top: 10px;' }, button('保存并重启', saveBasic, true))
		]));

		var logsCard = card('最近日志', E('pre', {
			'id': 'et-logs',
			'style': 'max-height: 260px; overflow: auto; white-space: pre-wrap; font-size: 0.8rem; margin: 0;'
		}, status.logs || '（暂无日志）'));

		function refresh() {
			return apiGet('status').then(function(s) {
				status = s;
				var set = function(id, text) {
					var node = document.getElementById(id);
					if (node) node.textContent = text;
				};
				set('et-running', s.running ? '● 运行中' : '○ 已停止');
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

		return E('div', {}, [
			E('h2', {}, 'EasyTier 组网'),
			E('p', { 'style': 'color: var(--text-color-low, #6b7280);' }, 'EasyTier Go 核心状态、Peers 与配置。修改配置后会自动重启服务。'),
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
