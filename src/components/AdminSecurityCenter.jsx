import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { motion as Motion } from 'framer-motion';
import {
  AlertTriangle,
  Bell,
  CheckCircle2,
  Clock3,
  Eye,
  FileWarning,
  Lock,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  TerminalSquare,
} from 'lucide-react';
import {
  fetchBlockedIps,
  fetchSecurityBundle,
  performSecurityAction,
  saveSecuritySettings,
} from '../services/securityApi';

const SECTION_TABS = [
  { key: 'overview', label: 'Overview' },
  { key: 'logs', label: 'Logs' },
  { key: 'alerts', label: 'Alerts Center' },
  { key: 'incident', label: 'Incident Response' },
  { key: 'audit', label: 'Audit Trail' },
  { key: 'settings', label: 'Settings' },
];

const severityBadgeClass = (severity, isDarkMode) => {
  const value = String(severity || '').toLowerCase();

  if (value === 'critical') {
    return isDarkMode
      ? 'bg-red-500/20 text-red-200 border-red-400/50'
      : 'bg-red-100 text-red-700 border-red-200';
  }
  if (value === 'high') {
    return isDarkMode
      ? 'bg-orange-500/20 text-orange-200 border-orange-400/50'
      : 'bg-orange-100 text-orange-700 border-orange-200';
  }
  if (value === 'medium') {
    return isDarkMode
      ? 'bg-amber-500/20 text-amber-200 border-amber-400/50'
      : 'bg-amber-100 text-amber-700 border-amber-200';
  }
  if (value === 'low') {
    return isDarkMode
      ? 'bg-emerald-500/20 text-emerald-200 border-emerald-400/50'
      : 'bg-emerald-100 text-emerald-700 border-emerald-200';
  }

  return isDarkMode
    ? 'bg-slate-500/20 text-slate-200 border-slate-400/50'
    : 'bg-slate-100 text-slate-700 border-slate-200';
};

const DEFAULT_SETTINGS = {
  retentionDays: 15,
  thresholds: {
    failedLoginBurst: 5,
    resetPasswordBurst: 4,
  },
  telegram: {
    enabled: true,
    minimumSeverity: 'medium',
    mutedEventTypes: [],
  },
  controls: {
    loginEnabled: true,
    resetPasswordEnabled: true,
    heightenedProtection: false,
  },
  autoActions: {
    autoBlockOnCritical: true,
    autoBlockDurationMinutes: 1440,
  },
};

const parseListInput = (value) =>
  String(value || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);

const AdminSecurityCenter = ({ isDarkMode, showToast, adminUser, pageTransition }) => {
  const [activeSection, setActiveSection] = useState('overview');
  const [bundle, setBundle] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isSavingSettings, setIsSavingSettings] = useState(false);
  const [isActionBusy, setIsActionBusy] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [blockIpInput, setBlockIpInput] = useState('');
  const [eventsSearch, setEventsSearch] = useState('');
  const [alertsSearch, setAlertsSearch] = useState('');
  const [eventsSeverityFilter, setEventsSeverityFilter] = useState('all');
  const [alertsSeverityFilter, setAlertsSeverityFilter] = useState('all');
  const [draftSettings, setDraftSettings] = useState(DEFAULT_SETTINGS);

  const metrics = bundle?.overview?.metrics || {};
  const trends = bundle?.overview?.trends || {};
  const criticalAlerts = bundle?.overview?.latestCriticalAlerts || [];
  const securityEvents = useMemo(() => (Array.isArray(bundle?.events) ? bundle.events : []), [bundle?.events]);
  const securityAlerts = useMemo(() => (Array.isArray(bundle?.alerts) ? bundle.alerts : []), [bundle?.alerts]);
  const auditLogs = Array.isArray(bundle?.audit) ? bundle.audit : [];
  const blockedIps = Array.isArray(bundle?.blockedIps) ? bundle.blockedIps : [];

  const loadBundle = useCallback(async (silent = false) => {
    try {
      if (!silent) setIsLoading(true);
      setIsRefreshing(true);
      const payload = await fetchSecurityBundle();
      if (payload) {
        setBundle(payload);
        setDraftSettings(payload.settings || DEFAULT_SETTINGS);
      }
    } catch (error) {
      showToast(String(error?.message || 'Unable to load Security Center data.'), 'error');
    } finally {
      setIsRefreshing(false);
      setIsLoading(false);
    }
  }, [showToast]);

  useEffect(() => {
    loadBundle(false);
  }, [loadBundle]);

  const filteredEvents = useMemo(() => {
    const query = eventsSearch.trim().toLowerCase();
    return securityEvents.filter((entry) => {
      const severityOk = eventsSeverityFilter === 'all' || entry.severity === eventsSeverityFilter;
      const queryOk =
        !query ||
        String(entry.summary || '').toLowerCase().includes(query) ||
        String(entry.eventType || '').toLowerCase().includes(query) ||
        String(entry.ipAddress || '').toLowerCase().includes(query) ||
        String(entry.userEmail || '').toLowerCase().includes(query);
      return severityOk && queryOk;
    });
  }, [eventsSearch, eventsSeverityFilter, securityEvents]);

  const filteredAlerts = useMemo(() => {
    const query = alertsSearch.trim().toLowerCase();
    return securityAlerts.filter((entry) => {
      const severityOk = alertsSeverityFilter === 'all' || entry.severity === alertsSeverityFilter;
      const queryOk =
        !query ||
        String(entry.summary || '').toLowerCase().includes(query) ||
        String(entry.eventType || '').toLowerCase().includes(query) ||
        String(entry.id || '').toLowerCase().includes(query);
      return severityOk && queryOk;
    });
  }, [alertsSearch, alertsSeverityFilter, securityAlerts]);

  const runAction = async (action, data = {}, successMessage = 'Action completed successfully') => {
    try {
      setIsActionBusy(true);
      await performSecurityAction(action, data);
      showToast(successMessage, 'success');
      await loadBundle(true);
    } catch (error) {
      showToast(String(error?.message || 'Failed to execute action.'), 'error');
    } finally {
      setIsActionBusy(false);
    }
  };

  const handleSaveSettings = async () => {
    try {
      setIsSavingSettings(true);
      const payload = {
        ...draftSettings,
        telegram: {
          ...draftSettings.telegram,
          mutedEventTypes: Array.isArray(draftSettings.telegram?.mutedEventTypes)
            ? draftSettings.telegram.mutedEventTypes
            : parseListInput(draftSettings.telegram?.mutedEventTypesInput),
        },
      };
      await saveSecuritySettings(payload);
      showToast('Settings saved successfully', 'success');
      await loadBundle(true);
    } catch (error) {
      showToast(String(error?.message || 'Failed to save settings.'), 'error');
    } finally {
      setIsSavingSettings(false);
    }
  };

  const refreshBlockedIps = async () => {
    try {
      const latest = await fetchBlockedIps();
      setBundle((previous) => ({
        ...(previous || {}),
        blockedIps: latest,
      }));
    } catch {
      // ignore, normal reload flow still available
    }
  };

  const overviewCards = [
    {
      title: 'Alerts Today',
      value: Number(metrics.alertsToday) || 0,
      icon: Bell,
    },
    {
      title: 'Failed Login Attempts',
      value: Number(metrics.failedLoginsToday) || 0,
      icon: AlertTriangle,
    },
    {
      title: 'Password Reset Requests',
      value: Number(metrics.resetRequestsToday) || 0,
      icon: Lock,
    },
    {
      title: 'Blocked IPs',
      value: Number(metrics.blockedIpsCount) || 0,
      icon: Shield,
    },
    {
      title: 'Unresolved Alerts',
      value: Number(metrics.unresolvedAlerts) || 0,
      icon: FileWarning,
    },
  ];

  if (isLoading) {
    return (
      <div className={`rounded-3xl border p-8 ${isDarkMode ? 'border-slate-700 bg-slate-900/80 text-slate-100' : 'border-slate-200 bg-white text-slate-900'}`}>
        <div className="flex items-center gap-3 text-sm font-black">
          <RefreshCw size={16} className="animate-spin" />
          Loading Security Center...
        </div>
      </div>
    );
  }

  return (
    <Motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={pageTransition || { duration: 0.2 }}
      className="space-y-5"
    >
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-3">
        <div>
          <h2 className={`text-2xl font-black inline-flex items-center gap-2 ${isDarkMode ? 'text-slate-100' : 'text-slate-900'}`}>
            <ShieldAlert size={24} /> Security Center
          </h2>
          <p className={`text-sm font-bold mt-1 ${isDarkMode ? 'text-slate-300' : 'text-slate-500'}`}>
            Unified panel to monitor security events and control Telegram alerts.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className={`px-3 py-1.5 rounded-full text-xs font-black border ${isDarkMode ? 'border-slate-600 bg-slate-800 text-slate-100' : 'border-slate-200 bg-slate-50 text-slate-700'}`}>
            Admin: {adminUser?.email || 'admin'}
          </span>
          <span className={`px-3 py-1.5 rounded-full text-xs font-black border ${severityBadgeClass(metrics.riskLevel || 'low', isDarkMode)}`}>
            Risk Level: {String(metrics.riskLevel || 'low').toUpperCase()}
          </span>
          <button
            type="button"
            onClick={() => loadBundle(true)}
            disabled={isRefreshing}
            className={`inline-flex items-center gap-2 px-3 py-2 rounded-xl text-xs font-black border transition ${isDarkMode ? 'border-slate-600 text-slate-200 hover:bg-slate-800' : 'border-slate-300 text-slate-700 hover:bg-slate-50'}`}
          >
            <RefreshCw size={14} className={isRefreshing ? 'animate-spin' : ''} /> Refresh
          </button>
        </div>
      </div>

      <div className="flex gap-2 overflow-x-auto no-scrollbar pb-1">
        {SECTION_TABS.map((tab) => (
          <button
            key={tab.key}
            type="button"
            onClick={() => setActiveSection(tab.key)}
            className={`whitespace-nowrap px-4 py-2 rounded-2xl text-sm font-black border transition ${
              activeSection === tab.key
                ? isDarkMode
                  ? 'bg-emerald-500 text-slate-950 border-emerald-400'
                  : 'bg-slate-900 text-white border-slate-900'
                : isDarkMode
                ? 'border-slate-600 text-slate-200 hover:bg-slate-800'
                : 'border-slate-300 text-slate-600 hover:bg-slate-50'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeSection === 'overview' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 xl:grid-cols-5 gap-3">
            {overviewCards.map((card) => (
              <div key={card.title} className={`rounded-2xl border p-4 ${isDarkMode ? 'border-slate-700 bg-slate-900/80' : 'border-slate-200 bg-white'}`}>
                <div className={`w-10 h-10 rounded-xl flex items-center justify-center mb-3 ${isDarkMode ? 'bg-slate-800 text-emerald-300' : 'bg-emerald-50 text-emerald-600'}`}>
                  <card.icon size={18} />
                </div>
                <p className={`text-xs font-black ${isDarkMode ? 'text-slate-300' : 'text-slate-500'}`}>{card.title}</p>
                <p className={`text-2xl font-black ${isDarkMode ? 'text-slate-100' : 'text-slate-900'}`}>{card.value}</p>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
            <div className={`xl:col-span-2 rounded-2xl border p-4 ${isDarkMode ? 'border-slate-700 bg-slate-900/80' : 'border-slate-200 bg-white'}`}>
              <p className={`text-sm font-black mb-4 ${isDarkMode ? 'text-slate-100' : 'text-slate-900'}`}>Last 24 Hours</p>
              <div className="grid grid-cols-6 md:grid-cols-12 gap-2">
                {(trends.last24Hours || []).slice(-12).map((point) => (
                  <div key={point.label} className={`rounded-xl p-2 text-center ${isDarkMode ? 'bg-slate-800' : 'bg-slate-50'}`}>
                    <p className={`text-[11px] font-black ${isDarkMode ? 'text-slate-300' : 'text-slate-500'}`}>{point.label}</p>
                    <p className={`text-lg font-black ${isDarkMode ? 'text-slate-100' : 'text-slate-900'}`}>{point.count}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className={`rounded-2xl border p-4 ${isDarkMode ? 'border-slate-700 bg-slate-900/80' : 'border-slate-200 bg-white'}`}>
              <p className={`text-sm font-black mb-3 ${isDarkMode ? 'text-slate-100' : 'text-slate-900'}`}>Quick Actions</p>
              <div className="space-y-2">
                <button type="button" onClick={() => runAction('telegram_test', {}, 'Telegram test message sent')} disabled={isActionBusy} className="w-full text-right px-3 py-2 rounded-xl bg-blue-600 text-white text-xs font-black">Test Telegram</button>
                <button type="button" onClick={() => runAction('apply_control', { controls: { heightenedProtection: true } }, 'Protection level elevated')} disabled={isActionBusy} className="w-full text-right px-3 py-2 rounded-xl bg-amber-500 text-slate-950 text-xs font-black">Enable heightened protection</button>
                <button type="button" onClick={() => runAction('apply_control', { controls: { loginEnabled: false } }, 'Login temporarily disabled')} disabled={isActionBusy} className="w-full text-right px-3 py-2 rounded-xl bg-red-600 text-white text-xs font-black">Disable login temporarily</button>
              </div>
            </div>
          </div>

          <div className={`rounded-2xl border p-4 ${isDarkMode ? 'border-slate-700 bg-slate-900/80' : 'border-slate-200 bg-white'}`}>
            <p className={`text-sm font-black mb-3 ${isDarkMode ? 'text-slate-100' : 'text-slate-900'}`}>Latest Critical Alerts</p>
            {criticalAlerts.length === 0 ? (
              <p className={`text-sm font-bold ${isDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>No critical alerts at the moment.</p>
            ) : (
              <div className="space-y-2">
                {criticalAlerts.map((alert) => (
                  <button
                    key={alert.id}
                    type="button"
                    onClick={() => {
                      setSelectedAlert(alert);
                      setActiveSection('alerts');
                    }}
                    className={`w-full text-right rounded-xl border p-3 transition ${isDarkMode ? 'border-slate-700 hover:bg-slate-800/80' : 'border-slate-200 hover:bg-slate-50'}`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <p className={`text-sm font-black ${isDarkMode ? 'text-slate-100' : 'text-slate-900'}`}>{alert.summary}</p>
                      <span className={`text-[11px] font-black px-2 py-1 rounded-full border ${severityBadgeClass(alert.severity, isDarkMode)}`}>{String(alert.severity || '').toUpperCase()}</span>
                    </div>
                    <p className={`text-xs font-bold mt-1 ${isDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>{alert.eventType} - {alert.ipAddress || 'unknown'}</p>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {activeSection === 'logs' && (
        <div className={`rounded-2xl border p-4 space-y-4 ${isDarkMode ? 'border-slate-700 bg-slate-900/80' : 'border-slate-200 bg-white'}`}>
          <div className="flex flex-col md:flex-row gap-2">
            <div className={`flex-1 rounded-xl border px-3 py-2 flex items-center gap-2 ${isDarkMode ? 'border-slate-700 bg-slate-950 text-slate-200' : 'border-slate-200 bg-slate-50 text-slate-700'}`}>
              <Search size={15} />
              <input value={eventsSearch} onChange={(event) => setEventsSearch(event.target.value)} placeholder="Search logs..." className="flex-1 bg-transparent outline-none text-sm font-bold" />
            </div>
            <select value={eventsSeverityFilter} onChange={(event) => setEventsSeverityFilter(event.target.value)} className={`rounded-xl border px-3 py-2 text-sm font-black ${isDarkMode ? 'border-slate-700 bg-slate-950 text-slate-100' : 'border-slate-300 bg-white text-slate-800'}`}>
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>

          <div className="space-y-2 max-h-[55vh] overflow-auto">
            {filteredEvents.length === 0 ? (
              <div className={`rounded-xl border border-dashed p-5 text-center text-sm font-bold ${isDarkMode ? 'border-slate-700 text-slate-400' : 'border-slate-300 text-slate-500'}`}>No matching events found.</div>
            ) : (
              filteredEvents.slice(0, 150).map((event) => (
                <div key={event.id} className={`rounded-xl border p-3 ${isDarkMode ? 'border-slate-700 bg-slate-950/60' : 'border-slate-200 bg-slate-50/80'}`}>
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <p className={`text-sm font-black ${isDarkMode ? 'text-slate-100' : 'text-slate-900'}`}>{event.summary}</p>
                      <p className={`text-xs font-bold mt-1 ${isDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>{event.eventType} - {event.ipAddress || 'unknown'} - {event.createdAt}</p>
                    </div>
                    <span className={`text-[11px] font-black px-2 py-1 rounded-full border ${severityBadgeClass(event.severity, isDarkMode)}`}>{String(event.severity || '').toUpperCase()}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {activeSection === 'alerts' && (
        <div className={`rounded-2xl border p-4 space-y-4 ${isDarkMode ? 'border-slate-700 bg-slate-900/80' : 'border-slate-200 bg-white'}`}>
          <div className="flex flex-col md:flex-row gap-2">
            <div className={`flex-1 rounded-xl border px-3 py-2 flex items-center gap-2 ${isDarkMode ? 'border-slate-700 bg-slate-950 text-slate-200' : 'border-slate-200 bg-slate-50 text-slate-700'}`}>
              <Search size={15} />
              <input value={alertsSearch} onChange={(event) => setAlertsSearch(event.target.value)} placeholder="Search alerts..." className="flex-1 bg-transparent outline-none text-sm font-bold" />
            </div>
            <select value={alertsSeverityFilter} onChange={(event) => setAlertsSeverityFilter(event.target.value)} className={`rounded-xl border px-3 py-2 text-sm font-black ${isDarkMode ? 'border-slate-700 bg-slate-950 text-slate-100' : 'border-slate-300 bg-white text-slate-800'}`}>
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <div className="space-y-2 max-h-[55vh] overflow-auto">
            {filteredAlerts.length === 0 ? (
              <div className={`rounded-xl border border-dashed p-5 text-center text-sm font-bold ${isDarkMode ? 'border-slate-700 text-slate-400' : 'border-slate-300 text-slate-500'}`}>No matching alerts found.</div>
            ) : (
              filteredAlerts.slice(0, 120).map((alert) => (
                <div key={alert.id} className={`rounded-xl border p-3 ${isDarkMode ? 'border-slate-700 bg-slate-950/60' : 'border-slate-200 bg-slate-50/80'}`}>
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <p className={`text-sm font-black ${isDarkMode ? 'text-slate-100' : 'text-slate-900'}`}>{alert.summary}</p>
                      <p className={`text-xs font-bold mt-1 ${isDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>#{alert.id} - {alert.eventType} - {alert.ipAddress || 'unknown'}</p>
                    </div>
                    <span className={`text-[11px] font-black px-2 py-1 rounded-full border ${severityBadgeClass(alert.severity, isDarkMode)}`}>{String(alert.severity || '').toUpperCase()}</span>
                  </div>

                  <div className="mt-3 flex flex-wrap gap-2">
                    <button onClick={() => runAction('alert_mark_read', { alertId: alert.id }, 'Alert marked as read')} disabled={isActionBusy} className="px-3 py-1.5 rounded-lg text-xs font-black bg-blue-600 text-white">Mark as read</button>
                    <button onClick={() => runAction('alert_resolve', { alertId: alert.id }, 'Alert resolved')} disabled={isActionBusy} className="px-3 py-1.5 rounded-lg text-xs font-black bg-emerald-600 text-white">Resolve</button>
                    <button onClick={() => runAction('alert_archive', { alertId: alert.id }, 'Action completed successfully')} disabled={isActionBusy} className="px-3 py-1.5 rounded-lg text-xs font-black bg-slate-700 text-white">Archive</button>
                    <button onClick={() => setSelectedAlert(alert)} className={`px-3 py-1.5 rounded-lg text-xs font-black border ${isDarkMode ? 'border-slate-600 text-slate-200' : 'border-slate-300 text-slate-700'}`}>Details</button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {activeSection === 'incident' && (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className={`rounded-2xl border p-4 space-y-3 ${isDarkMode ? 'border-slate-700 bg-slate-900/80' : 'border-slate-200 bg-white'}`}>
            <h3 className={`text-lg font-black ${isDarkMode ? 'text-slate-100' : 'text-slate-900'}`}>Quick Actions</h3>
            <button onClick={() => runAction('apply_control', { controls: { loginEnabled: false } }, 'Login disabled')} className="w-full text-right px-4 py-2 rounded-xl bg-red-600 text-white text-sm font-black">Disable login temporarily</button>
            <button onClick={() => runAction('apply_control', { controls: { loginEnabled: true } }, 'Login enabled')} className="w-full text-right px-4 py-2 rounded-xl bg-emerald-600 text-white text-sm font-black">Enable login</button>
            <button onClick={() => runAction('apply_control', { controls: { resetPasswordEnabled: false } }, 'Password reset disabled')} className="w-full text-right px-4 py-2 rounded-xl bg-amber-500 text-slate-950 text-sm font-black">Disable reset password</button>
            <button onClick={() => runAction('apply_control', { controls: { resetPasswordEnabled: true } }, 'Password reset enabled')} className="w-full text-right px-4 py-2 rounded-xl bg-blue-600 text-white text-sm font-black">Enable reset password</button>
          </div>

          <div className={`rounded-2xl border p-4 space-y-3 ${isDarkMode ? 'border-slate-700 bg-slate-900/80' : 'border-slate-200 bg-white'}`}>
            <h3 className={`text-lg font-black ${isDarkMode ? 'text-slate-100' : 'text-slate-900'}`}>IP Management</h3>
            <div className={`rounded-xl border px-3 py-2 flex items-center gap-2 ${isDarkMode ? 'border-slate-700 bg-slate-950' : 'border-slate-300 bg-white'}`}>
              <TerminalSquare size={16} className={isDarkMode ? 'text-slate-300' : 'text-slate-500'} />
              <input value={blockIpInput} onChange={(event) => setBlockIpInput(event.target.value)} placeholder="Example: 102.44.10.3" className={`flex-1 bg-transparent outline-none text-sm font-bold ${isDarkMode ? 'text-slate-100' : 'text-slate-900'}`} />
            </div>
            <div className="flex gap-2">
              <button onClick={() => runAction('block_ip', { ipAddress: blockIpInput, reason: 'Manual block from incident tab' }, 'IP blocked successfully')} disabled={!blockIpInput || isActionBusy} className="flex-1 px-3 py-2 rounded-xl bg-red-600 text-white text-sm font-black disabled:opacity-50">Block</button>
              <button onClick={() => runAction('unblock_ip', { ipAddress: blockIpInput }, 'IP unblocked successfully')} disabled={!blockIpInput || isActionBusy} className="flex-1 px-3 py-2 rounded-xl bg-emerald-600 text-white text-sm font-black disabled:opacity-50">Unblock</button>
            </div>

            <div className={`rounded-xl border p-3 ${isDarkMode ? 'border-slate-700 bg-slate-950/60' : 'border-slate-200 bg-slate-50'}`}>
              <div className="flex items-center justify-between mb-2">
                <p className={`text-sm font-black ${isDarkMode ? 'text-slate-200' : 'text-slate-800'}`}>Blocked IP addresses</p>
                <button onClick={refreshBlockedIps} className={`text-xs font-black inline-flex items-center gap-1 ${isDarkMode ? 'text-slate-300' : 'text-slate-600'}`}><RefreshCw size={12} /> Refresh</button>
              </div>
              <div className="space-y-1 max-h-40 overflow-auto">
                {blockedIps.filter((entry) => entry.status === 'blocked').length === 0 ? (
                  <p className={`text-xs font-bold ${isDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>No blocked IP addresses.</p>
                ) : (
                  blockedIps.filter((entry) => entry.status === 'blocked').map((entry) => (
                    <div key={entry.id || entry.ipAddress} className={isDarkMode ? 'rounded-xl border border-slate-800 bg-slate-900/80 px-3 py-2' : 'rounded-xl border border-slate-200 bg-white px-3 py-2'}>
                      <div className="flex items-center justify-between gap-2 text-xs">
                        <span className={isDarkMode ? 'text-slate-200 font-black' : 'text-slate-700 font-black'}>{entry.ipAddress}</span>
                        <button onClick={() => runAction('unblock_ip', { ipAddress: entry.ipAddress }, 'IP unblocked')} className="px-2 py-1 rounded-lg bg-emerald-600 text-white font-black">Unblock</button>
                      </div>
                      <div className={isDarkMode ? 'mt-1 space-y-1 text-[11px] font-bold text-slate-400' : 'mt-1 space-y-1 text-[11px] font-bold text-slate-500'}>
                        <p>Reason: {entry.reason || 'n/a'}</p>
                        <p>Until: {entry.expiresAt ? new Date(entry.expiresAt).toLocaleString('fr-DZ') : 'manual release only'}</p>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {activeSection === 'audit' && (
        <div className={`rounded-2xl border p-4 ${isDarkMode ? 'border-slate-700 bg-slate-900/80' : 'border-slate-200 bg-white'}`}>
          <div className="space-y-2 max-h-[60vh] overflow-auto">
            {auditLogs.length === 0 ? (
              <p className={`text-sm font-bold ${isDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>No audit entries yet.</p>
            ) : (
              auditLogs.slice(0, 180).map((entry) => (
                <div key={entry.id} className={`rounded-xl border p-3 ${isDarkMode ? 'border-slate-700 bg-slate-950/60' : 'border-slate-200 bg-slate-50'}`}>
                  <div className="flex items-center justify-between gap-2">
                    <p className={`text-sm font-black ${isDarkMode ? 'text-slate-100' : 'text-slate-900'}`}>{entry.action}</p>
                    <Clock3 size={14} className={isDarkMode ? 'text-slate-400' : 'text-slate-500'} />
                  </div>
                  <p className={`text-xs font-bold mt-1 ${isDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>{entry.actorEmail || 'system'} - {entry.ipAddress || 'unknown'} - {entry.createdAt}</p>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {activeSection === 'settings' && (
        <div className={`rounded-2xl border p-4 space-y-5 ${isDarkMode ? 'border-slate-700 bg-slate-900/80' : 'border-slate-200 bg-white'}`}>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <label className="text-sm font-black">
              <span className={isDarkMode ? 'text-slate-200' : 'text-slate-700'}>failedLoginBurst</span>
              <input type="number" min="3" value={draftSettings.thresholds?.failedLoginBurst || 5} onChange={(event) => setDraftSettings((previous) => ({ ...previous, thresholds: { ...(previous.thresholds || {}), failedLoginBurst: Number(event.target.value) || 5 } }))} className={`mt-1 w-full rounded-xl border px-3 py-2 ${isDarkMode ? 'border-slate-700 bg-slate-950 text-slate-100' : 'border-slate-300 bg-white text-slate-900'}`} />
            </label>
            <label className="text-sm font-black">
              <span className={isDarkMode ? 'text-slate-200' : 'text-slate-700'}>resetPasswordBurst</span>
              <input type="number" min="2" value={draftSettings.thresholds?.resetPasswordBurst || 4} onChange={(event) => setDraftSettings((previous) => ({ ...previous, thresholds: { ...(previous.thresholds || {}), resetPasswordBurst: Number(event.target.value) || 4 } }))} className={`mt-1 w-full rounded-xl border px-3 py-2 ${isDarkMode ? 'border-slate-700 bg-slate-950 text-slate-100' : 'border-slate-300 bg-white text-slate-900'}`} />
            </label>
            <label className="text-sm font-black">
              <span className={isDarkMode ? 'text-slate-200' : 'text-slate-700'}>minimumSeverity</span>
              <select value={draftSettings.telegram?.minimumSeverity || 'medium'} onChange={(event) => setDraftSettings((previous) => ({ ...previous, telegram: { ...(previous.telegram || {}), minimumSeverity: event.target.value } }))} className={`mt-1 w-full rounded-xl border px-3 py-2 ${isDarkMode ? 'border-slate-700 bg-slate-950 text-slate-100' : 'border-slate-300 bg-white text-slate-900'}`}>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </label>
            <label className="text-sm font-black">
              <span className={isDarkMode ? 'text-slate-200' : 'text-slate-700'}>retentionDays</span>
              <input type="number" min="7" max="180" value={draftSettings.retentionDays || 15} onChange={(event) => setDraftSettings((previous) => ({ ...previous, retentionDays: Number(event.target.value) || 15 }))} className={`mt-1 w-full rounded-xl border px-3 py-2 ${isDarkMode ? 'border-slate-700 bg-slate-950 text-slate-100' : 'border-slate-300 bg-white text-slate-900'}`} />
            </label>
            <label className="text-sm font-black">
              <span className={isDarkMode ? 'text-slate-200' : 'text-slate-700'}>autoBlockDurationMinutes</span>
              <input type="number" min="15" max="10080" value={draftSettings.autoActions?.autoBlockDurationMinutes || 1440} onChange={(event) => setDraftSettings((previous) => ({ ...previous, autoActions: { ...(previous.autoActions || {}), autoBlockDurationMinutes: Number(event.target.value) || 1440 } }))} className={`mt-1 w-full rounded-xl border px-3 py-2 ${isDarkMode ? 'border-slate-700 bg-slate-950 text-slate-100' : 'border-slate-300 bg-white text-slate-900'}`} />
            </label>
            <label className="text-sm font-black md:col-span-2">
              <span className={isDarkMode ? 'text-slate-200' : 'text-slate-700'}>mutedEventTypes (comma separated)</span>
              <input type="text" value={Array.isArray(draftSettings.telegram?.mutedEventTypes) ? draftSettings.telegram.mutedEventTypes.join(', ') : ''} onChange={(event) => setDraftSettings((previous) => ({ ...previous, telegram: { ...(previous.telegram || {}), mutedEventTypes: parseListInput(event.target.value) } }))} className={`mt-1 w-full rounded-xl border px-3 py-2 ${isDarkMode ? 'border-slate-700 bg-slate-950 text-slate-100' : 'border-slate-300 bg-white text-slate-900'}`} />
            </label>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-2">
            <button type="button" onClick={() => setDraftSettings((previous) => ({ ...previous, telegram: { ...(previous.telegram || {}), enabled: !(previous.telegram?.enabled ?? true) } }))} className={`px-3 py-2 rounded-xl text-sm font-black ${draftSettings.telegram?.enabled ? 'bg-emerald-600 text-white' : 'bg-slate-600 text-white'}`}>{draftSettings.telegram?.enabled ? 'Telegram: ON' : 'Telegram: OFF'}</button>
            <button type="button" onClick={() => setDraftSettings((previous) => ({ ...previous, controls: { ...(previous.controls || {}), loginEnabled: !(previous.controls?.loginEnabled ?? true) } }))} className={`px-3 py-2 rounded-xl text-sm font-black ${draftSettings.controls?.loginEnabled ? 'bg-emerald-600 text-white' : 'bg-red-600 text-white'}`}>{draftSettings.controls?.loginEnabled ? 'Login Enabled' : 'Login Disabled'}</button>
            <button type="button" onClick={() => setDraftSettings((previous) => ({ ...previous, controls: { ...(previous.controls || {}), resetPasswordEnabled: !(previous.controls?.resetPasswordEnabled ?? true) } }))} className={`px-3 py-2 rounded-xl text-sm font-black ${draftSettings.controls?.resetPasswordEnabled ? 'bg-emerald-600 text-white' : 'bg-amber-500 text-slate-950'}`}>{draftSettings.controls?.resetPasswordEnabled ? 'Reset Enabled' : 'Reset Disabled'}</button>
            <button type="button" onClick={() => setDraftSettings((previous) => ({ ...previous, autoActions: { ...(previous.autoActions || {}), autoBlockOnCritical: !(previous.autoActions?.autoBlockOnCritical ?? true) } }))} className={`px-3 py-2 rounded-xl text-sm font-black ${(draftSettings.autoActions?.autoBlockOnCritical ?? true) ? 'bg-rose-600 text-white' : 'bg-slate-600 text-white'}`}>{(draftSettings.autoActions?.autoBlockOnCritical ?? true) ? 'Auto Block: ON' : 'Auto Block: OFF'}</button>
          </div>

          <div className="flex justify-end gap-2">
            <button type="button" onClick={() => runAction('telegram_test', {}, 'Telegram test message sent')} className="px-4 py-2 rounded-xl bg-blue-600 text-white text-sm font-black">Test Telegram</button>
            <button type="button" onClick={handleSaveSettings} disabled={isSavingSettings} className="px-4 py-2 rounded-xl bg-slate-900 text-white text-sm font-black disabled:opacity-60">{isSavingSettings ? 'Saving...' : 'Save Settings'}</button>
          </div>
        </div>
      )}

      {selectedAlert && (
        <div className="fixed inset-0 z-50 bg-slate-950/60 flex items-center justify-center p-4" onClick={() => setSelectedAlert(null)}>
          <div className={`w-full max-w-xl rounded-2xl border p-5 ${isDarkMode ? 'border-slate-700 bg-slate-900 text-slate-100' : 'border-slate-200 bg-white text-slate-900'}`} onClick={(event) => event.stopPropagation()}>
            <div className="flex items-start justify-between gap-3 mb-4">
              <h4 className="text-lg font-black inline-flex items-center gap-2"><Eye size={18} /> Alert Details</h4>
              <button className={`text-xs font-black ${isDarkMode ? 'text-slate-300' : 'text-slate-500'}`} onClick={() => setSelectedAlert(null)}>Close</button>
            </div>
            <div className="space-y-2 text-sm font-bold">
              <p><span className="font-black">ID:</span> {selectedAlert.id}</p>
              <p><span className="font-black">Type:</span> {selectedAlert.eventType}</p>
              <p><span className="font-black">Summary:</span> {selectedAlert.summary}</p>
              <p><span className="font-black">Severity:</span> {selectedAlert.severity}</p>
              <p><span className="font-black">IP:</span> {selectedAlert.ipAddress || 'unknown'}</p>
              <p><span className="font-black">Time:</span> {selectedAlert.createdAt}</p>
              <p><span className="font-black">Risk Score:</span> {selectedAlert.riskScore || 0}/100</p>
            </div>
          </div>
        </div>
      )}
    </Motion.div>
  );
};

export default AdminSecurityCenter;

