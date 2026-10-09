/**
 * Advanced Live Stats Manager for HVM Panel Frontend
 * Handles real-time statistics updates with WebSocket and fallback polling
 */

class LiveStatsManager {
    constructor(options = {}) {
        this.socket = null;
        this.isConnected = false;
        this.subscriptions = new Set();
        this.fallbackInterval = null;
        this.retryCount = 0;
        this.maxRetries = 5;
        this.retryDelay = 1000;
        
        // Configuration
        this.config = {
            socketioEnabled: options.socketioEnabled || false,
            fallbackPollingInterval: options.fallbackPollingInterval || 5000,
            reconnectInterval: options.reconnectInterval || 3000,
            maxReconnectAttempts: options.maxReconnectAttempts || 10,
            ...options
        };
        
        // Stats cache
        this.statsCache = new Map();
        this.cacheTimeout = 30000; // 30 seconds
        
        // Event handlers
        this.eventHandlers = {
            'vps_stats_update': [],
            'dashboard_stats_update': [],
            'node_stats_update': [],
            'connection_status': []
        };
        
        this.init();
    }
    
    init() {
        if (this.config.socketioEnabled && typeof io !== 'undefined') {
            this.initWebSocket();
        } else {
            console.log('WebSocket not available, using polling fallback');
            this.initPollingFallback();
        }
        
        // Handle page visibility changes
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.pauseUpdates();
            } else {
                this.resumeUpdates();
            }
        });
        
        // Handle window focus/blur
        window.addEventListener('focus', () => this.resumeUpdates());
        window.addEventListener('blur', () => this.pauseUpdates());
    }
    
    initWebSocket() {
        try {
            this.socket = io();
            
            this.socket.on('connect', () => {
                console.log('Live stats WebSocket connected');
                this.isConnected = true;
                this.retryCount = 0;
                this.emit('connection_status', { connected: true, method: 'websocket' });
                
                // Resubscribe to all active subscriptions
                this.resubscribeAll();
            });
            
            this.socket.on('disconnect', () => {
                console.log('Live stats WebSocket disconnected');
                this.isConnected = false;
                this.emit('connection_status', { connected: false, method: 'websocket' });
                
                // Start fallback polling
                this.initPollingFallback();
            });
            
            this.socket.on('reconnect', () => {
                console.log('Live stats WebSocket reconnected');
                this.isConnected = true;
                this.emit('connection_status', { connected: true, method: 'websocket' });
                
                // Stop fallback polling
                this.stopPollingFallback();
            });
            
            // Handle stats updates
            this.socket.on('vps_stats_update', (data) => {
                this.handleVPSStatsUpdate(data);
            });
            
            this.socket.on('dashboard_stats_update', (data) => {
                this.handleDashboardStatsUpdate(data);
            });
            
            this.socket.on('node_stats_update', (data) => {
                this.handleNodeStatsUpdate(data);
            });
            
            this.socket.on('connect_error', (error) => {
                console.error('WebSocket connection error:', error);
                this.handleConnectionError();
            });
            
        } catch (error) {
            console.error('Failed to initialize WebSocket:', error);
            this.initPollingFallback();
        }
    }
    
    initPollingFallback() {
        if (this.fallbackInterval) {
            clearInterval(this.fallbackInterval);
        }
        
        console.log('Starting polling fallback for live stats');
        this.emit('connection_status', { connected: true, method: 'polling' });
        
        this.fallbackInterval = setInterval(() => {
            this.pollStats();
        }, this.config.fallbackPollingInterval);
        
        // Initial poll
        this.pollStats();
    }
    
    stopPollingFallback() {
        if (this.fallbackInterval) {
            clearInterval(this.fallbackInterval);
            this.fallbackInterval = null;
            console.log('Stopped polling fallback');
        }
    }
    
    async pollStats() {
        try {
            // Poll dashboard stats if subscribed
            if (this.subscriptions.has('dashboard_stats')) {
                const response = await fetch('/dashboard/stats');
                if (response.ok) {
                    const data = await response.json();
                    if (data.success) {
                        this.handleDashboardStatsUpdate({
                            stats: data.stats,
                            timestamp: data.timestamp,
                            cached: data.cached || false
                        });
                    }
                }
            }
            
            // Poll individual VPS stats
            for (const subscription of this.subscriptions) {
                if (subscription.startsWith('vps_')) {
                    const vpsId = subscription.replace('vps_', '');
                    try {
                        const response = await fetch(`/vps/${vpsId}/stats`);
                        if (response.ok) {
                            const data = await response.json();
                            if (data.success) {
                                this.handleVPSStatsUpdate({
                                    vps_id: parseInt(vpsId),
                                    stats: data.stats
                                });
                            }
                        }
                    } catch (error) {
                        console.error(`Error polling VPS ${vpsId} stats:`, error);
                    }
                }
            }
            
        } catch (error) {
            console.error('Error in polling fallback:', error);
        }
    }
    
    handleConnectionError() {
        this.retryCount++;
        
        if (this.retryCount <= this.maxRetries) {
            console.log(`Retrying connection (${this.retryCount}/${this.maxRetries})...`);
            setTimeout(() => {
                if (!this.isConnected) {
                    this.initPollingFallback();
                }
            }, this.retryDelay * this.retryCount);
        } else {
            console.log('Max reconnection attempts reached, using polling fallback');
            this.initPollingFallback();
        }
    }
    
    // Subscription management
    subscribeToDashboardStats() {
        this.subscriptions.add('dashboard_stats');
        
        if (this.isConnected && this.socket) {
            this.socket.emit('subscribe_dashboard_stats');
        }
    }
    
    unsubscribeFromDashboardStats() {
        this.subscriptions.delete('dashboard_stats');
        
        if (this.isConnected && this.socket) {
            this.socket.emit('unsubscribe_dashboard_stats');
        }
    }
    
    subscribeToVPSStats(vpsId) {
        const subscription = `vps_${vpsId}`;
        this.subscriptions.add(subscription);
        
        if (this.isConnected && this.socket) {
            this.socket.emit('join_vps_room', { vps_id: vpsId });
        }
    }
    
    unsubscribeFromVPSStats(vpsId) {
        const subscription = `vps_${vpsId}`;
        this.subscriptions.delete(subscription);
        
        if (this.isConnected && this.socket) {
            this.socket.emit('leave_vps_room', { vps_id: vpsId });
        }
    }
    
    subscribeToNodeStats() {
        this.subscriptions.add('node_stats');
        
        if (this.isConnected && this.socket) {
            this.socket.emit('subscribe_node_stats');
        }
    }
    
    unsubscribeFromNodeStats() {
        this.subscriptions.delete('node_stats');
        
        if (this.isConnected && this.socket) {
            this.socket.emit('unsubscribe_node_stats');
        }
    }
    
    resubscribeAll() {
        for (const subscription of this.subscriptions) {
            if (subscription === 'dashboard_stats') {
                this.socket.emit('subscribe_dashboard_stats');
            } else if (subscription === 'node_stats') {
                this.socket.emit('subscribe_node_stats');
            } else if (subscription.startsWith('vps_')) {
                const vpsId = subscription.replace('vps_', '');
                this.socket.emit('join_vps_room', { vps_id: parseInt(vpsId) });
            }
        }
    }
    
    // Event handling
    on(event, handler) {
        if (!this.eventHandlers[event]) {
            this.eventHandlers[event] = [];
        }
        this.eventHandlers[event].push(handler);
    }
    
    off(event, handler) {
        if (this.eventHandlers[event]) {
            const index = this.eventHandlers[event].indexOf(handler);
            if (index > -1) {
                this.eventHandlers[event].splice(index, 1);
            }
        }
    }
    
    emit(event, data) {
        if (this.eventHandlers[event]) {
            this.eventHandlers[event].forEach(handler => {
                try {
                    handler(data);
                } catch (error) {
                    console.error(`Error in event handler for ${event}:`, error);
                }
            });
        }
    }
    
    // Stats update handlers
    handleVPSStatsUpdate(data) {
        const { vps_id, stats } = data;
        
        // Cache the stats
        this.statsCache.set(`vps_${vps_id}`, {
            stats,
            timestamp: Date.now()
        });
        
        // Update UI elements
        this.updateVPSStatsUI(vps_id, stats);
        
        // Emit event for custom handlers
        this.emit('vps_stats_update', data);
    }
    
    handleDashboardStatsUpdate(data) {
        const { stats, timestamp, cached } = data;
        
        // Update each VPS in the dashboard
        Object.entries(stats).forEach(([vpsId, vpsStats]) => {
            this.updateVPSStatsUI(parseInt(vpsId), vpsStats);
        });
        
        // Update connection indicator
        this.updateConnectionIndicator(cached);
        
        // Emit event for custom handlers
        this.emit('dashboard_stats_update', data);
    }
    
    handleNodeStatsUpdate(data) {
        const { nodes, timestamp } = data;
        
        // Update node stats in admin interface
        Object.entries(nodes).forEach(([nodeId, nodeStats]) => {
            this.updateNodeStatsUI(parseInt(nodeId), nodeStats);
        });
        
        // Emit event for custom handlers
        this.emit('node_stats_update', data);
    }
    
    // UI update methods
    updateVPSStatsUI(vpsId, stats) {
        // Update status indicator
        const statusElement = document.querySelector(`[data-vps-id="${vpsId}"] .status-indicator`);
        if (statusElement) {
            statusElement.className = `status-indicator status-${stats.status}`;
            
            const statusText = statusElement.querySelector('.status-text');
            if (statusText) {
                statusText.textContent = stats.status.charAt(0).toUpperCase() + stats.status.slice(1);
            }
        }
        
        // Update CPU usage
        const cpuElement = document.querySelector(`[data-vps-id="${vpsId}"] .cpu-usage`);
        if (cpuElement) {
            const cpuBar = cpuElement.querySelector('.progress-bar');
            const cpuText = cpuElement.querySelector('.usage-text');
            
            if (cpuBar) {
                cpuBar.style.width = `${stats.cpu}%`;
                cpuBar.className = `progress-bar ${this.getUsageClass(stats.cpu)}`;
            }
            
            if (cpuText) {
                cpuText.textContent = `${stats.cpu.toFixed(1)}%`;
            }
        }
        
        // Update RAM usage
        const ramElement = document.querySelector(`[data-vps-id="${vpsId}"] .ram-usage`);
        if (ramElement) {
            const ramBar = ramElement.querySelector('.progress-bar');
            const ramText = ramElement.querySelector('.usage-text');
            const ramPct = stats.ram?.pct || 0;
            
            if (ramBar) {
                ramBar.style.width = `${ramPct}%`;
                ramBar.className = `progress-bar ${this.getUsageClass(ramPct)}`;
            }
            
            if (ramText) {
                ramText.textContent = `${ramPct.toFixed(1)}%`;
            }
        }
        
        // Update connection issue indicator
        const connectionElement = document.querySelector(`[data-vps-id="${vpsId}"] .connection-status`);
        if (connectionElement) {
            if (stats.connection_issue) {
                connectionElement.style.display = 'inline-block';
                connectionElement.title = 'Connection issue - showing cached data';
            } else {
                connectionElement.style.display = 'none';
            }
        }
    }
    
    updateNodeStatsUI(nodeId, nodeStats) {
        const nodeElement = document.querySelector(`[data-node-id="${nodeId}"]`);
        if (!nodeElement) return;
        
        // Update online status
        const statusElement = nodeElement.querySelector('.node-status');
        if (statusElement) {
            statusElement.className = `node-status ${nodeStats.online ? 'online' : 'offline'}`;
            statusElement.textContent = nodeStats.status;
        }
        
        // Update CPU usage
        const cpuElement = nodeElement.querySelector('.cpu-usage .progress-bar');
        if (cpuElement) {
            cpuElement.style.width = `${nodeStats.cpu}%`;
            cpuElement.className = `progress-bar ${this.getUsageClass(nodeStats.cpu)}`;
        }
        
        // Update RAM usage
        const ramElement = nodeElement.querySelector('.ram-usage .progress-bar');
        if (ramElement) {
            ramElement.style.width = `${nodeStats.ram_pct}%`;
            ramElement.className = `progress-bar ${this.getUsageClass(nodeStats.ram_pct)}`;
        }
        
        // Update VPS count
        const vpsCountElement = nodeElement.querySelector('.vps-count');
        if (vpsCountElement) {
            vpsCountElement.textContent = `${nodeStats.vps_count} / ${nodeStats.total_vps || '?'}`;
        }
    }
    
    updateConnectionIndicator(cached = false) {
        const indicator = document.querySelector('.live-stats-indicator');
        if (indicator) {
            if (this.isConnected && !cached) {
                indicator.className = 'live-stats-indicator connected';
                indicator.title = 'Live stats connected';
            } else if (cached) {
                indicator.className = 'live-stats-indicator cached';
                indicator.title = 'Showing cached data';
            } else {
                indicator.className = 'live-stats-indicator disconnected';
                indicator.title = 'Live stats disconnected';
            }
        }
    }
    
    getUsageClass(percentage) {
        if (percentage >= 90) return 'danger';
        if (percentage >= 75) return 'warning';
        return 'success';
    }
    
    // Lifecycle methods
    pauseUpdates() {
        if (this.fallbackInterval) {
            clearInterval(this.fallbackInterval);
            this.fallbackInterval = null;
        }
    }
    
    resumeUpdates() {
        if (!this.isConnected && !this.fallbackInterval) {
            this.initPollingFallback();
        }
    }
    
    destroy() {
        this.pauseUpdates();
        
        if (this.socket) {
            this.socket.disconnect();
        }
        
        this.subscriptions.clear();
        this.statsCache.clear();
        this.eventHandlers = {};
    }
    
    // Utility methods
    getCachedStats(vpsId) {
        const cached = this.statsCache.get(`vps_${vpsId}`);
        if (cached && (Date.now() - cached.timestamp) < this.cacheTimeout) {
            return cached.stats;
        }
        return null;
    }
    
    getConnectionStatus() {
        return {
            connected: this.isConnected,
            method: this.isConnected ? 'websocket' : (this.fallbackInterval ? 'polling' : 'disconnected'),
            subscriptions: Array.from(this.subscriptions)
        };
    }
}

// Global instance
window.liveStatsManager = null;

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Check if live stats should be enabled
    const socketioAvailable = window.CONFIG?.socketioAvailable || false;
    
    window.liveStatsManager = new LiveStatsManager({
        socketioEnabled: socketioAvailable,
        fallbackPollingInterval: 5000,
        reconnectInterval: 3000,
        maxReconnectAttempts: 10
    });
    
    // Auto-subscribe based on page content
    if (document.querySelector('.vps-list') || document.querySelector('.dashboard-stats')) {
        window.liveStatsManager.subscribeToDashboardStats();
    }
    
    if (document.querySelector('.admin-nodes')) {
        window.liveStatsManager.subscribeToNodeStats();
    }
    
    // Subscribe to individual VPS if on VPS detail page
    const vpsDetailElement = document.querySelector('[data-vps-id]');
    if (vpsDetailElement) {
        const vpsId = vpsDetailElement.dataset.vpsId;
        if (vpsId) {
            window.liveStatsManager.subscribeToVPSStats(parseInt(vpsId));
        }
    }
    
    console.log('Live Stats Manager initialized');
});

// Clean up on page unload
window.addEventListener('beforeunload', () => {
    if (window.liveStatsManager) {
        window.liveStatsManager.destroy();
    }
});