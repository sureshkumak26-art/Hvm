#!/usr/bin/env python3
"""
Advanced Live Stats Manager for StrenoxCloud Panel
Handles real-time statistics, caching, and performance optimization
"""

import asyncio
import threading
import time
import json
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

@dataclass
class StatsData:
    """Structured stats data container"""
    vps_id: int
    container_name: str
    node_id: int
    status: str
    cpu: float
    ram_used: int
    ram_total: int
    ram_pct: float
    disk_used: str
    disk_total: str
    disk_pct: str
    uptime: str
    processes: int
    network_rx: int = 0
    network_tx: int = 0
    private_ip: str = "N/A"
    load_avg_1: float = 0.0
    load_avg_5: float = 0.0
    load_avg_15: float = 0.0
    timestamp: float = 0.0
    connection_issue: bool = False
    raw_status: str = ""

@dataclass
class NodeStats:
    """Node statistics container"""
    node_id: int
    name: str
    online: bool
    status: str
    cpu: float = 0.0
    ram_pct: float = 0.0
    disk_pct: float = 0.0
    vps_count: int = 0
    total_vps: int = 0
    last_seen: str = ""
    health_status: str = "unknown"
    circuit_breaker_open: bool = False
    timestamp: float = 0.0

class LiveStatsManager:
    """Advanced live statistics manager with caching and real-time updates"""
    
    def __init__(self, socketio=None):
        self.socketio = socketio
        self.vps_stats_cache: Dict[int, StatsData] = {}
        self.node_stats_cache: Dict[int, NodeStats] = {}
        self.update_queues: Dict[str, asyncio.Queue] = defaultdict(asyncio.Queue)
        self.active_subscriptions: Dict[str, set] = defaultdict(set)
        self.stats_lock = threading.RLock()
        self.running = False
        self.update_tasks: List[asyncio.Task] = []
        
        # Performance settings
        self.vps_update_interval = 3
        self.node_update_interval = 10
        self.cache_ttl = 30
        self.batch_size = 10
        self.max_concurrent_requests = 5
        
        # Metrics
        self.metrics = {
            'total_updates': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'errors': 0,
            'last_update': 0
        }
        
        logger.info("LiveStatsManager initialized")
    
    def start(self):
        """Start the live stats manager"""
        if self.running:
            return
        
        self.running = True
        self.background_thread = threading.Thread(target=self._run_background_loop, daemon=True)
        self.background_thread.start()
        logger.info("LiveStatsManager started")
    
    def _run_background_loop(self):
        """Run the background event loop in a separate thread"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._start_background_tasks())
        except Exception as e:
            logger.error(f"Error in background loop: {e}")
        finally:
            try:
                loop.close()
            except:
                pass
    
    def stop(self):
        """Stop the live stats manager"""
        self.running = False
        for task in self.update_tasks:
            if not task.done():
                task.cancel()
        self.update_tasks.clear()
        logger.info("LiveStatsManager stopped")
    
    async def _start_background_tasks(self):
        """Start background update tasks"""
        self.update_tasks = [
            asyncio.create_task(self._vps_stats_updater()),
            asyncio.create_task(self._node_stats_updater()),
            asyncio.create_task(self._cache_cleaner()),
            asyncio.create_task(self._metrics_reporter())
        ]
        await asyncio.gather(*self.update_tasks, return_exceptions=True)

    async def _vps_stats_updater(self):
        """Background task to update VPS statistics."""
        try:
            from hvm import get_all_vps, get_container_stats, is_vps_suspended
        except ImportError as e:
            logger.error(f"Failed to import required functions from hvm: {e}")
            return

        # VPS in any of these statuses can't (or shouldn't) be polled.
        # Polling them just generates `Instance not found` / `Operation not
        # permitted` errors which flood the node-agent log with 500s.
        SKIP_STATUSES = {
            'suspended',     # admin paused — don't bother
            'installing',    # creation in progress — container may not exist yet
            'reinstalling',  # being recreated — same reason
            'transferring',  # migration in progress
            'failed',        # creation failed — container doesn't exist
            'missing',       # marked missing by us — see _update_vps_stats below
            'deleted',       # being deleted
        }

        # Per-VPS consecutive-failure counter. After enough misses we mark
        # the VPS row as 'missing' in the DB so it stops being polled at all.
        if not hasattr(self, '_vps_miss_count'):
            self._vps_miss_count = {}
        MISS_THRESHOLD = 3

        while self.running:
            try:
                all_vps = get_all_vps()
                active_vps = [
                    v for v in all_vps
                    if (v.get('status') or '').lower() not in SKIP_STATUSES
                    and not is_vps_suspended(v)
                ]

                for i in range(0, len(active_vps), self.batch_size):
                    batch = active_vps[i:i + self.batch_size]
                    semaphore = asyncio.Semaphore(self.max_concurrent_requests)
                    tasks = [
                        self._update_vps_stats(vps, semaphore, get_container_stats)
                        for vps in batch
                    ]
                    await asyncio.gather(*tasks, return_exceptions=True)
                    await asyncio.sleep(0.5)

                if self.socketio:
                    self._emit_batch_stats_update()

                self.metrics['last_update'] = time.time()
            except Exception as e:
                logger.error(f"Error in VPS stats updater: {e}")
                self.metrics['errors'] += 1

            await asyncio.sleep(self.vps_update_interval)
    
    async def _update_vps_stats(self, vps: Dict, semaphore: asyncio.Semaphore, get_container_stats):
        """Update statistics for a single VPS."""
        async with semaphore:
            try:
                cached_stats = self.vps_stats_cache.get(vps['id'])
                if cached_stats and (time.time() - cached_stats.timestamp) < self.cache_ttl:
                    self.metrics['cache_hits'] += 1
                    return cached_stats

                self.metrics['cache_misses'] += 1
                stats = await asyncio.wait_for(
                    get_container_stats(vps['container_name'], vps['node_id']),
                    timeout=8.0
                )

                # Success — reset the consecutive-miss counter.
                if not hasattr(self, '_vps_miss_count'):
                    self._vps_miss_count = {}
                self._vps_miss_count.pop(vps['id'], None)

                stats_data = self._convert_to_stats_data(vps, stats)
                with self.stats_lock:
                    self.vps_stats_cache[vps['id']] = stats_data

                self.metrics['total_updates'] += 1

                if self.socketio and f"vps_{vps['id']}" in self.active_subscriptions:
                    self._emit_vps_stats_update(vps['id'], stats_data)

                return stats_data
            except asyncio.TimeoutError:
                logger.warning(f"Timeout updating stats for VPS {vps['id']}")
                return self._create_error_stats(vps, "timeout")
            except Exception as e:
                # If the container is gone from the host, mark the VPS row as
                # 'missing' after a few consecutive failures so we stop
                # spamming `lxc info` against a non-existent instance.
                msg = str(e).lower()
                if any(s in msg for s in (
                    "instance not found", "not found",
                    "doesn't exist", "does not exist", "no such",
                )):
                    if not hasattr(self, '_vps_miss_count'):
                        self._vps_miss_count = {}
                    self._vps_miss_count[vps['id']] = (
                        self._vps_miss_count.get(vps['id'], 0) + 1
                    )
                    misses = self._vps_miss_count[vps['id']]
                    if misses >= 3:
                        try:
                            from hvm import update_vps
                            update_vps(vps['id'], status='missing')
                            logger.warning(
                                f"VPS {vps['id']} ({vps.get('container_name')}) "
                                f"marked 'missing' after {misses} consecutive "
                                f"`Instance not found` errors. Stats polling "
                                f"will now skip it."
                            )
                        except Exception as upd_e:
                            logger.error(
                                f"Could not mark VPS {vps['id']} as missing: {upd_e}"
                            )
                        # Reset so we don't re-mark on every poll.
                        self._vps_miss_count.pop(vps['id'], None)
                    else:
                        # Quiet during the grace window so the log doesn't
                        # fill with the same line.
                        logger.info(
                            f"VPS {vps['id']} container not found "
                            f"({misses}/3 consecutive); will mark missing soon."
                        )
                else:
                    logger.error(f"Error updating stats for VPS {vps['id']}: {e}")
                return self._create_error_stats(vps, "error")

    async def _node_stats_updater(self):
        """Background task to update node statistics"""
        try:
            from hvm import get_nodes, get_node_status, get_current_vps_count, get_node_health_status
        except ImportError as e:
            logger.error(f"Failed to import required functions from hvm: {e}")
            return
        
        while self.running:
            try:
                nodes = get_nodes()
                semaphore = asyncio.Semaphore(self.max_concurrent_requests)
                tasks = [
                    self._update_node_stats(node, semaphore, get_node_status, get_current_vps_count, get_node_health_status)
                    for node in nodes
                ]
                await asyncio.gather(*tasks, return_exceptions=True)
                
                if self.socketio:
                    self._emit_node_stats_update()
            except Exception as e:
                logger.error(f"Error in node stats updater: {e}")
                self.metrics['errors'] += 1
            
            await asyncio.sleep(self.node_update_interval)
    
    async def _update_node_stats(self, node: Dict, semaphore: asyncio.Semaphore, get_node_status, get_current_vps_count, get_node_health_status):
        """Update statistics for a single node"""
        async with semaphore:
            try:
                cached_stats = self.node_stats_cache.get(node['id'])
                if cached_stats and (time.time() - cached_stats.timestamp) < self.cache_ttl:
                    return cached_stats
                
                status = await get_node_status(node['id'])
                vps_count = get_current_vps_count(node['id'])
                health_status = get_node_health_status(node['id'])
                
                node_stats = NodeStats(
                    node_id=node['id'],
                    name=node['name'],
                    online=status.get('online', False),
                    status=status.get('status', 'Unknown'),
                    cpu=status.get('stats', {}).get('cpu', 0.0),
                    ram_pct=status.get('stats', {}).get('ram', {}).get('percent', 0.0),
                    disk_pct=status.get('stats', {}).get('disk', {}).get('percent', 0.0),
                    vps_count=vps_count,
                    total_vps=node.get('total_vps', 0),
                    last_seen=status.get('last_seen', ''),
                    health_status=health_status['status'],
                    circuit_breaker_open=health_status['circuit_breaker_open'],
                    timestamp=time.time()
                )
                
                with self.stats_lock:
                    self.node_stats_cache[node['id']] = node_stats
                
                return node_stats
            except Exception as e:
                logger.error(f"Error updating stats for node {node['id']}: {e}")
                return NodeStats(
                    node_id=node['id'],
                    name=node['name'],
                    online=False,
                    status='Error',
                    timestamp=time.time()
                )
    
    async def _cache_cleaner(self):
        """Clean expired cache entries"""
        while self.running:
            try:
                current_time = time.time()
                with self.stats_lock:
                    expired_vps = [
                        vps_id for vps_id, stats in self.vps_stats_cache.items()
                        if current_time - stats.timestamp > self.cache_ttl * 2
                    ]
                    for vps_id in expired_vps:
                        del self.vps_stats_cache[vps_id]
                    
                    expired_nodes = [
                        node_id for node_id, stats in self.node_stats_cache.items()
                        if current_time - stats.timestamp > self.cache_ttl * 2
                    ]
                    for node_id in expired_nodes:
                        del self.node_stats_cache[node_id]
                
                if expired_vps or expired_nodes:
                    logger.debug(f"Cleaned {len(expired_vps)} VPS and {len(expired_nodes)} node cache entries")
            except Exception as e:
                logger.error(f"Error in cache cleaner: {e}")
            
            await asyncio.sleep(60)
    
    async def _metrics_reporter(self):
        """Report performance metrics"""
        while self.running:
            try:
                logger.info(f"LiveStats Metrics: {self.metrics}")
                self.metrics['total_updates'] = 0
                self.metrics['cache_hits'] = 0
                self.metrics['cache_misses'] = 0
                self.metrics['errors'] = 0
            except Exception as e:
                logger.error(f"Error in metrics reporter: {e}")
            
            await asyncio.sleep(300)

    def _convert_to_stats_data(self, vps: Dict, stats: Dict) -> StatsData:
        """Convert raw stats to structured StatsData"""
        ram = stats.get('ram', {})
        network = stats.get('network', {})
        load_avg = stats.get('load_average', {})
        
        return StatsData(
            vps_id=vps['id'],
            container_name=vps['container_name'],
            node_id=vps['node_id'],
            status=stats.get('status', 'unknown'),
            cpu=float(stats.get('cpu', 0.0)),
            ram_used=ram.get('used', 0),
            ram_total=ram.get('total', 0),
            ram_pct=float(ram.get('pct', 0.0)),
            disk_used=str(stats.get('disk', {}).get('used', '0')),
            disk_total=str(stats.get('disk', {}).get('size', '0')),
            disk_pct=str(stats.get('disk', {}).get('use_percent', '0%')),
            uptime=str(stats.get('uptime', 'Unknown')),
            processes=int(stats.get('processes', 0)),
            network_rx=network.get('rx_bytes', 0),
            network_tx=network.get('tx_bytes', 0),
            private_ip=str(stats.get('private_ip', 'N/A')),
            load_avg_1=float(load_avg.get('1min', 0.0)),
            load_avg_5=float(load_avg.get('5min', 0.0)),
            load_avg_15=float(load_avg.get('15min', 0.0)),
            timestamp=time.time(),
            connection_issue=stats.get('connection_issue', False),
            raw_status=str(stats.get('raw_status', ''))
        )
    
    def _create_error_stats(self, vps: Dict, error_type: str) -> StatsData:
        """Create error stats data"""
        return StatsData(
            vps_id=vps['id'],
            container_name=vps['container_name'],
            node_id=vps['node_id'],
            status=vps.get('status', 'stopped'),
            cpu=0.0,
            ram_used=0,
            ram_total=0,
            ram_pct=0.0,
            disk_used='0',
            disk_total='0',
            disk_pct='0%',
            uptime=error_type.title(),
            processes=0,
            timestamp=time.time(),
            connection_issue=True,
            raw_status=error_type
        )
    
    def _emit_vps_stats_update(self, vps_id: int, stats: StatsData):
        """Emit VPS stats update via WebSocket"""
        if not self.socketio:
            return
        try:
            self.socketio.emit('vps_stats_update', {
                'vps_id': vps_id,
                'stats': asdict(stats)
            }, room=f'vps_{vps_id}')
        except Exception as e:
            logger.error(f"Error emitting VPS stats update: {e}")
    
    def _emit_batch_stats_update(self):
        """Emit batch stats update for dashboard"""
        if not self.socketio:
            return
        try:
            batch_data = {}
            with self.stats_lock:
                for vps_id, stats in self.vps_stats_cache.items():
                    batch_data[vps_id] = {
                        'status': stats.status,
                        'cpu': stats.cpu,
                        'ram_pct': stats.ram_pct,
                        'connection_issue': stats.connection_issue
                    }
            self.socketio.emit('dashboard_stats_update', {
                'stats': batch_data,
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error emitting batch stats update: {e}")
    
    def _emit_node_stats_update(self):
        """Emit node stats update"""
        if not self.socketio:
            return
        try:
            node_data = {}
            with self.stats_lock:
                for node_id, stats in self.node_stats_cache.items():
                    node_data[node_id] = asdict(stats)
            self.socketio.emit('node_stats_update', {
                'nodes': node_data,
                'timestamp': time.time()
            })
        except Exception as e:
            logger.error(f"Error emitting node stats update: {e}")
    
    def get_vps_stats(self, vps_id: int) -> Optional[StatsData]:
        """Get cached VPS stats"""
        with self.stats_lock:
            return self.vps_stats_cache.get(vps_id)
    
    def get_node_stats(self, node_id: int) -> Optional[NodeStats]:
        """Get cached node stats"""
        with self.stats_lock:
            return self.node_stats_cache.get(node_id)
    
    def get_all_vps_stats(self) -> Dict[int, StatsData]:
        """Get all cached VPS stats"""
        with self.stats_lock:
            return self.vps_stats_cache.copy()
    
    def get_all_node_stats(self) -> Dict[int, NodeStats]:
        """Get all cached node stats"""
        with self.stats_lock:
            return self.node_stats_cache.copy()
    
    def subscribe_to_vps(self, vps_id: int, client_id: str):
        """Subscribe client to VPS updates"""
        self.active_subscriptions[f'vps_{vps_id}'].add(client_id)
    
    def unsubscribe_from_vps(self, vps_id: int, client_id: str):
        """Unsubscribe client from VPS updates"""
        self.active_subscriptions[f'vps_{vps_id}'].discard(client_id)
    
    def get_performance_metrics(self) -> Dict:
        """Get performance metrics"""
        return self.metrics.copy()

live_stats_manager = None

def get_live_stats_manager() -> LiveStatsManager:
    """Get the global live stats manager instance"""
    global live_stats_manager
    if live_stats_manager is None:
        live_stats_manager = LiveStatsManager()
    return live_stats_manager

def init_live_stats_manager(socketio=None):
    """Initialize the live stats manager"""
    global live_stats_manager
    live_stats_manager = LiveStatsManager(socketio)
    live_stats_manager.start()
    return live_stats_manager
