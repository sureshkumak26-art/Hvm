#!/usr/bin/env python3
"""
StrenoxCloud Panel - Comprehensive REST API
Full management API for StrenoxCloud Panel
"""

from flask import Blueprint, request, jsonify
from functools import wraps
import secrets
import hashlib
from datetime import datetime
import logging

# Create API blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api/v1')

logger = logging.getLogger(__name__)

# ============================================================================
# API Authentication Decorator
# ============================================================================

def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from hvm import get_db
        
        # Get API key from header or query parameter
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not api_key:
            return jsonify({
                'success': False,
                'error': 'API key required',
                'message': 'Provide API key in X-API-Key header or api_key parameter'
            }), 401
        
        # Validate API key
        try:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute('''SELECT u.*, ak.* FROM api_keys ak
                              JOIN users u ON ak.user_id = u.id
                              WHERE ak.key = ? AND ak.is_active = 1''', (api_key,))
                result = cur.fetchone()
                
                if not result:
                    return jsonify({
                        'success': False,
                        'error': 'Invalid API key',
                        'message': 'API key not found or inactive'
                    }), 401
                
                # Update last used timestamp
                cur.execute('UPDATE api_keys SET last_used_at = ? WHERE key = ?',
                           (datetime.now().isoformat(), api_key))
                conn.commit()
                
                # Store user info in request context
                request.api_user = dict(result)
                request.api_key_info = {
                    'key_id': result['id'],
                    'user_id': result['user_id'],
                    'is_admin': result['is_admin']
                }
                
        except Exception as e:
            logger.error(f"API key validation error: {e}")
            return jsonify({
                'success': False,
                'error': 'Authentication error',
                'message': str(e)
            }), 500
        
        return f(*args, **kwargs)
    
    return decorated_function

def require_admin_api(f):
    """Decorator to require admin API key"""
    @wraps(f)
    @require_api_key
    def decorated_function(*args, **kwargs):
        if not request.api_key_info.get('is_admin'):
            return jsonify({
                'success': False,
                'error': 'Admin access required',
                'message': 'This endpoint requires admin privileges'
            }), 403
        
        return f(*args, **kwargs)
    
    return decorated_function

# ============================================================================
# API Info & Health
# ============================================================================

@api_bp.route('/info', methods=['GET'])
def api_info():
    """Get API information"""
    return jsonify({
        'success': True,
        'api': {
            'name': 'StrenoxCloud Panel API',
            'version': 'v1',
            'description': 'Comprehensive REST API for StrenoxCloud Panel management',
            'documentation': '/api/v1/docs',
            'endpoints': {
                'authentication': '/api/v1/auth/*',
                'users': '/api/v1/users/*',
                'vps': '/api/v1/vps/*',
                'nodes': '/api/v1/nodes/*',
                'system': '/api/v1/system/*'
            }
        }
    })

@api_bp.route('/health', methods=['GET'])
def api_health():
    """Health check endpoint"""
    return jsonify({
        'success': True,
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })

# ============================================================================
# User Management API
# ============================================================================

@api_bp.route('/users', methods=['GET'])
@require_admin_api
def api_list_users():
    """List all users"""
    from hvm import get_db
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''SELECT id, username, email, is_admin, created_at, last_login
                          FROM users ORDER BY id''')
            users = [dict(row) for row in cur.fetchall()]
        
        return jsonify({
            'success': True,
            'users': users,
            'count': len(users)
        })
    except Exception as e:
        logger.error(f"API list users error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/users/<int:user_id>', methods=['GET'])
@require_admin_api
def api_get_user(user_id):
    """Get user details"""
    from hvm import get_db
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''SELECT id, username, email, is_admin, created_at, last_login, last_active
                          FROM users WHERE id = ?''', (user_id,))
            user = cur.fetchone()
            
            if not user:
                return jsonify({'success': False, 'error': 'User not found'}), 404
            
            # Get user's VPS count
            cur.execute('SELECT COUNT(*) FROM vps WHERE user_id = ?', (user_id,))
            vps_count = cur.fetchone()[0]
            
            user_data = dict(user)
            user_data['vps_count'] = vps_count
        
        return jsonify({
            'success': True,
            'user': user_data
        })
    except Exception as e:
        logger.error(f"API get user error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/users', methods=['POST'])
@require_admin_api
def api_create_user():
    """Create new user"""
    from hvm import get_db
    from werkzeug.security import generate_password_hash
    
    try:
        data = request.get_json()
        
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        is_admin = data.get('is_admin', False)
        
        if not username or not email or not password:
            return jsonify({
                'success': False,
                'error': 'Missing required fields',
                'required': ['username', 'email', 'password']
            }), 400
        
        password_hash = generate_password_hash(password)
        now = datetime.now().isoformat()
        
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''INSERT INTO users (username, email, password_hash, is_admin, created_at)
                          VALUES (?, ?, ?, ?, ?)''',
                       (username, email, password_hash, 1 if is_admin else 0, now))
            conn.commit()
            user_id = cur.lastrowid
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'message': 'User created successfully'
        }), 201
    except Exception as e:
        logger.error(f"API create user error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/users/<int:user_id>', methods=['PUT', 'PATCH'])
@require_admin_api
def api_update_user(user_id):
    """Update user"""
    from hvm import get_db
    from werkzeug.security import generate_password_hash
    
    try:
        data = request.get_json()
        
        with get_db() as conn:
            cur = conn.cursor()
            
            if 'email' in data:
                cur.execute('UPDATE users SET email = ? WHERE id = ?', (data['email'], user_id))
            
            if 'password' in data:
                password_hash = generate_password_hash(data['password'])
                cur.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash, user_id))
            
            if 'is_admin' in data:
                cur.execute('UPDATE users SET is_admin = ? WHERE id = ?', 
                           (1 if data['is_admin'] else 0, user_id))
            
            conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'User updated successfully'
        })
    except Exception as e:
        logger.error(f"API update user error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/users/<int:user_id>', methods=['DELETE'])
@require_admin_api
def api_delete_user(user_id):
    """Delete user"""
    from hvm import get_db
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'User deleted successfully'
        })
    except Exception as e:
        logger.error(f"API delete user error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# VPS Management API
# ============================================================================

@api_bp.route('/vps', methods=['GET'])
@require_api_key
def api_list_vps():
    """List VPS (user's own or all if admin)"""
    from hvm import get_db
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            
            if request.api_key_info['is_admin']:
                # Admin sees all VPS
                cur.execute('''SELECT v.*, u.username, n.name as node_name
                              FROM vps v
                              LEFT JOIN users u ON v.user_id = u.id
                              LEFT JOIN nodes n ON v.node_id = n.id
                              ORDER BY v.created_at DESC''')
            else:
                # User sees only their VPS
                cur.execute('''SELECT v.*, n.name as node_name
                              FROM vps v
                              LEFT JOIN nodes n ON v.node_id = n.id
                              WHERE v.user_id = ?
                              ORDER BY v.created_at DESC''',
                           (request.api_key_info['user_id'],))
            
            vps_list = [dict(row) for row in cur.fetchall()]
        
        return jsonify({
            'success': True,
            'vps': vps_list,
            'count': len(vps_list)
        })
    except Exception as e:
        logger.error(f"API list VPS error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/vps/<int:vps_id>', methods=['GET'])
@require_api_key
def api_get_vps(vps_id):
    """Get VPS details"""
    from hvm import get_db, get_vps_by_id, run_sync, get_container_stats
    
    try:
        vps = get_vps_by_id(vps_id)
        
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Check access
        if not request.api_key_info['is_admin'] and vps['user_id'] != request.api_key_info['user_id']:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get live stats
        try:
            stats = run_sync(get_container_stats(vps['container_name'], vps['node_id']))
            vps['stats'] = stats
        except:
            vps['stats'] = None
        
        return jsonify({
            'success': True,
            'vps': vps
        })
    except Exception as e:
        logger.error(f"API get VPS error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/vps', methods=['POST'])
@require_admin_api
def api_create_vps():
    """Create new VPS"""
    from hvm import (get_db, create_vps, get_node, get_current_vps_count, get_vps_for_user, 
                     get_setting, install_vps_async, create_notification, log_activity)
    import threading
    import asyncio
    import re
    
    try:
        data = request.get_json()
        
        # Required fields
        required = ['hostname', 'user_id', 'node_id', 'cpu', 'ram', 'storage']
        for field in required:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}',
                    'required': required
                }), 400
        
        user_id = int(data['user_id'])
        node_id = int(data['node_id'])
        hostname = data['hostname']
        cpu = int(data['cpu'])
        ram = int(data['ram'])  # in GB
        storage = int(data['storage'])  # in GB
        swap = 0  # PERMANENTLY DISABLED - Always force to 0, ignore any user input
        kvm_enabled = bool(data.get('kvm_enabled', False))  # KVM access
        os_version = data.get('os_version', 'ubuntu:22.04')
        ip_address = data.get('ip_address')
        ip_alias = data.get('ip_alias')
        expiration_days = int(data.get('expiration_days', 0))
        auto_suspend_enabled = bool(data.get('auto_suspend_enabled', False))
        bandwidth_quota_gb = int(data.get('bandwidth_quota_gb', 0))
        
        # Swap is permanently disabled - no validation needed
        
        # Validate user exists
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT id FROM users WHERE id = ?', (user_id,))
            if not cur.fetchone():
                return jsonify({'success': False, 'error': f'User ID {user_id} not found'}), 404
        
        # Validate node exists
        node = get_node(node_id)
        if not node:
            return jsonify({'success': False, 'error': f'Node ID {node_id} not found'}), 404
        
        # Check node capacity
        current_count = get_current_vps_count(node_id)
        if current_count >= node['total_vps']:
            return jsonify({'success': False, 'error': f'Node at full capacity ({current_count}/{node["total_vps"]})'}), 400
        
        # Check user VPS limit
        max_vps = int(get_setting('max_vps_per_user', '10'))
        user_vps_count = len(get_vps_for_user(user_id))
        if user_vps_count >= max_vps:
            return jsonify({'success': False, 'error': f'User has reached maximum VPS limit ({max_vps})'}), 400
        
        # Generate container name
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT COUNT(*) FROM vps WHERE user_id = ?', (user_id,))
            vps_count = cur.fetchone()[0] + 1
        
        container_name = hostname.lower().replace(' ', '-').replace('_', '-')
        container_name = re.sub(r'[^a-z0-9\-]', '', container_name)
        if not container_name:
            container_name = f"hvm-vps-{user_id}-{vps_count}"
        
        ram_mb = ram * 1024
        
        # Create config string
        config_str = f"{ram}GB RAM / {cpu} CPU / {storage}GB Disk / Swap: DISABLED"
        if kvm_enabled:
            config_str += " / KVM Enabled"
        if bandwidth_quota_gb > 0:
            config_str += f" / {bandwidth_quota_gb}GB Bandwidth"
        
        # Create VPS record with "installing" status
        vps_id = create_vps(
            user_id=user_id,
            node_id=node_id,
            container_name=container_name,
            hostname=hostname or container_name,
            ram=f"{ram}GB",
            cpu=str(cpu),
            storage=f"{storage}GB",
            config=config_str,
            os_version=os_version,
            ip_address=ip_address,
            ip_alias=ip_alias,
            expiration_days=expiration_days,
            auto_suspend_enabled=auto_suspend_enabled,
            bandwidth_quota_gb=bandwidth_quota_gb,
            swap=0,  # PERMANENTLY DISABLED - Always 0
            kvm_enabled=kvm_enabled,
            status='installing'
        )
        
        # Start installation in background
        def run_installation():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(
                    install_vps_async(vps_id, container_name, node_id, ram_mb, cpu, storage, 
                                     os_version, ip_address, bandwidth_quota_gb, 0, kvm_enabled)  # swap always 0
                )
                loop.close()
            except Exception as e:
                logger.error(f"Background installation error: {e}", exc_info=True)
        
        installation_thread = threading.Thread(target=run_installation, daemon=True)
        installation_thread.start()
        
        log_activity(user_id, 'create_vps_api', 'vps', str(vps_id),
                    {'container': container_name, 'via': 'api'})
        create_notification(user_id, 'info', 'VPS Installation Started', 
                          f'Your VPS {container_name} installation has started.')
        
        return jsonify({
            'success': True,
            'vps_id': vps_id,
            'container_name': container_name,
            'status': 'installing',
            'message': 'VPS creation started successfully'
        }), 201
        
    except Exception as e:
        logger.error(f"API create VPS error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/vps/<int:vps_id>/start', methods=['POST'])
@require_api_key
def api_start_vps(vps_id):
    """Start VPS"""
    from hvm import get_vps_by_id, run_sync, execute_lxc
    
    try:
        vps = get_vps_by_id(vps_id)
        
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Check access
        if not request.api_key_info['is_admin'] and vps['user_id'] != request.api_key_info['user_id']:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Start VPS
        run_sync(execute_lxc(vps['container_name'], f"start {vps['container_name']}", node_id=vps['node_id']))
        
        return jsonify({
            'success': True,
            'message': 'VPS started successfully'
        })
    except Exception as e:
        logger.error(f"API start VPS error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/vps/<int:vps_id>/stop', methods=['POST'])
@require_api_key
def api_stop_vps(vps_id):
    """Stop VPS"""
    from hvm import get_vps_by_id, run_sync, execute_lxc
    
    try:
        vps = get_vps_by_id(vps_id)
        
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Check access
        if not request.api_key_info['is_admin'] and vps['user_id'] != request.api_key_info['user_id']:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Stop VPS
        run_sync(execute_lxc(vps['container_name'], f"stop {vps['container_name']}", node_id=vps['node_id']))
        
        return jsonify({
            'success': True,
            'message': 'VPS stopped successfully'
        })
    except Exception as e:
        logger.error(f"API stop VPS error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/vps/<int:vps_id>/restart', methods=['POST'])
@require_api_key
def api_restart_vps(vps_id):
    """Restart VPS"""
    from hvm import get_vps_by_id, run_sync, execute_lxc
    
    try:
        vps = get_vps_by_id(vps_id)
        
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Check access
        if not request.api_key_info['is_admin'] and vps['user_id'] != request.api_key_info['user_id']:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Restart VPS
        run_sync(execute_lxc(vps['container_name'], f"restart {vps['container_name']}", node_id=vps['node_id']))
        
        return jsonify({
            'success': True,
            'message': 'VPS restarted successfully'
        })
    except Exception as e:
        logger.error(f"API restart VPS error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/vps/<int:vps_id>', methods=['DELETE'])
@require_admin_api
def api_delete_vps(vps_id):
    """Delete VPS"""
    from hvm import get_db, get_vps_by_id, run_sync, execute_lxc
    
    try:
        vps = get_vps_by_id(vps_id)
        
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Delete container
        try:
            run_sync(execute_lxc(vps['container_name'], f"delete {vps['container_name']} --force", node_id=vps['node_id']))
        except:
            pass
        
        # Delete from database
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('DELETE FROM vps WHERE id = ?', (vps_id,))
            conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'VPS deleted successfully'
        })
    except Exception as e:
        logger.error(f"API delete VPS error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Node Management API
# ============================================================================

@api_bp.route('/nodes', methods=['GET'])
@require_admin_api
def api_list_nodes():
    """List all nodes"""
    from hvm import get_nodes
    
    try:
        nodes = get_nodes()
        
        return jsonify({
            'success': True,
            'nodes': nodes,
            'count': len(nodes)
        })
    except Exception as e:
        logger.error(f"API list nodes error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/nodes/<int:node_id>', methods=['GET'])
@require_admin_api
def api_get_node(node_id):
    """Get node details"""
    from hvm import get_node, run_sync, get_host_stats
    
    try:
        node = get_node(node_id)
        
        if not node:
            return jsonify({'success': False, 'error': 'Node not found'}), 404
        
        # Get node stats
        try:
            stats = run_sync(get_host_stats(node_id))
            node['stats'] = stats
        except:
            node['stats'] = None
        
        return jsonify({
            'success': True,
            'node': node
        })
    except Exception as e:
        logger.error(f"API get node error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# System API
# ============================================================================

@api_bp.route('/system/info', methods=['GET'])
@require_admin_api
def api_system_info():
    """Get system information"""
    from hvm import get_host_cpu_usage, get_host_ram_usage, get_host_disk_usage, get_host_uptime
    import platform
    
    try:
        system_info = {
            'hostname': platform.node(),
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'cpu': {
                'cores': __import__('os').cpu_count(),
                'usage': get_host_cpu_usage()
            },
            'memory': get_host_ram_usage(),
            'disk': get_host_disk_usage(),
            'uptime': get_host_uptime()
        }
        
        return jsonify({
            'success': True,
            'system': system_info
        })
    except Exception as e:
        logger.error(f"API system info error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/system/stats', methods=['GET'])
@require_admin_api
def api_system_stats():
    """Get system statistics"""
    from hvm import get_db
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            
            cur.execute('SELECT COUNT(*) FROM users')
            total_users = cur.fetchone()[0]
            
            cur.execute('SELECT COUNT(*) FROM vps')
            total_vps = cur.fetchone()[0]
            
            cur.execute('SELECT COUNT(*) FROM vps WHERE status = "running"')
            running_vps = cur.fetchone()[0]
            
            cur.execute('SELECT COUNT(*) FROM nodes')
            total_nodes = cur.fetchone()[0]
        
        return jsonify({
            'success': True,
            'stats': {
                'users': total_users,
                'vps': {
                    'total': total_vps,
                    'running': running_vps,
                    'stopped': total_vps - running_vps
                },
                'nodes': total_nodes
            }
        })
    except Exception as e:
        logger.error(f"API system stats error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# VPS Extended Management API
# ============================================================================

@api_bp.route('/vps/<int:vps_id>/suspend', methods=['POST'])
@require_admin_api
def api_suspend_vps(vps_id):
    """Suspend VPS"""
    from hvm import get_db, get_vps_by_id, run_sync, execute_lxc
    
    try:
        data = request.get_json() or {}
        reason = data.get('reason', 'Suspended by admin via API')
        
        vps = get_vps_by_id(vps_id)
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Stop VPS
        try:
            run_sync(execute_lxc(vps['container_name'], f"stop {vps['container_name']} --force", node_id=vps['node_id']))
        except:
            pass
        
        # Update database
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('UPDATE vps SET suspended = 1, suspended_reason = ?, status = "stopped" WHERE id = ?',
                       (reason, vps_id))
            conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'VPS suspended successfully'
        })
    except Exception as e:
        logger.error(f"API suspend VPS error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/vps/<int:vps_id>/unsuspend', methods=['POST'])
@require_admin_api
def api_unsuspend_vps(vps_id):
    """Unsuspend VPS"""
    from hvm import get_db
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('UPDATE vps SET suspended = 0, suspended_reason = NULL WHERE id = ?', (vps_id,))
            conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'VPS unsuspended successfully'
        })
    except Exception as e:
        logger.error(f"API unsuspend VPS error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/vps/<int:vps_id>/resize', methods=['POST'])
@require_admin_api
def api_resize_vps(vps_id):
    """Resize VPS resources"""
    from hvm import get_db, get_vps_by_id
    
    try:
        data = request.get_json() or {}
        
        vps = get_vps_by_id(vps_id)
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        with get_db() as conn:
            cur = conn.cursor()
            
            if 'cpu' in data:
                cur.execute('UPDATE vps SET cpu = ? WHERE id = ?', (data['cpu'], vps_id))
            
            if 'ram' in data:
                cur.execute('UPDATE vps SET ram = ? WHERE id = ?', (data['ram'], vps_id))
            
            if 'storage' in data:
                cur.execute('UPDATE vps SET storage = ? WHERE id = ?', (data['storage'], vps_id))
            
            conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'VPS resized successfully (restart required for changes to take effect)'
        })
    except Exception as e:
        logger.error(f"API resize VPS error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/vps/<int:vps_id>/execute', methods=['POST'])
@require_api_key
def api_execute_command(vps_id):
    """Execute command in VPS"""
    from hvm import get_vps_by_id, run_sync, execute_lxc
    
    try:
        data = request.get_json() or {}
        command = data.get('command')
        
        if not command:
            return jsonify({'success': False, 'error': 'command required'}), 400
        
        vps = get_vps_by_id(vps_id)
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Check access
        if not request.api_key_info['is_admin'] and vps['user_id'] != request.api_key_info['user_id']:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Execute command
        result = run_sync(execute_lxc(vps['container_name'], f"exec {vps['container_name']} -- {command}", node_id=vps['node_id']))
        
        return jsonify({
            'success': True,
            'output': result
        })
    except Exception as e:
        logger.error(f"API execute command error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Node Extended Management API
# ============================================================================

@api_bp.route('/nodes', methods=['POST'])
@require_admin_api
def api_create_node():
    """Create new node"""
    from hvm import get_db
    
    try:
        data = request.get_json() or {}
        
        name = data.get('name')
        url = data.get('url')
        location = data.get('location', '')
        api_key = data.get('api_key')
        
        if not name or not url:
            return jsonify({
                'success': False,
                'error': 'Missing required fields',
                'required': ['name', 'url']
            }), 400
        
        now = datetime.now().isoformat()
        
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''INSERT INTO nodes (name, url, location, api_key, created_at, updated_at)
                          VALUES (?, ?, ?, ?, ?, ?)''',
                       (name, url, location, api_key, now, now))
            conn.commit()
            node_id = cur.lastrowid
        
        return jsonify({
            'success': True,
            'node_id': node_id,
            'message': 'Node created successfully'
        }), 201
    except Exception as e:
        logger.error(f"API create node error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/nodes/<int:node_id>', methods=['PUT', 'PATCH'])
@require_admin_api
def api_update_node(node_id):
    """Update node"""
    from hvm import get_db
    
    try:
        data = request.get_json() or {}
        
        with get_db() as conn:
            cur = conn.cursor()
            
            if 'name' in data:
                cur.execute('UPDATE nodes SET name = ? WHERE id = ?', (data['name'], node_id))
            
            if 'url' in data:
                cur.execute('UPDATE nodes SET url = ? WHERE id = ?', (data['url'], node_id))
            
            if 'location' in data:
                cur.execute('UPDATE nodes SET location = ? WHERE id = ?', (data['location'], node_id))
            
            if 'api_key' in data:
                cur.execute('UPDATE nodes SET api_key = ? WHERE id = ?', (data['api_key'], node_id))
            
            cur.execute('UPDATE nodes SET updated_at = ? WHERE id = ?', (datetime.now().isoformat(), node_id))
            conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'Node updated successfully'
        })
    except Exception as e:
        logger.error(f"API update node error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/nodes/<int:node_id>', methods=['DELETE'])
@require_admin_api
def api_delete_node(node_id):
    """Delete node"""
    from hvm import get_db
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('DELETE FROM nodes WHERE id = ?', (node_id,))
            conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'Node deleted successfully'
        })
    except Exception as e:
        logger.error(f"API delete node error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Settings Management API
# ============================================================================

@api_bp.route('/settings', methods=['GET'])
@require_admin_api
def api_get_settings():
    """Get all settings"""
    from hvm import get_db
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT key, value, description FROM settings')
            settings = {row['key']: {'value': row['value'], 'description': row['description']} 
                       for row in cur.fetchall()}
        
        return jsonify({
            'success': True,
            'settings': settings
        })
    except Exception as e:
        logger.error(f"API get settings error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/settings/<key>', methods=['GET'])
@require_admin_api
def api_get_setting(key):
    """Get specific setting"""
    from hvm import get_setting
    
    try:
        value = get_setting(key)
        
        if value is None:
            return jsonify({'success': False, 'error': 'Setting not found'}), 404
        
        return jsonify({
            'success': True,
            'key': key,
            'value': value
        })
    except Exception as e:
        logger.error(f"API get setting error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/settings/<key>', methods=['PUT', 'PATCH'])
@require_admin_api
def api_update_setting(key):
    """Update setting"""
    from hvm import set_setting
    
    try:
        data = request.get_json() or {}
        value = data.get('value')
        
        if value is None:
            return jsonify({'success': False, 'error': 'value required'}), 400
        
        set_setting(key, str(value))
        
        return jsonify({
            'success': True,
            'message': 'Setting updated successfully'
        })
    except Exception as e:
        logger.error(f"API update setting error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Maintenance Mode API
# ============================================================================

@api_bp.route('/maintenance/enable', methods=['POST'])
@require_admin_api
def api_enable_maintenance():
    """Enable maintenance mode"""
    from hvm import set_setting
    
    try:
        data = request.get_json() or {}
        message = data.get('message', 'Site is under maintenance. Please check back later.')
        
        set_setting('maintenance_mode', '1')
        set_setting('maintenance_message', message)
        
        return jsonify({
            'success': True,
            'message': 'Maintenance mode enabled'
        })
    except Exception as e:
        logger.error(f"API enable maintenance error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/maintenance/disable', methods=['POST'])
@require_admin_api
def api_disable_maintenance():
    """Disable maintenance mode"""
    from hvm import set_setting
    
    try:
        set_setting('maintenance_mode', '0')
        
        return jsonify({
            'success': True,
            'message': 'Maintenance mode disabled'
        })
    except Exception as e:
        logger.error(f"API disable maintenance error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Bulk Operations API
# ============================================================================

@api_bp.route('/vps/bulk/start', methods=['POST'])
@require_admin_api
def api_bulk_start_vps():
    """Start multiple VPS"""
    from hvm import get_db, run_sync, execute_lxc
    
    try:
        data = request.get_json() or {}
        vps_ids = data.get('vps_ids', [])
        
        if not vps_ids:
            return jsonify({'success': False, 'error': 'vps_ids required'}), 400
        
        started = []
        failed = []
        
        with get_db() as conn:
            cur = conn.cursor()
            for vps_id in vps_ids:
                cur.execute('SELECT * FROM vps WHERE id = ?', (vps_id,))
                vps = cur.fetchone()
                
                if vps:
                    try:
                        run_sync(execute_lxc(vps['container_name'], f"start {vps['container_name']}", node_id=vps['node_id']))
                        started.append(vps_id)
                    except Exception as e:
                        failed.append({'vps_id': vps_id, 'error': str(e)})
        
        return jsonify({
            'success': True,
            'started': started,
            'failed': failed,
            'message': f'Started {len(started)} VPS, {len(failed)} failed'
        })
    except Exception as e:
        logger.error(f"API bulk start VPS error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/vps/bulk/stop', methods=['POST'])
@require_admin_api
def api_bulk_stop_vps():
    """Stop multiple VPS"""
    from hvm import get_db, run_sync, execute_lxc
    
    try:
        data = request.get_json() or {}
        vps_ids = data.get('vps_ids', [])
        
        if not vps_ids:
            return jsonify({'success': False, 'error': 'vps_ids required'}), 400
        
        stopped = []
        failed = []
        
        with get_db() as conn:
            cur = conn.cursor()
            for vps_id in vps_ids:
                cur.execute('SELECT * FROM vps WHERE id = ?', (vps_id,))
                vps = cur.fetchone()
                
                if vps:
                    try:
                        run_sync(execute_lxc(vps['container_name'], f"stop {vps['container_name']}", node_id=vps['node_id']))
                        stopped.append(vps_id)
                    except Exception as e:
                        failed.append({'vps_id': vps_id, 'error': str(e)})
        
        return jsonify({
            'success': True,
            'stopped': stopped,
            'failed': failed,
            'message': f'Stopped {len(stopped)} VPS, {len(failed)} failed'
        })
    except Exception as e:
        logger.error(f"API bulk stop VPS error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Port Forwarding API
# ============================================================================

@api_bp.route('/ports', methods=['GET'])
@require_api_key
def api_list_ports():
    """List port forwards (user's own or all if admin)"""
    from hvm import get_db
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            
            if request.api_key_info['is_admin']:
                cur.execute('''SELECT pf.*, v.hostname, u.username
                              FROM port_forwards pf
                              LEFT JOIN vps v ON pf.vps_id = v.id
                              LEFT JOIN users u ON pf.user_id = u.id
                              ORDER BY pf.created_at DESC''')
            else:
                cur.execute('''SELECT pf.*, v.hostname
                              FROM port_forwards pf
                              LEFT JOIN vps v ON pf.vps_id = v.id
                              WHERE pf.user_id = ?
                              ORDER BY pf.created_at DESC''',
                           (request.api_key_info['user_id'],))
            
            ports = [dict(row) for row in cur.fetchall()]
        
        return jsonify({
            'success': True,
            'ports': ports,
            'count': len(ports)
        })
    except Exception as e:
        logger.error(f"API list ports error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/ports', methods=['POST'])
@require_api_key
def api_create_port():
    """Create port forward"""
    from hvm import get_db, allocate_port
    
    try:
        data = request.get_json() or {}
        
        vps_id = data.get('vps_id')
        internal_port = data.get('internal_port')
        protocol = data.get('protocol', 'tcp')
        description = data.get('description', '')
        
        if not vps_id or not internal_port:
            return jsonify({
                'success': False,
                'error': 'Missing required fields',
                'required': ['vps_id', 'internal_port']
            }), 400
        
        # Check VPS ownership
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT user_id FROM vps WHERE id = ?', (vps_id,))
            vps = cur.fetchone()
            
            if not vps:
                return jsonify({'success': False, 'error': 'VPS not found'}), 404
            
            if not request.api_key_info['is_admin'] and vps['user_id'] != request.api_key_info['user_id']:
                return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Allocate port
        external_port = allocate_port(request.api_key_info['user_id'], vps_id, internal_port, protocol, description)
        
        if not external_port:
            return jsonify({'success': False, 'error': 'No ports available'}), 400
        
        return jsonify({
            'success': True,
            'external_port': external_port,
            'message': 'Port forward created successfully'
        }), 201
    except Exception as e:
        logger.error(f"API create port error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/ports/<int:port_id>', methods=['DELETE'])
@require_api_key
def api_delete_port(port_id):
    """Delete port forward"""
    from hvm import get_db
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            
            # Check ownership
            cur.execute('SELECT user_id FROM port_forwards WHERE id = ?', (port_id,))
            port = cur.fetchone()
            
            if not port:
                return jsonify({'success': False, 'error': 'Port forward not found'}), 404
            
            if not request.api_key_info['is_admin'] and port['user_id'] != request.api_key_info['user_id']:
                return jsonify({'success': False, 'error': 'Access denied'}), 403
            
            cur.execute('DELETE FROM port_forwards WHERE id = ?', (port_id,))
            conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'Port forward deleted successfully'
        })
    except Exception as e:
        logger.error(f"API delete port error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Notifications API
# ============================================================================

@api_bp.route('/notifications', methods=['GET'])
@require_api_key
def api_list_notifications():
    """List user notifications"""
    from hvm import get_db
    
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        
        offset = (page - 1) * per_page
        
        with get_db() as conn:
            cur = conn.cursor()
            
            query = 'SELECT * FROM notifications WHERE user_id = ?'
            params = [request.api_key_info['user_id']]
            
            if unread_only:
                query += ' AND is_read = 0'
            
            query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'
            params.extend([per_page, offset])
            
            cur.execute(query, params)
            notifications = [dict(row) for row in cur.fetchall()]
            
            # Get total count
            count_query = 'SELECT COUNT(*) FROM notifications WHERE user_id = ?'
            count_params = [request.api_key_info['user_id']]
            if unread_only:
                count_query += ' AND is_read = 0'
            
            cur.execute(count_query, count_params)
            total = cur.fetchone()[0]
        
        return jsonify({
            'success': True,
            'notifications': notifications,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
        })
    except Exception as e:
        logger.error(f"API list notifications error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/notifications/<int:notification_id>/read', methods=['POST'])
@require_api_key
def api_mark_notification_read(notification_id):
    """Mark notification as read"""
    from hvm import get_db
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            
            # Check ownership
            cur.execute('SELECT user_id FROM notifications WHERE id = ?', (notification_id,))
            notif = cur.fetchone()
            
            if not notif:
                return jsonify({'success': False, 'error': 'Notification not found'}), 404
            
            if notif['user_id'] != request.api_key_info['user_id']:
                return jsonify({'success': False, 'error': 'Access denied'}), 403
            
            cur.execute('UPDATE notifications SET is_read = 1 WHERE id = ?', (notification_id,))
            conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'Notification marked as read'
        })
    except Exception as e:
        logger.error(f"API mark notification read error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/notifications/read-all', methods=['POST'])
@require_api_key
def api_mark_all_notifications_read():
    """Mark all notifications as read"""
    from hvm import get_db
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ?',
                       (request.api_key_info['user_id'],))
            conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'All notifications marked as read'
        })
    except Exception as e:
        logger.error(f"API mark all notifications read error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Activity Logs API
# ============================================================================

@api_bp.route('/activity', methods=['GET'])
@require_api_key
def api_list_activity():
    """List activity logs"""
    from hvm import get_db
    
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        
        offset = (page - 1) * per_page
        
        with get_db() as conn:
            cur = conn.cursor()
            
            if request.api_key_info['is_admin']:
                # Admin sees all activity
                cur.execute('''SELECT al.*, u.username
                              FROM activity_log al
                              LEFT JOIN users u ON al.user_id = u.id
                              ORDER BY al.timestamp DESC
                              LIMIT ? OFFSET ?''', (per_page, offset))
                
                cur.execute('SELECT COUNT(*) FROM activity_log')
            else:
                # User sees only their activity
                cur.execute('''SELECT * FROM activity_log
                              WHERE user_id = ?
                              ORDER BY timestamp DESC
                              LIMIT ? OFFSET ?''',
                           (request.api_key_info['user_id'], per_page, offset))
                
                cur.execute('SELECT COUNT(*) FROM activity_log WHERE user_id = ?',
                           (request.api_key_info['user_id'],))
            
            activities = [dict(row) for row in cur.fetchall()]
            total = cur.fetchone()[0]
        
        return jsonify({
            'success': True,
            'activities': activities,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
        })
    except Exception as e:
        logger.error(f"API list activity error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# VPS Password Management API
# ============================================================================

@api_bp.route('/vps/<int:vps_id>/password', methods=['GET'])
@require_api_key
def api_get_vps_password(vps_id):
    """Get VPS password"""
    from hvm import get_vps_by_id
    
    try:
        vps = get_vps_by_id(vps_id)
        
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Check access
        if not request.api_key_info['is_admin'] and vps['user_id'] != request.api_key_info['user_id']:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        password = vps.get('root_password', 'root')
        
        return jsonify({
            'success': True,
            'password': password
        })
    except Exception as e:
        logger.error(f"API get VPS password error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/vps/<int:vps_id>/password', methods=['POST', 'PUT'])
@require_api_key
def api_change_vps_password(vps_id):
    """Change VPS password"""
    from hvm import get_db, get_vps_by_id, run_sync, execute_lxc
    import platform
    
    try:
        data = request.get_json() or {}
        new_password = data.get('password')
        
        if not new_password:
            return jsonify({'success': False, 'error': 'password required'}), 400
        
        vps = get_vps_by_id(vps_id)
        
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Check access
        if not request.api_key_info['is_admin'] and vps['user_id'] != request.api_key_info['user_id']:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Update in database
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('UPDATE vps SET root_password = ? WHERE id = ?', (new_password, vps_id))
            conn.commit()
        
        # Update in container if on Linux
        if platform.system() == 'Linux' and vps.get('status') == 'running':
            try:
                cmd = f"exec {vps['container_name']} -- bash -c \"echo 'root:{new_password}' | chpasswd\""
                run_sync(execute_lxc(vps['container_name'], cmd, node_id=vps['node_id']))
            except:
                pass
        
        return jsonify({
            'success': True,
            'message': 'Password changed successfully'
        })
    except Exception as e:
        logger.error(f"API change VPS password error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# API Key Management API (Admin Only)
# ============================================================================

@api_bp.route('/api-keys', methods=['GET'])
@require_admin_api
def api_list_api_keys():
    """List all API keys (admin only)"""
    from hvm import get_db
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''SELECT ak.*, u.username
                          FROM api_keys ak
                          JOIN users u ON ak.user_id = u.id
                          ORDER BY ak.created_at DESC''')
            keys = [dict(row) for row in cur.fetchall()]
        
        return jsonify({
            'success': True,
            'api_keys': keys,
            'count': len(keys)
        })
    except Exception as e:
        logger.error(f"API list API keys error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/api-keys', methods=['POST'])
@require_admin_api
def api_create_api_key():
    """Create new API key (admin only)"""
    from hvm import get_db
    
    try:
        data = request.get_json() or {}
        name = data.get('name', 'API Key')
        user_id = data.get('user_id')
        
        if not user_id:
            return jsonify({'success': False, 'error': 'user_id required'}), 400
        
        # Generate new API key
        new_key = secrets.token_urlsafe(32)
        now = datetime.now().isoformat()
        
        with get_db() as conn:
            cur = conn.cursor()
            
            # Verify user exists
            cur.execute('SELECT id FROM users WHERE id = ?', (user_id,))
            if not cur.fetchone():
                return jsonify({'success': False, 'error': 'User not found'}), 404
            
            cur.execute('''INSERT INTO api_keys (user_id, name, key, is_active, created_at)
                          VALUES (?, ?, ?, 1, ?)''',
                       (user_id, name, new_key, now))
            conn.commit()
            key_id = cur.lastrowid
        
        return jsonify({
            'success': True,
            'api_key': {
                'id': key_id,
                'name': name,
                'key': new_key,
                'user_id': user_id
            },
            'message': 'API key created successfully'
        }), 201
    except Exception as e:
        logger.error(f"API create API key error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/api-keys/<int:key_id>', methods=['DELETE'])
@require_admin_api
def api_delete_api_key(key_id):
    """Delete API key (admin only)"""
    from hvm import get_db
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            
            # Check if key exists
            cur.execute('SELECT user_id FROM api_keys WHERE id = ?', (key_id,))
            key = cur.fetchone()
            
            if not key:
                return jsonify({'success': False, 'error': 'API key not found'}), 404
            
            cur.execute('DELETE FROM api_keys WHERE id = ?', (key_id,))
            conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'API key deleted successfully'
        })
    except Exception as e:
        logger.error(f"API delete API key error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Statistics API
# ============================================================================

@api_bp.route('/stats/overview', methods=['GET'])
@require_api_key
def api_stats_overview():
    """Get overview statistics"""
    from hvm import get_db
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            
            if request.api_key_info['is_admin']:
                # Admin stats
                cur.execute('SELECT COUNT(*) FROM users')
                total_users = cur.fetchone()[0]
                
                cur.execute('SELECT COUNT(*) FROM vps')
                total_vps = cur.fetchone()[0]
                
                cur.execute('SELECT COUNT(*) FROM vps WHERE status = "running"')
                running_vps = cur.fetchone()[0]
                
                cur.execute('SELECT COUNT(*) FROM vps WHERE suspended = 1')
                suspended_vps = cur.fetchone()[0]
                
                cur.execute('SELECT COUNT(*) FROM nodes')
                total_nodes = cur.fetchone()[0]
                
                cur.execute('SELECT COUNT(*) FROM port_forwards')
                total_ports = cur.fetchone()[0]
                
                stats = {
                    'users': total_users,
                    'vps': {
                        'total': total_vps,
                        'running': running_vps,
                        'stopped': total_vps - running_vps - suspended_vps,
                        'suspended': suspended_vps
                    },
                    'nodes': total_nodes,
                    'ports': total_ports
                }
            else:
                # User stats
                user_id = request.api_key_info['user_id']
                
                cur.execute('SELECT COUNT(*) FROM vps WHERE user_id = ?', (user_id,))
                total_vps = cur.fetchone()[0]
                
                cur.execute('SELECT COUNT(*) FROM vps WHERE user_id = ? AND status = "running"', (user_id,))
                running_vps = cur.fetchone()[0]
                
                cur.execute('SELECT COUNT(*) FROM vps WHERE user_id = ? AND suspended = 1', (user_id,))
                suspended_vps = cur.fetchone()[0]
                
                cur.execute('SELECT COUNT(*) FROM port_forwards WHERE user_id = ?', (user_id,))
                total_ports = cur.fetchone()[0]
                
                cur.execute('SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0', (user_id,))
                unread_notifications = cur.fetchone()[0]
                
                stats = {
                    'vps': {
                        'total': total_vps,
                        'running': running_vps,
                        'stopped': total_vps - running_vps - suspended_vps,
                        'suspended': suspended_vps
                    },
                    'ports': total_ports,
                    'notifications': {
                        'unread': unread_notifications
                    }
                }
        
        return jsonify({
            'success': True,
            'stats': stats
        })
    except Exception as e:
        logger.error(f"API stats overview error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# API Documentation
# ============================================================================

@api_bp.route('/docs', methods=['GET'])
def api_documentation():
    """API documentation — HTML when the browser asks, JSON otherwise."""

    # If the caller wants JSON (or didn't explicitly ask for HTML), return JSON.
    accept_header = request.headers.get('Accept', '')
    if 'text/html' not in accept_header and 'application/json' in accept_header:
        return _api_docs_json()
    if 'text/html' not in accept_header:
        # Default to HTML for browsers (no Accept header) but JSON for
        # programmatic clients that send `Accept: application/json`.
        if not accept_header or accept_header == '*/*':
            return _api_docs_html()
        return _api_docs_json()
    return _api_docs_html()


def _api_docs_json():
    """JSON form of the API docs — auto-generated from the URL map."""
    from flask import current_app
    groups: dict = {}
    for rule in current_app.url_map.iter_rules():
        if not rule.rule.startswith('/api/v1'):
            continue
        path = rule.rule[len('/api/v1'):] or '/'
        # Group by the second path segment (e.g. /vps/<id>/start -> vps).
        parts = [p for p in path.strip('/').split('/') if p]
        group = parts[0] if parts else 'meta'
        methods = sorted(m for m in rule.methods
                         if m not in {'HEAD', 'OPTIONS'})
        view = current_app.view_functions.get(rule.endpoint)
        doc = (view.__doc__ or '').strip().split('\n')[0] if view else ''
        is_admin = getattr(view, '_is_admin_required', False)
        groups.setdefault(group, []).append({
            'path': rule.rule,
            'methods': methods,
            'endpoint': rule.endpoint,
            'description': doc,
            'admin_only': is_admin,
        })
    for g in groups.values():
        g.sort(key=lambda e: e['path'])
    return jsonify({
        'success': True,
        'api': {
            'name': 'StrenoxCloud Panel API',
            'version': 'v1.0',
            'base_url': '/api/v1',
            'description': 'Complete REST API for managing VPS, users, '
                           'nodes, ports and system resources.',
        },
        'auth': {
            'header': 'X-API-Key',
            'query_param': 'api_key',
            'notes': 'Admin endpoints require an API key owned by an admin user.',
        },
        'groups': groups,
        'generated_at': datetime.now().isoformat(),
    })


def _api_docs_html():
    """Dark-themed, auto-generated, single-page HTML docs."""
    from flask import current_app, render_template_string

    # Build the endpoint list straight from the URL map so docs never drift.
    rules = []
    for rule in current_app.url_map.iter_rules():
        if not rule.rule.startswith('/api/v1'):
            continue
        path = rule.rule[len('/api/v1'):] or '/'
        parts = [p for p in path.strip('/').split('/') if p]
        group = parts[0] if parts else 'meta'
        methods = sorted(m for m in rule.methods
                         if m not in {'HEAD', 'OPTIONS'})
        view = current_app.view_functions.get(rule.endpoint)
        if view and view.__doc__:
            first_line = view.__doc__.strip().split('\n')[0].strip()
        else:
            first_line = ''
        rules.append({
            'group': group,
            'path': rule.rule,
            'short_path': path,
            'methods': methods,
            'endpoint': rule.endpoint,
            'description': first_line,
        })
    rules.sort(key=lambda r: (r['group'], r['path']))

    # Pretty group titles + emoji.
    group_meta = {
        'meta':          ('Meta',                 'fa-info-circle'),
        '':              ('Root',                 'fa-circle'),
        'info':          ('Meta',                 'fa-info-circle'),
        'health':        ('Meta',                 'fa-heart-pulse'),
        'docs':          ('Meta',                 'fa-book'),
        'endpoints':     ('Meta',                 'fa-list'),
        'me':            ('Identity',             'fa-id-badge'),
        'profile':       ('Identity',             'fa-user'),
        'users':         ('Users',                'fa-users'),
        'vps':           ('VPS',                  'fa-server'),
        'nodes':         ('Nodes',                'fa-network-wired'),
        'ports':         ('Ports',                'fa-plug'),
        'notifications': ('Notifications',        'fa-bell'),
        'activity':      ('Activity',             'fa-clock-rotate-left'),
        'api-keys':      ('API Keys',             'fa-key'),
        'settings':      ('Settings',             'fa-cog'),
        'maintenance':   ('Maintenance',          'fa-tools'),
        'system':        ('System',               'fa-microchip'),
        'emergency':     ('Emergency',            'fa-triangle-exclamation'),
        'backups':       ('Backups',              'fa-database'),
        'os-icons':      ('OS Icons',             'fa-icons'),
        'os-templates':  ('OS Templates',         'fa-cube'),
        'stats':         ('Statistics',           'fa-chart-line'),
        'logs':          ('Logs',                 'fa-file-lines'),
        'search':        ('Search',               'fa-magnifying-glass'),
        'webhooks':      ('Webhooks',             'fa-link'),
    }
    # Group rules.
    grouped: dict = {}
    for r in rules:
        grouped.setdefault(r['group'], []).append(r)
    # Sorted group keys with friendly ordering.
    preferred = [
        'me', 'profile', 'info', 'health', 'docs', 'endpoints',
        'vps', 'users', 'nodes', 'ports', 'settings', 'system',
        'api-keys', 'backups', 'maintenance', 'emergency',
        'notifications', 'activity', 'os-icons', 'os-templates',
        'stats', 'logs', 'search', 'webhooks',
    ]
    ordered_groups = (
        [g for g in preferred if g in grouped]
        + [g for g in sorted(grouped) if g not in preferred]
    )

    html = '''
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>StrenoxCloud Panel · API Docs</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
    :root {
        --bg:        #0a0c10;
        --bg-1:      #0c0e12;
        --bg-2:      #111316;
        --bg-3:      #1a1c20;
        --bg-elev:   #1f2228;
        --border:    rgba(255, 255, 255, 0.08);
        --border-2:  rgba(255, 255, 255, 0.14);
        --text:      #e6eef9;
        --text-mut:  #9aa4b2;
        --primary:   #4facfe;
        --primary-2: #667eea;
        --green:     #34d399;
        --yellow:    #fbbf24;
        --orange:    #f97316;
        --red:       #ef4444;
        --purple:    #c084fc;
        --grad-1:    linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        --grad-cool: linear-gradient(135deg, #0ea5e9 0%, #4facfe 100%);
        --sidebar-w: 240px;
        --header-h:  56px;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html { font-size: 15px; }
    body {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        background: var(--bg);
        color: var(--text);
        line-height: 1.55;
        -webkit-font-smoothing: antialiased;
        min-height: 100vh;
    }
    a { color: var(--primary); text-decoration: none; }
    a:hover { text-decoration: underline; }
    code, pre, .mono {
        font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        font-size: 0.85em;
    }

    /* ===== Page chrome ===== */
    .topbar {
        position: sticky; top: 0; z-index: 50;
        height: var(--header-h);
        background: rgba(12, 14, 18, 0.85);
        backdrop-filter: blur(14px);
        -webkit-backdrop-filter: blur(14px);
        border-bottom: 1px solid var(--border);
        display: flex; align-items: center;
        padding: 0 1.25rem;
        gap: 0.85rem;
    }
    .topbar .brand {
        display: flex; align-items: center; gap: 0.55rem;
        font-weight: 700; font-size: 1rem;
        color: var(--text);
        text-decoration: none;
    }
    .topbar .brand i {
        background: var(--grad-1);
        -webkit-background-clip: text;
        background-clip: text;
        color: transparent;
        font-size: 1.2rem;
    }
    .topbar .version-pill {
        padding: 0.18rem 0.55rem;
        background: rgba(79, 172, 254, 0.15);
        color: var(--primary);
        border: 1px solid rgba(79, 172, 254, 0.35);
        border-radius: 999px;
        font-size: 0.7rem;
        font-weight: 600;
        letter-spacing: 0.05em;
        text-transform: uppercase;
    }
    .topbar .search {
        flex: 1;
        max-width: 420px;
        position: relative;
    }
    .topbar .search input {
        width: 100%;
        background: var(--bg-2);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 0.5rem 0.85rem 0.5rem 2.1rem;
        color: var(--text);
        font-family: inherit;
        font-size: 0.85rem;
        outline: none;
        transition: border-color 0.15s, box-shadow 0.15s;
    }
    .topbar .search input::placeholder { color: rgba(154, 164, 178, 0.6); }
    .topbar .search input:focus {
        border-color: rgba(79, 172, 254, 0.55);
        box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.15);
    }
    .topbar .search i {
        position: absolute; left: 0.7rem; top: 50%;
        transform: translateY(-50%);
        color: var(--text-mut); font-size: 0.85rem;
    }
    .topbar .links { display: flex; gap: 0.4rem; margin-left: auto; }
    .topbar .links a {
        padding: 0.4rem 0.75rem;
        background: var(--bg-2);
        border: 1px solid var(--border);
        border-radius: 8px;
        color: var(--text);
        font-size: 0.8rem;
        font-weight: 500;
        text-decoration: none;
        display: inline-flex; align-items: center; gap: 0.35rem;
        transition: all 0.15s ease;
    }
    .topbar .links a:hover {
        background: var(--bg-3); border-color: var(--border-2);
        text-decoration: none;
    }

    /* ===== Layout ===== */
    .layout {
        display: grid;
        grid-template-columns: var(--sidebar-w) 1fr;
        gap: 0;
        min-height: calc(100vh - var(--header-h));
    }

    /* ===== Sidebar TOC ===== */
    .toc {
        position: sticky;
        top: var(--header-h);
        height: calc(100vh - var(--header-h));
        overflow-y: auto;
        background: rgba(17, 19, 22, 0.55);
        backdrop-filter: blur(10px);
        border-right: 1px solid var(--border);
        padding: 1.1rem 0.7rem;
    }
    .toc h4 {
        font-size: 0.66rem;
        text-transform: uppercase;
        color: var(--text-mut);
        letter-spacing: 0.08em;
        margin: 0.5rem 0.7rem 0.4rem;
        font-weight: 600;
    }
    .toc a.toc-item {
        display: flex; align-items: center; gap: 0.55rem;
        padding: 0.45rem 0.7rem;
        border-radius: 8px;
        color: var(--text-mut);
        text-decoration: none;
        font-size: 0.85rem;
        margin-bottom: 0.15rem;
        transition: all 0.15s;
    }
    .toc a.toc-item:hover {
        background: rgba(255, 255, 255, 0.04);
        color: var(--text);
        text-decoration: none;
    }
    .toc a.toc-item.active {
        background: rgba(79, 172, 254, 0.12);
        color: var(--primary);
        border-left: 3px solid var(--primary);
        padding-left: calc(0.7rem - 3px);
    }
    .toc a.toc-item i {
        width: 16px; text-align: center; font-size: 0.85rem;
    }
    .toc a.toc-item .count {
        margin-left: auto;
        background: rgba(255, 255, 255, 0.06);
        font-size: 0.65rem;
        padding: 0.05rem 0.4rem;
        border-radius: 999px;
        color: var(--text-mut);
    }
    .toc a.toc-item.active .count {
        background: rgba(79, 172, 254, 0.2);
        color: var(--primary);
    }

    /* ===== Main content ===== */
    .content {
        padding: 1.4rem 1.6rem 4rem;
        max-width: 1100px;
        width: 100%;
    }
    .hero {
        background:
            radial-gradient(800px 320px at 0% 0%, rgba(102, 126, 234, 0.18), transparent 60%),
            radial-gradient(800px 320px at 100% 100%, rgba(118, 75, 162, 0.18), transparent 60%),
            linear-gradient(160deg, rgba(20, 22, 27, 0.96), rgba(13, 15, 20, 0.96));
        border: 1px solid var(--border-2);
        border-radius: 16px;
        padding: 1.6rem 1.75rem;
        margin-bottom: 1.5rem;
        position: relative;
        overflow: hidden;
    }
    .hero h1 {
        font-size: 1.65rem;
        font-weight: 700;
        margin-bottom: 0.45rem;
        background: var(--grad-1);
        -webkit-background-clip: text;
        background-clip: text;
        color: transparent;
        line-height: 1.2;
    }
    .hero p { color: var(--text-mut); font-size: 0.95rem; max-width: 700px; }
    .hero .pills { display: flex; gap: 0.45rem; flex-wrap: wrap; margin-top: 1rem; }
    .hero .pill {
        display: inline-flex; align-items: center; gap: 0.35rem;
        padding: 0.32rem 0.75rem;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid var(--border);
        border-radius: 999px;
        font-size: 0.74rem;
        color: var(--text);
        font-weight: 500;
    }
    .hero .pill i { color: var(--primary); }
    .hero .stats {
        position: absolute;
        top: 1.3rem; right: 1.6rem;
        text-align: right;
    }
    .hero .stats .num {
        font-size: 2.1rem;
        font-weight: 800;
        background: var(--grad-cool);
        -webkit-background-clip: text;
        background-clip: text;
        color: transparent;
        line-height: 1;
    }
    .hero .stats .lbl {
        font-size: 0.7rem; color: var(--text-mut);
        text-transform: uppercase; letter-spacing: 0.08em;
        margin-top: 0.25rem;
    }

    /* ===== Cards ===== */
    .card {
        background: linear-gradient(160deg, rgba(20, 22, 27, 0.85), rgba(13, 15, 20, 0.85));
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 1rem 1.1rem;
        margin-bottom: 1rem;
    }
    .card h2 {
        font-size: 1.05rem; font-weight: 700;
        display: flex; align-items: center; gap: 0.55rem;
        margin: 0.2rem 0 0.9rem;
        color: var(--text);
    }
    .card h2 i { color: var(--primary); font-size: 1rem; }
    .card h3 {
        font-size: 0.9rem; font-weight: 600; color: var(--text);
        margin: 0.85rem 0 0.4rem;
    }
    .card p { color: var(--text-mut); font-size: 0.88rem; }
    .card ul { margin: 0.45rem 0 0 1.15rem; color: var(--text-mut); font-size: 0.88rem; }
    .card ul li { margin: 0.2rem 0; }
    .card ul li code { color: var(--text); }

    /* ===== Endpoint groups ===== */
    .group-card {
        background: linear-gradient(160deg, rgba(20, 22, 27, 0.85), rgba(13, 15, 20, 0.85));
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 1rem 1.1rem;
        margin-bottom: 1rem;
    }
    .group-head {
        display: flex; align-items: center; gap: 0.6rem;
        margin: 0.2rem 0 0.85rem;
        padding-bottom: 0.7rem;
        border-bottom: 1px solid var(--border);
    }
    .group-head h2 {
        font-size: 1.05rem;
        font-weight: 700;
        margin: 0;
        display: flex; align-items: center; gap: 0.55rem;
        color: var(--text);
    }
    .group-head h2 i {
        background: var(--grad-1);
        -webkit-background-clip: text; background-clip: text;
        color: transparent;
    }
    .group-head .count {
        margin-left: auto;
        background: rgba(255, 255, 255, 0.05);
        color: var(--text-mut);
        padding: 0.15rem 0.55rem;
        border-radius: 999px;
        font-size: 0.7rem;
        font-weight: 600;
    }

    /* ===== Endpoint row ===== */
    .endpoint {
        background: rgba(255, 255, 255, 0.02);
        border: 1px solid var(--border);
        border-radius: 10px;
        margin-bottom: 0.55rem;
        overflow: hidden;
        transition: border-color 0.15s, transform 0.1s;
    }
    .endpoint:hover { border-color: var(--border-2); }
    .endpoint summary {
        list-style: none;
        cursor: pointer;
        padding: 0.55rem 0.85rem;
        display: flex; align-items: center; gap: 0.6rem;
        flex-wrap: wrap;
        user-select: none;
    }
    .endpoint summary::-webkit-details-marker { display: none; }
    .endpoint summary:hover { background: rgba(255, 255, 255, 0.03); }
    .endpoint[open] summary { border-bottom: 1px solid var(--border); }
    .endpoint .chev {
        color: var(--text-mut);
        font-size: 0.7rem;
        transition: transform 0.18s ease;
    }
    .endpoint[open] .chev { transform: rotate(90deg); }
    .methods { display: inline-flex; gap: 0.25rem; }
    .method {
        font-size: 0.65rem; font-weight: 700;
        padding: 0.22rem 0.55rem;
        border-radius: 6px;
        letter-spacing: 0.04em;
        font-family: 'JetBrains Mono', monospace;
    }
    .method.GET    { background: rgba(52, 211, 153, 0.18);  color: #34d399; border: 1px solid rgba(52, 211, 153, 0.35); }
    .method.POST   { background: rgba(79, 172, 254, 0.18);  color: #4facfe; border: 1px solid rgba(79, 172, 254, 0.35); }
    .method.PUT    { background: rgba(251, 191, 36, 0.18);  color: #fbbf24; border: 1px solid rgba(251, 191, 36, 0.35); }
    .method.PATCH  { background: rgba(192, 132, 252, 0.18); color: #c084fc; border: 1px solid rgba(192, 132, 252, 0.35); }
    .method.DELETE { background: rgba(239, 68, 68, 0.18);   color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.35); }
    .path {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.82rem;
        color: var(--text);
        font-weight: 500;
    }
    .endpoint .desc {
        margin-left: auto;
        color: var(--text-mut);
        font-size: 0.78rem;
        max-width: 50%;
        text-align: right;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .endpoint-body {
        padding: 0.85rem 0.9rem;
        background: rgba(0, 0, 0, 0.18);
    }
    .endpoint-body .label {
        font-size: 0.66rem;
        text-transform: uppercase;
        color: var(--text-mut);
        letter-spacing: 0.08em;
        margin: 0 0 0.35rem;
        font-weight: 600;
    }
    .endpoint-body p.desc-full {
        color: var(--text); font-size: 0.85rem; margin-bottom: 0.7rem;
    }

    /* Code block + copy button */
    .codeblock {
        position: relative;
        background: #07090c;
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 0.7rem 0.9rem;
        margin: 0.35rem 0 0.6rem;
        overflow-x: auto;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.78rem;
        color: #c9d4e6;
        white-space: pre;
    }
    .codeblock .copy {
        position: absolute; top: 0.45rem; right: 0.45rem;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid var(--border-2);
        color: var(--text-mut);
        padding: 0.22rem 0.5rem;
        border-radius: 6px;
        cursor: pointer;
        font-size: 0.7rem;
        font-family: inherit;
        transition: all 0.15s;
    }
    .codeblock .copy:hover {
        background: rgba(79, 172, 254, 0.12);
        color: var(--primary);
        border-color: rgba(79, 172, 254, 0.4);
    }
    .codeblock .copy.copied {
        background: rgba(52, 211, 153, 0.15);
        color: var(--green);
        border-color: rgba(52, 211, 153, 0.4);
    }

    /* ===== Info boxes ===== */
    .info-box, .warn-box, .ok-box {
        padding: 0.7rem 0.95rem;
        border-radius: 8px;
        margin: 0.55rem 0;
        font-size: 0.85rem;
        display: flex; align-items: flex-start; gap: 0.55rem;
        border: 1px solid;
    }
    .info-box { background: rgba(79, 172, 254, 0.08);  color: var(--text); border-color: rgba(79, 172, 254, 0.3); }
    .info-box i { color: var(--primary); }
    .warn-box { background: rgba(251, 191, 36, 0.08);  color: var(--text); border-color: rgba(251, 191, 36, 0.3); }
    .warn-box i { color: var(--yellow); }
    .ok-box   { background: rgba(52, 211, 153, 0.08);  color: var(--text); border-color: rgba(52, 211, 153, 0.3); }
    .ok-box i { color: var(--green); }

    /* ===== Mobile ===== */
    .menu-btn {
        display: none;
        background: none; border: none;
        color: var(--text); font-size: 1.1rem;
        cursor: pointer; padding: 0.35rem 0.55rem;
        border-radius: 8px;
    }
    .menu-btn:hover { background: var(--bg-2); }

    @media (max-width: 900px) {
        html { font-size: 14px; }
        .layout { grid-template-columns: 1fr; }
        .toc {
            position: fixed;
            top: var(--header-h); left: 0; bottom: 0;
            width: 78vw; max-width: 280px;
            transform: translateX(-100%);
            transition: transform 0.25s ease;
            z-index: 40;
            background: rgba(12, 14, 18, 0.98);
        }
        .toc.open { transform: translateX(0); box-shadow: 0 0 30px rgba(0,0,0,0.5); }
        .menu-btn { display: block; }
        .topbar .search { max-width: none; }
        .content { padding: 1rem 0.85rem 3rem; }
        .hero { padding: 1.1rem 1.2rem; }
        .hero h1 { font-size: 1.3rem; }
        .hero .stats { position: static; text-align: left; margin-top: 0.9rem; }
        .endpoint .desc { display: none; }
    }
    @media (max-width: 420px) {
        .topbar .brand span { display: none; }
        .topbar .links a span { display: none; }
        .endpoint .path { font-size: 0.76rem; }
    }

    /* Scrollbar styling */
    *::-webkit-scrollbar { width: 8px; height: 8px; }
    *::-webkit-scrollbar-track { background: transparent; }
    *::-webkit-scrollbar-thumb {
        background: rgba(255, 255, 255, 0.08);
        border-radius: 4px;
    }
    *::-webkit-scrollbar-thumb:hover { background: rgba(255, 255, 255, 0.15); }
</style>
</head>
<body>

<header class="topbar">
    <button class="menu-btn" id="menuBtn" aria-label="Toggle menu">
        <i class="fas fa-bars"></i>
    </button>
    <a href="/" class="brand">
        <i class="fas fa-cube"></i>
        <span>StrenoxCloud Panel <span class="version-pill">API v1</span></span>
    </a>
    <div class="search">
        <i class="fas fa-magnifying-glass"></i>
        <input type="search" id="searchBox" placeholder="Search endpoints (e.g. vps/start, users/reset)">
    </div>
    <div class="links">
        <a href="/admin/api"><i class="fas fa-key"></i><span>API Keys</span></a>
        <a href="/api/v1/info" target="_blank"><i class="fas fa-code"></i><span>JSON</span></a>
        <a href="/dashboard"><i class="fas fa-arrow-left"></i><span>Panel</span></a>
    </div>
</header>

<div class="layout">
    <!-- Sidebar TOC -->
    <aside class="toc" id="toc">
        <h4>Getting Started</h4>
        <a class="toc-item" href="#overview"><i class="fas fa-rocket"></i><span>Overview</span></a>
        <a class="toc-item" href="#auth"><i class="fas fa-shield-halved"></i><span>Authentication</span></a>
        <a class="toc-item" href="#errors"><i class="fas fa-circle-exclamation"></i><span>Error Codes</span></a>

        <h4>Endpoints</h4>
        {% for g in ordered_groups %}
        {% set meta = group_meta.get(g, (g.title(), 'fa-folder')) %}
        <a class="toc-item" href="#group-{{ g }}">
            <i class="fas {{ meta[1] }}"></i>
            <span>{{ meta[0] }}</span>
            <span class="count">{{ grouped[g]|length }}</span>
        </a>
        {% endfor %}
    </aside>

    <!-- Main column -->
    <main class="content">
        <section class="hero">
            <div class="stats">
                <div class="num">{{ rules|length }}</div>
                <div class="lbl">endpoints</div>
            </div>
            <h1>StrenoxCloud Panel REST API</h1>
            <p>Drive every action available in the web UI through plain HTTP requests. Manage VPSes, nodes, users, ports, settings, backups and more from your own scripts and integrations.</p>
            <div class="pills">
                <span class="pill"><i class="fas fa-circle-check"></i> JSON in / JSON out</span>
                <span class="pill"><i class="fas fa-key"></i> API key auth</span>
                <span class="pill"><i class="fas fa-bolt"></i> {{ rules|length }} endpoints</span>
                <span class="pill"><i class="fas fa-code-branch"></i> v1.0</span>
            </div>
        </section>

        <section class="card" id="overview">
            <h2><i class="fas fa-rocket"></i> Getting Started</h2>
            <h3>Base URL</h3>
            <div class="codeblock"><button class="copy">Copy</button>{{ base_url }}/api/v1</div>
            <h3>Quick example</h3>
            <div class="codeblock"><button class="copy">Copy</button>curl -H "X-API-Key: YOUR_KEY" {{ base_url }}/api/v1/me</div>
            <div class="ok-box">
                <i class="fas fa-check-circle"></i>
                <div>Generate an API key from <a href="/admin/api">/admin/api</a>, then start hitting endpoints. Every successful response includes <code>"success": true</code>.</div>
            </div>
        </section>

        <section class="card" id="auth">
            <h2><i class="fas fa-shield-halved"></i> Authentication</h2>
            <p>All requests (except <code>/info</code>, <code>/health</code> and <code>/docs</code>) require an API key.</p>
            <h3>Header (recommended)</h3>
            <div class="codeblock"><button class="copy">Copy</button>X-API-Key: your_api_key_here</div>
            <h3>Query string (fallback)</h3>
            <div class="codeblock"><button class="copy">Copy</button>{{ base_url }}/api/v1/vps?api_key=your_api_key_here</div>
            <div class="info-box">
                <i class="fas fa-circle-info"></i>
                <div>Endpoints tagged <strong>Admin</strong> require a key owned by an admin user. Non-admin keys can still read their own VPSes, profile, notifications and create port forwards.</div>
            </div>
        </section>

        <section class="card" id="errors">
            <h2><i class="fas fa-circle-exclamation"></i> Error Codes</h2>
            <ul>
                <li><code>200</code> — Success</li>
                <li><code>201</code> — Created</li>
                <li><code>400</code> — Bad request (validation / missing fields)</li>
                <li><code>401</code> — Unauthorized (missing / invalid API key)</li>
                <li><code>403</code> — Forbidden (key lacks admin scope)</li>
                <li><code>404</code> — Resource not found</li>
                <li><code>405</code> — Method not allowed</li>
                <li><code>429</code> — Rate-limit / capacity reached</li>
                <li><code>500</code> — Server error</li>
            </ul>
            <p style="margin-top:0.6rem;">Errors always look like:</p>
            <div class="codeblock"><button class="copy">Copy</button>{
  "success": false,
  "error": "Short reason",
  "message": "More detail (optional)"
}</div>
        </section>

        {% for g in ordered_groups %}
        {% set meta = group_meta.get(g, (g.title(), 'fa-folder')) %}
        <section class="group-card" id="group-{{ g }}">
            <div class="group-head">
                <h2><i class="fas {{ meta[1] }}"></i> {{ meta[0] }}</h2>
                <span class="count">{{ grouped[g]|length }} endpoints</span>
            </div>
            {% for r in grouped[g] %}
            <details class="endpoint"
                     data-path="{{ r.path|lower }}"
                     data-methods="{{ r.methods|join(' ')|lower }}"
                     data-desc="{{ r.description|lower }}">
                <summary>
                    <span class="chev"><i class="fas fa-chevron-right"></i></span>
                    <span class="methods">
                        {% for m in r.methods %}<span class="method {{ m }}">{{ m }}</span>{% endfor %}
                    </span>
                    <span class="path">{{ r.path }}</span>
                    {% if r.description %}<span class="desc">{{ r.description }}</span>{% endif %}
                </summary>
                <div class="endpoint-body">
                    {% if r.description %}<p class="desc-full">{{ r.description }}</p>{% endif %}
                    <p class="label">Example</p>
                    <div class="codeblock"><button class="copy">Copy</button>curl{% if 'GET' not in r.methods %} -X {{ r.methods[0] }}{% endif %} \
     -H "X-API-Key: $API_KEY" \\{% if r.methods[0] in ('POST','PUT','PATCH') %}
     -H "Content-Type: application/json" \\
     -d '{}' \\{% endif %}
     {{ base_url }}{{ r.path }}</div>
                </div>
            </details>
            {% endfor %}
        </section>
        {% endfor %}

        <div style="text-align:center; color: var(--text-mut); font-size: 0.78rem; margin-top: 2rem; padding-top: 1.5rem; border-top: 1px solid var(--border);">
            Generated live from the URL map · {{ rules|length }} endpoints total
        </div>
    </main>
</div>

<script>
    // ===== Mobile sidebar toggle =====
    const menuBtn = document.getElementById('menuBtn');
    const toc = document.getElementById('toc');
    menuBtn?.addEventListener('click', () => toc.classList.toggle('open'));
    document.addEventListener('click', (e) => {
        if (window.innerWidth <= 900
            && toc.classList.contains('open')
            && !toc.contains(e.target)
            && !menuBtn.contains(e.target)) {
            toc.classList.remove('open');
        }
    });
    toc.querySelectorAll('a.toc-item').forEach(a => {
        a.addEventListener('click', () => {
            if (window.innerWidth <= 900) toc.classList.remove('open');
        });
    });

    // ===== Copy buttons =====
    document.querySelectorAll('.codeblock .copy').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const block = btn.parentElement;
            const text = block.innerText.replace(/^Copy\\n?/, '').trim();
            try {
                await navigator.clipboard.writeText(text);
                btn.textContent = 'Copied!';
                btn.classList.add('copied');
                setTimeout(() => {
                    btn.textContent = 'Copy';
                    btn.classList.remove('copied');
                }, 1500);
            } catch (err) {
                btn.textContent = 'Failed';
                setTimeout(() => btn.textContent = 'Copy', 1500);
            }
        });
    });

    // ===== Endpoint search =====
    const searchBox = document.getElementById('searchBox');
    const allEndpoints = document.querySelectorAll('.endpoint');
    const allGroups = document.querySelectorAll('.group-card');
    function applyFilter() {
        const q = (searchBox.value || '').trim().toLowerCase();
        if (!q) {
            allEndpoints.forEach(e => e.style.display = '');
            allGroups.forEach(g => g.style.display = '');
            return;
        }
        const tokens = q.split(/\\s+/).filter(Boolean);
        allEndpoints.forEach(ep => {
            const hay = (ep.dataset.path || '')
                + ' ' + (ep.dataset.methods || '')
                + ' ' + (ep.dataset.desc || '');
            const match = tokens.every(t => hay.includes(t));
            ep.style.display = match ? '' : 'none';
        });
        // Hide groups that have no visible endpoints.
        allGroups.forEach(g => {
            const anyVisible = [...g.querySelectorAll('.endpoint')]
                .some(e => e.style.display !== 'none');
            g.style.display = anyVisible ? '' : 'none';
        });
    }
    searchBox?.addEventListener('input', applyFilter);
    // Press "/" to focus the search box (avoiding inputs).
    document.addEventListener('keydown', (e) => {
        if (e.key === '/' && document.activeElement.tagName !== 'INPUT'
            && document.activeElement.tagName !== 'TEXTAREA') {
            e.preventDefault();
            searchBox?.focus();
        }
    });

    // ===== TOC scroll-spy =====
    const tocLinks = [...document.querySelectorAll('.toc a.toc-item')];
    const targets = tocLinks
        .map(a => document.querySelector(a.getAttribute('href')))
        .filter(Boolean);
    function onScroll() {
        let activeIdx = 0;
        const offset = 80;
        for (let i = 0; i < targets.length; i++) {
            if (targets[i].getBoundingClientRect().top - offset <= 0) {
                activeIdx = i;
            }
        }
        tocLinks.forEach((a, i) => a.classList.toggle('active', i === activeIdx));
    }
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
</script>
</body>
</html>
'''
    base_url = request.host_url.rstrip('/')
    return render_template_string(
        html,
        rules=rules,
        grouped=grouped,
        ordered_groups=ordered_groups,
        group_meta=group_meta,
        base_url=base_url,
    )


# ============================================================================
# Error Handlers
# ============================================================================

@api_bp.errorhandler(404)
def api_not_found(error):
    return jsonify({
        'success': False,
        'error': 'Endpoint not found',
        'message': 'The requested API endpoint does not exist'
    }), 404

@api_bp.errorhandler(405)
def api_method_not_allowed(error):
    return jsonify({
        'success': False,
        'error': 'Method not allowed',
        'message': 'The HTTP method is not allowed for this endpoint'
    }), 405

@api_bp.errorhandler(500)
def api_internal_error(error):
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500

# ============================================================================
# API Documentation
# ============================================================================
# ============================================================================
# VPS Reinstall API
# ============================================================================

@api_bp.route('/vps/<int:vps_id>/reinstall', methods=['POST'])
@require_api_key
def api_reinstall_vps(vps_id):
    """Reinstall VPS with new OS"""
    from hvm import get_db, get_vps_by_id, run_sync, execute_lxc
    
    try:
        data = request.get_json() or {}
        os_version = data.get('os_version')
        
        if not os_version:
            return jsonify({'success': False, 'error': 'os_version required'}), 400
        
        vps = get_vps_by_id(vps_id)
        
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Check access
        if not request.api_key_info['is_admin'] and vps['user_id'] != request.api_key_info['user_id']:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Stop and delete container
        try:
            run_sync(execute_lxc(vps['container_name'], f"stop {vps['container_name']} --force", node_id=vps['node_id']))
            run_sync(execute_lxc(vps['container_name'], f"delete {vps['container_name']} --force", node_id=vps['node_id']))
        except:
            pass
        
        # Update database
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('UPDATE vps SET os_version = ?, status = "installing" WHERE id = ?', (os_version, vps_id))
            conn.commit()
        
        # Trigger reinstall (this would call install_vps_async in production)
        return jsonify({
            'success': True,
            'message': 'VPS reinstall started',
            'note': 'Check VPS status for installation progress'
        })
    except Exception as e:
        logger.error(f"API reinstall VPS error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# VPS Migration API
# ============================================================================

@api_bp.route('/vps/<int:vps_id>/migrate', methods=['POST'])
@require_admin_api
def api_migrate_vps(vps_id):
    """Migrate VPS to another node"""
    from hvm import get_db, get_vps_by_id
    
    try:
        data = request.get_json() or {}
        target_node_id = data.get('target_node_id')
        
        if not target_node_id:
            return jsonify({'success': False, 'error': 'target_node_id required'}), 400
        
        vps = get_vps_by_id(vps_id)
        
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        if vps['node_id'] == target_node_id:
            return jsonify({'success': False, 'error': 'VPS is already on target node'}), 400
        
        # Update database to mark as transferring
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('UPDATE vps SET status = "transferring" WHERE id = ?', (vps_id,))
            conn.commit()
        
        # Trigger migration (this would call live_migrate_vps in production)
        return jsonify({
            'success': True,
            'message': 'VPS migration started',
            'note': 'Check VPS status for migration progress'
        })
    except Exception as e:
        logger.error(f"API migrate VPS error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# VPS Stats API
# ============================================================================

@api_bp.route('/vps/<int:vps_id>/stats', methods=['GET'])
@require_api_key
def api_get_vps_stats(vps_id):
    """Get VPS resource usage statistics"""
    from hvm import get_vps_by_id, run_sync, get_container_stats
    
    try:
        vps = get_vps_by_id(vps_id)
        
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Check access
        if not request.api_key_info['is_admin'] and vps['user_id'] != request.api_key_info['user_id']:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get live stats
        try:
            stats = run_sync(get_container_stats(vps['container_name'], vps['node_id']))
            
            return jsonify({
                'success': True,
                'stats': stats
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': 'Could not retrieve stats',
                'message': str(e)
            }), 500
    except Exception as e:
        logger.error(f"API get VPS stats error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Backup Management API
# ============================================================================

@api_bp.route('/backups', methods=['GET'])
@require_admin_api
def api_list_backups():
    """List all backups"""
    import os
    import glob
    
    try:
        backup_dir = 'backups'
        if not os.path.exists(backup_dir):
            return jsonify({'success': True, 'backups': [], 'count': 0})
        
        backups = []
        for backup_file in glob.glob(os.path.join(backup_dir, '*.db')):
            stat = os.stat(backup_file)
            backups.append({
                'filename': os.path.basename(backup_file),
                'path': backup_file,
                'size': stat.st_size,
                'created_at': datetime.fromtimestamp(stat.st_ctime).isoformat()
            })
        
        backups.sort(key=lambda x: x['created_at'], reverse=True)
        
        return jsonify({
            'success': True,
            'backups': backups,
            'count': len(backups)
        })
    except Exception as e:
        logger.error(f"API list backups error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/backups/create', methods=['POST'])
@require_admin_api
def api_create_backup():
    """Create database backup"""
    from hvm import create_backup
    
    try:
        backup_file = create_backup()
        
        if backup_file:
            return jsonify({
                'success': True,
                'backup_file': backup_file,
                'message': 'Backup created successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to create backup'
            }), 500
    except Exception as e:
        logger.error(f"API create backup error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# OS Templates API
# ============================================================================

@api_bp.route('/os-templates', methods=['GET'])
@require_api_key
def api_list_os_templates():
    """List available OS templates"""
    from hvm import OS_OPTIONS
    
    try:
        templates = []
        for key, value in OS_OPTIONS.items():
            templates.append({
                'key': key,
                'name': value['name'],
                'image': value['image'],
                'icon': value.get('icon', 'default.png')
            })
        
        return jsonify({
            'success': True,
            'templates': templates,
            'count': len(templates)
        })
    except Exception as e:
        logger.error(f"API list OS templates error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Bandwidth API
# ============================================================================

@api_bp.route('/vps/<int:vps_id>/bandwidth', methods=['GET'])
@require_api_key
def api_get_vps_bandwidth():
    """Get VPS bandwidth usage"""
    from hvm import get_vps_by_id, get_db
    
    try:
        vps = get_vps_by_id(vps_id)
        
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Check access
        if not request.api_key_info['is_admin'] and vps['user_id'] != request.api_key_info['user_id']:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get bandwidth data from database
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''SELECT bandwidth_used, bandwidth_quota, bandwidth_reset_date
                          FROM vps WHERE id = ?''', (vps_id,))
            result = cur.fetchone()
            
            if result:
                return jsonify({
                    'success': True,
                    'bandwidth': {
                        'used_gb': result['bandwidth_used'] or 0,
                        'quota_gb': result['bandwidth_quota'] or 0,
                        'reset_date': result['bandwidth_reset_date'],
                        'percentage': (result['bandwidth_used'] / result['bandwidth_quota'] * 100) if result['bandwidth_quota'] > 0 else 0
                    }
                })
        
        return jsonify({'success': False, 'error': 'Could not retrieve bandwidth data'}), 500
    except Exception as e:
        logger.error(f"API get VPS bandwidth error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Logs API
# ============================================================================

@api_bp.route('/logs', methods=['GET'])
@require_admin_api
def api_get_logs():
    """Get system logs (admin only)"""
    try:
        lines = request.args.get('lines', 100, type=int)
        level = request.args.get('level', 'all')  # all, error, warning, info
        
        log_file = 'hvm.log'
        
        if not __import__('os').path.exists(log_file):
            return jsonify({'success': True, 'logs': [], 'count': 0})
        
        with open(log_file, 'r') as f:
            all_lines = f.readlines()
        
        # Filter by level if specified
        if level != 'all':
            filtered_lines = [line for line in all_lines if level.upper() in line]
        else:
            filtered_lines = all_lines
        
        # Get last N lines
        recent_lines = filtered_lines[-lines:]
        
        return jsonify({
            'success': True,
            'logs': recent_lines,
            'count': len(recent_lines),
            'total': len(all_lines)
        })
    except Exception as e:
        logger.error(f"API get logs error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Search API
# ============================================================================

@api_bp.route('/search', methods=['GET'])
@require_api_key
def api_search():
    """Search across VPS, users, and nodes"""
    from hvm import get_db
    
    try:
        query = request.args.get('q', '')
        
        if not query:
            return jsonify({'success': False, 'error': 'query parameter required'}), 400
        
        results = {
            'vps': [],
            'users': [],
            'nodes': []
        }
        
        with get_db() as conn:
            cur = conn.cursor()
            
            # Search VPS
            if request.api_key_info['is_admin']:
                cur.execute('''SELECT v.*, u.username FROM vps v
                              LEFT JOIN users u ON v.user_id = u.id
                              WHERE v.hostname LIKE ? OR v.container_name LIKE ? OR v.ip_address LIKE ?
                              LIMIT 20''',
                           (f'%{query}%', f'%{query}%', f'%{query}%'))
            else:
                cur.execute('''SELECT * FROM vps
                              WHERE user_id = ? AND (hostname LIKE ? OR container_name LIKE ? OR ip_address LIKE ?)
                              LIMIT 20''',
                           (request.api_key_info['user_id'], f'%{query}%', f'%{query}%', f'%{query}%'))
            
            results['vps'] = [dict(row) for row in cur.fetchall()]
            
            # Search users (admin only)
            if request.api_key_info['is_admin']:
                cur.execute('''SELECT id, username, email, is_admin, created_at FROM users
                              WHERE username LIKE ? OR email LIKE ?
                              LIMIT 20''',
                           (f'%{query}%', f'%{query}%'))
                results['users'] = [dict(row) for row in cur.fetchall()]
                
                # Search nodes (admin only)
                cur.execute('''SELECT * FROM nodes
                              WHERE name LIKE ? OR location LIKE ? OR url LIKE ?
                              LIMIT 20''',
                           (f'%{query}%', f'%{query}%', f'%{query}%'))
                results['nodes'] = [dict(row) for row in cur.fetchall()]
        
        return jsonify({
            'success': True,
            'query': query,
            'results': results,
            'total': len(results['vps']) + len(results['users']) + len(results['nodes'])
        })
    except Exception as e:
        logger.error(f"API search error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Webhook API
# ============================================================================

@api_bp.route('/webhooks', methods=['GET'])
@require_admin_api
def api_list_webhooks():
    """List all webhooks"""
    from hvm import get_db
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM webhooks ORDER BY created_at DESC')
            webhooks = [dict(row) for row in cur.fetchall()]
        
        return jsonify({
            'success': True,
            'webhooks': webhooks,
            'count': len(webhooks)
        })
    except Exception as e:
        logger.error(f"API list webhooks error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/webhooks', methods=['POST'])
@require_admin_api
def api_create_webhook():
    """Create new webhook"""
    from hvm import get_db
    
    try:
        data = request.get_json() or {}
        
        url = data.get('url')
        events = data.get('events', [])
        is_active = data.get('is_active', True)
        
        if not url or not events:
            return jsonify({
                'success': False,
                'error': 'Missing required fields',
                'required': ['url', 'events']
            }), 400
        
        now = datetime.now().isoformat()
        
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''INSERT INTO webhooks (url, events, is_active, created_at)
                          VALUES (?, ?, ?, ?)''',
                       (url, ','.join(events), 1 if is_active else 0, now))
            conn.commit()
            webhook_id = cur.lastrowid
        
        return jsonify({
            'success': True,
            'webhook_id': webhook_id,
            'message': 'Webhook created successfully'
        }), 201
    except Exception as e:
        logger.error(f"API create webhook error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/webhooks/<int:webhook_id>', methods=['DELETE'])
@require_admin_api
def api_delete_webhook(webhook_id):
    """Delete webhook"""
    from hvm import get_db
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('DELETE FROM webhooks WHERE id = ?', (webhook_id,))
            conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'Webhook deleted successfully'
        })
    except Exception as e:
        logger.error(f"API delete webhook error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Full panel coverage — endpoints below mirror every administrative action
# available in the web UI so the panel can be fully driven from an API key.
# Grouped by area; ordering matches the corresponding admin pages.
# ============================================================================

# ---------------------------------------------------------------------------
# Identity helper — "who am I?"
# ---------------------------------------------------------------------------

@api_bp.route('/me', methods=['GET'])
@require_api_key
def api_me():
    """Return the authenticated user / API-key info."""
    info = request.api_key_info or {}
    user = request.api_user or {}
    return jsonify({
        'success': True,
        'user': {
            'id': info.get('user_id'),
            'username': user.get('username'),
            'email': user.get('email'),
            'is_admin': bool(info.get('is_admin')),
        },
        'api_key': {
            'id': info.get('key_id'),
            'name': user.get('name'),
            'is_admin': bool(info.get('is_admin')),
        },
    })


# ---------------------------------------------------------------------------
# Profile (authenticated user — self-service)
# ---------------------------------------------------------------------------

@api_bp.route('/profile', methods=['GET'])
@require_api_key
def api_get_profile():
    """Get the calling user's own profile."""
    from hvm import get_db
    user_id = request.api_key_info['user_id']
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''SELECT id, username, email, is_admin, is_main_admin,
                                  profile_picture, created_at, last_login,
                                  last_active, discord_id, discord_username,
                                  discord_email
                           FROM users WHERE id = ?''', (user_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({'success': False, 'error': 'User not found'}), 404
        return jsonify({'success': True, 'user': dict(row)})
    except Exception as e:
        logger.error(f"API get profile error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/profile', methods=['PUT', 'PATCH'])
@require_api_key
def api_update_profile():
    """Update the calling user's own profile (email / profile picture)."""
    from hvm import get_db
    user_id = request.api_key_info['user_id']
    data = request.get_json() or {}
    allowed = {'email', 'profile_picture'}
    updates = {k: v for k, v in data.items() if k in allowed}
    if not updates:
        return jsonify({'success': False, 'error': 'No updatable fields provided',
                        'allowed': sorted(allowed)}), 400
    try:
        with get_db() as conn:
            cur = conn.cursor()
            sets = ', '.join(f'{k} = ?' for k in updates)
            cur.execute(f'UPDATE users SET {sets} WHERE id = ?',
                        (*updates.values(), user_id))
            conn.commit()
        return jsonify({'success': True, 'updated': list(updates.keys())})
    except Exception as e:
        logger.error(f"API update profile error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/profile/change-password', methods=['POST'])
@require_api_key
def api_change_own_password():
    """Change the calling user's own login password."""
    from hvm import get_db
    from werkzeug.security import check_password_hash, generate_password_hash
    user_id = request.api_key_info['user_id']
    data = request.get_json() or {}
    current_pw = data.get('current_password') or data.get('old_password')
    new_pw = data.get('new_password')
    if not current_pw or not new_pw:
        return jsonify({'success': False,
                        'error': 'current_password and new_password are required'}), 400
    if len(new_pw) < 6:
        return jsonify({'success': False,
                        'error': 'new_password must be at least 6 characters'}), 400
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT password_hash FROM users WHERE id = ?', (user_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({'success': False, 'error': 'User not found'}), 404
            if not check_password_hash(row['password_hash'], current_pw):
                return jsonify({'success': False,
                                'error': 'Current password is incorrect'}), 401
            cur.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                        (generate_password_hash(new_pw), user_id))
            conn.commit()
        return jsonify({'success': True, 'message': 'Password changed'})
    except Exception as e:
        logger.error(f"API change own password error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ---------------------------------------------------------------------------
# User management — admin extensions
# ---------------------------------------------------------------------------

@api_bp.route('/users/<int:user_id>/reset-password', methods=['POST'])
@require_admin_api
def api_admin_reset_user_password(user_id):
    """Admin-reset another user's login password."""
    from hvm import get_db, log_activity
    from werkzeug.security import generate_password_hash
    data = request.get_json() or {}
    new_pw = data.get('new_password')
    if not new_pw or len(new_pw) < 6:
        return jsonify({'success': False,
                        'error': 'new_password (>= 6 chars) is required'}), 400
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT id, username FROM users WHERE id = ?', (user_id,))
            user = cur.fetchone()
            if not user:
                return jsonify({'success': False, 'error': 'User not found'}), 404
            cur.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                        (generate_password_hash(new_pw), user_id))
            conn.commit()
        log_activity(request.api_key_info['user_id'],
                     'admin_reset_user_password_api',
                     'user', str(user_id), {'username': user['username']})
        return jsonify({'success': True,
                        'message': f'Password reset for {user["username"]}'})
    except Exception as e:
        logger.error(f"API admin reset password error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/users/<int:user_id>/regenerate-api-key', methods=['POST'])
@require_admin_api
def api_admin_regenerate_user_api_key(user_id):
    """Regenerate an old-style per-user API key (legacy field on the users
    table). New API keys should be created via /api-keys instead."""
    from hvm import get_db, generate_api_key, log_activity
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT id, username FROM users WHERE id = ?', (user_id,))
            user = cur.fetchone()
            if not user:
                return jsonify({'success': False, 'error': 'User not found'}), 404
            new_key = generate_api_key()
            cur.execute('UPDATE users SET api_key = ? WHERE id = ?',
                        (new_key, user_id))
            conn.commit()
        log_activity(request.api_key_info['user_id'],
                     'admin_regenerate_user_api_key',
                     'user', str(user_id), {'username': user['username']})
        return jsonify({'success': True, 'api_key': new_key})
    except Exception as e:
        logger.error(f"API regen user key error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ---------------------------------------------------------------------------
# VPS — extended admin actions
# ---------------------------------------------------------------------------

@api_bp.route('/vps/<int:vps_id>', methods=['PUT', 'PATCH'])
@require_api_key
def api_update_vps(vps_id):
    """Update VPS attributes the panel exposes on the edit page (admin only
    for any change beyond owner-allowed fields)."""
    from hvm import get_db, log_activity
    info = request.api_key_info
    data = request.get_json() or {}
    # Whitelist of editable columns to prevent injection / id clobbering.
    admin_fields = {
        'container_name', 'os_version', 'config', 'ip_address',
        'expires_at', 'status', 'user_id', 'node_id', 'notes', 'is_whitelisted',
    }
    user_fields = {'notes'}
    fields = admin_fields if info.get('is_admin') else user_fields
    updates = {k: v for k, v in data.items() if k in fields}
    if not updates:
        return jsonify({'success': False,
                        'error': 'No editable fields provided',
                        'allowed': sorted(fields)}), 400
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT id, user_id, container_name FROM vps WHERE id = ?',
                        (vps_id,))
            vps = cur.fetchone()
            if not vps:
                return jsonify({'success': False, 'error': 'VPS not found'}), 404
            if not info.get('is_admin') and vps['user_id'] != info['user_id']:
                return jsonify({'success': False, 'error': 'Access denied'}), 403
            sets = ', '.join(f'{k} = ?' for k in updates)
            cur.execute(f'UPDATE vps SET {sets} WHERE id = ?',
                        (*updates.values(), vps_id))
            conn.commit()
        log_activity(info['user_id'], 'api_update_vps',
                     'vps', str(vps_id), updates)
        return jsonify({'success': True, 'updated': list(updates.keys())})
    except Exception as e:
        logger.error(f"API update VPS error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/vps/<int:vps_id>/renew', methods=['POST'])
@require_admin_api
def api_renew_vps(vps_id):
    """Extend a VPS's expiration date.

    Body: `{ "days": <int> }` or `{ "expires_at": "ISO-8601" }`.
    Defaults to +30 days from current expiration (or now if none).
    """
    from hvm import get_db, log_activity
    data = request.get_json() or {}
    days = data.get('days')
    explicit = data.get('expires_at')
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT id, container_name, expires_at FROM vps WHERE id = ?',
                        (vps_id,))
            vps = cur.fetchone()
            if not vps:
                return jsonify({'success': False, 'error': 'VPS not found'}), 404

            if explicit:
                new_expires = explicit
            else:
                from datetime import datetime as _dt, timedelta as _td
                add_days = int(days) if days else 30
                base = None
                if vps['expires_at']:
                    try:
                        base = _dt.fromisoformat(vps['expires_at'].replace('Z', ''))
                    except Exception:
                        base = None
                if not base or base < _dt.now():
                    base = _dt.now()
                new_expires = (base + _td(days=add_days)).isoformat()

            cur.execute('UPDATE vps SET expires_at = ?, status = "running" WHERE id = ?',
                        (new_expires, vps_id))
            conn.commit()
        log_activity(request.api_key_info['user_id'], 'api_renew_vps',
                     'vps', str(vps_id),
                     {'days': days, 'new_expires': new_expires})
        return jsonify({'success': True, 'new_expires_at': new_expires})
    except Exception as e:
        logger.error(f"API renew VPS error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/vps/<int:vps_id>/expiration', methods=['PUT', 'PATCH'])
@require_admin_api
def api_set_vps_expiration(vps_id):
    """Set a VPS's expiration date directly. Body: `{ "expires_at": "ISO" }`."""
    from hvm import get_db, log_activity
    data = request.get_json() or {}
    expires_at = data.get('expires_at')
    if not expires_at:
        return jsonify({'success': False, 'error': 'expires_at is required'}), 400
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('UPDATE vps SET expires_at = ? WHERE id = ?',
                        (expires_at, vps_id))
            if cur.rowcount == 0:
                return jsonify({'success': False, 'error': 'VPS not found'}), 404
            conn.commit()
        log_activity(request.api_key_info['user_id'], 'api_set_expiration',
                     'vps', str(vps_id), {'expires_at': expires_at})
        return jsonify({'success': True, 'expires_at': expires_at})
    except Exception as e:
        logger.error(f"API set expiration error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/vps/<int:vps_id>/whitelist', methods=['POST'])
@require_admin_api
def api_toggle_vps_whitelist(vps_id):
    """Toggle (or set) a VPS's whitelist flag — whitelisted VPS skip
    expiration / resource enforcement. Body: `{ "whitelisted": true/false }`."""
    from hvm import get_db, log_activity
    data = request.get_json() or {}
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT id, is_whitelisted FROM vps WHERE id = ?', (vps_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({'success': False, 'error': 'VPS not found'}), 404
            if 'whitelisted' in data:
                new_val = 1 if data['whitelisted'] else 0
            else:
                new_val = 0 if row['is_whitelisted'] else 1
            cur.execute('UPDATE vps SET is_whitelisted = ? WHERE id = ?',
                        (new_val, vps_id))
            conn.commit()
        log_activity(request.api_key_info['user_id'], 'api_toggle_whitelist',
                     'vps', str(vps_id), {'is_whitelisted': new_val})
        return jsonify({'success': True, 'is_whitelisted': bool(new_val)})
    except Exception as e:
        logger.error(f"API toggle whitelist error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/vps/<int:vps_id>/console', methods=['GET'])
@require_api_key
def api_get_vps_console_info(vps_id):
    """Get the SSH connection info the web console uses (host/port/user/pw).
    Owner or admin only. Useful for programmatic SSH automation."""
    from hvm import get_db, decrypt_node_password
    info = request.api_key_info
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''SELECT v.*, n.url AS node_url, n.api_key AS node_api_key,
                                  n.ip_addresses AS node_ips
                           FROM vps v
                           LEFT JOIN nodes n ON v.node_id = n.id
                           WHERE v.id = ?''', (vps_id,))
            vps = cur.fetchone()
            if not vps:
                return jsonify({'success': False, 'error': 'VPS not found'}), 404
            if not info.get('is_admin') and vps['user_id'] != info['user_id']:
                return jsonify({'success': False, 'error': 'Access denied'}), 403
            host = vps['ip_address'] or ''
            port = vps['ssh_port'] if 'ssh_port' in vps.keys() else 22
            try:
                password = (
                    decrypt_node_password(vps['ssh_password_encrypted'])
                    if 'ssh_password_encrypted' in vps.keys() and vps['ssh_password_encrypted']
                    else None
                )
            except Exception:
                password = None
        return jsonify({
            'success': True,
            'connection': {
                'host': host,
                'port': port or 22,
                'username': 'root',
                'password': password,
            },
        })
    except Exception as e:
        logger.error(f"API get console info error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/vps/<int:vps_id>/migration-progress', methods=['GET'])
@require_admin_api
def api_vps_migration_progress(vps_id):
    """Get the live progress of an in-flight VPS migration."""
    from hvm import get_db
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''SELECT * FROM vps_migrations
                           WHERE vps_id = ?
                           ORDER BY id DESC LIMIT 1''', (vps_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({'success': True, 'in_progress': False})
        m = dict(row)
        return jsonify({
            'success': True,
            'in_progress': m.get('status') in ('queued', 'running'),
            'migration': m,
        })
    except Exception as e:
        logger.error(f"API migration progress error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Nodes — extended ops
# ---------------------------------------------------------------------------

@api_bp.route('/nodes/<int:node_id>/test-connection', methods=['POST'])
@require_admin_api
def api_node_test_connection(node_id):
    """Smoke-test the agent connection for a node."""
    from hvm import get_db
    import requests as _rq
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM nodes WHERE id = ?', (node_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({'success': False, 'error': 'Node not found'}), 404
            node = dict(row)
        if node.get('is_local'):
            return jsonify({'success': True, 'reachable': True,
                            'message': 'Local node (always reachable)'})
        url = (node.get('url') or '').rstrip('/')
        if not url:
            return jsonify({'success': False, 'reachable': False,
                            'error': 'Node URL is not configured'}), 400
        try:
            r = _rq.get(f'{url}/api/health',
                        headers={'X-API-Key': node['api_key']},
                        timeout=8, verify=bool(node.get('verify_ssl', 1)))
            ok = r.status_code == 200
            body = r.json() if 'application/json' in r.headers.get('Content-Type', '') else r.text
        except _rq.exceptions.RequestException as e:
            return jsonify({'success': True, 'reachable': False,
                            'error': str(e)}), 200
        return jsonify({'success': True, 'reachable': ok,
                        'status_code': r.status_code, 'body': body})
    except Exception as e:
        logger.error(f"API node test error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/nodes/<int:node_id>/regenerate-key', methods=['POST'])
@require_admin_api
def api_node_regenerate_key(node_id):
    """Rotate the API key the panel uses to talk to a node-agent."""
    from hvm import get_db, generate_api_key, log_activity
    try:
        new_key = generate_api_key()
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('UPDATE nodes SET api_key = ? WHERE id = ?',
                        (new_key, node_id))
            if cur.rowcount == 0:
                return jsonify({'success': False, 'error': 'Node not found'}), 404
            conn.commit()
        log_activity(request.api_key_info['user_id'], 'api_regen_node_key',
                     'node', str(node_id))
        return jsonify({'success': True, 'api_key': new_key,
                        'note': 'Deploy this key to the node-agent on the node host.'})
    except Exception as e:
        logger.error(f"API regen node key error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/nodes/<int:node_id>/check', methods=['GET'])
@require_admin_api
def api_node_check(node_id):
    """Run a deeper health check on a node (uptime, resources, etc.)."""
    from hvm import get_db
    import requests as _rq
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM nodes WHERE id = ?', (node_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({'success': False, 'error': 'Node not found'}), 404
            node = dict(row)
        url = (node.get('url') or '').rstrip('/')
        if node.get('is_local') or not url:
            return jsonify({'success': True, 'is_local': bool(node.get('is_local')),
                            'note': 'Use /system/stats for local node info.'})
        try:
            r = _rq.get(f'{url}/api/system-info',
                        headers={'X-API-Key': node['api_key']},
                        timeout=10, verify=bool(node.get('verify_ssl', 1)))
            return jsonify({'success': r.status_code == 200,
                            'status_code': r.status_code,
                            'data': r.json() if r.status_code == 200 else None})
        except _rq.exceptions.RequestException as e:
            return jsonify({'success': False, 'error': str(e)}), 200
    except Exception as e:
        logger.error(f"API node check error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/nodes/<int:node_id>/circuit-breaker/reset', methods=['POST'])
@require_admin_api
def api_node_reset_circuit_breaker(node_id):
    """Clear a node's tripped circuit-breaker state."""
    try:
        from hvm import reset_node_circuit_breaker
        reset_node_circuit_breaker(node_id)
        return jsonify({'success': True, 'message': 'Circuit breaker reset'})
    except Exception as e:
        logger.error(f"API reset CB error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/nodes/<int:node_id>/failures/reset', methods=['POST'])
@require_admin_api
def api_node_reset_failures(node_id):
    """Clear a node's accumulated failure counter (same as the circuit-
    breaker reset since failures drive the breaker)."""
    try:
        from hvm import reset_node_circuit_breaker
        reset_node_circuit_breaker(node_id)
        return jsonify({'success': True, 'message': 'Failure counter cleared'})
    except Exception as e:
        logger.error(f"API reset failures error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/nodes/<int:node_id>/execute', methods=['POST'])
@require_admin_api
def api_node_execute(node_id):
    """Run an arbitrary shell command on a node host (admin only).

    Body: `{ "command": "uname -a", "timeout": 30 }`.
    Equivalent to the "execute on host" action — DOES NOT prepend `lxc`.
    """
    from hvm import get_db, run_sync, execute_host_shell
    data = request.get_json() or {}
    cmd = (data.get('command') or '').strip()
    if not cmd:
        return jsonify({'success': False, 'error': 'command is required'}), 400
    timeout = int(data.get('timeout') or 60)
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT id FROM nodes WHERE id = ?', (node_id,))
            if not cur.fetchone():
                return jsonify({'success': False, 'error': 'Node not found'}), 404
        result = run_sync(execute_host_shell(cmd, node_id=node_id, timeout=timeout))
        return jsonify({'success': True, 'output': result})
    except Exception as e:
        logger.error(f"API node execute error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ---------------------------------------------------------------------------
# System — vacuum / SMTP test / live stats / resource check
# ---------------------------------------------------------------------------

@api_bp.route('/system/vacuum', methods=['POST'])
@require_admin_api
def api_system_vacuum():
    """Run SQLite VACUUM to compact the database."""
    from hvm import get_db
    try:
        with get_db() as conn:
            conn.execute('VACUUM')
        return jsonify({'success': True, 'message': 'Database vacuumed'})
    except Exception as e:
        logger.error(f"API vacuum error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/system/test-smtp', methods=['POST'])
@require_admin_api
def api_system_test_smtp():
    """Send a test e-mail through the configured SMTP settings."""
    from hvm import send_email
    data = request.get_json() or {}
    to_addr = data.get('to') or data.get('email')
    if not to_addr:
        return jsonify({'success': False, 'error': 'to (email) is required'}), 400
    try:
        ok = send_email(
            to_addr,
            data.get('subject') or 'StrenoxCloud Panel — SMTP test',
            data.get('body') or 'This is a test message from the StrenoxCloud Panel API.',
        )
        return jsonify({'success': bool(ok), 'sent_to': to_addr})
    except Exception as e:
        logger.error(f"API smtp test error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/system/resource-check', methods=['POST'])
@require_admin_api
def api_resource_check():
    """Check whether a node has enough resources for a planned VPS.

    Body: `{ "node_id": int, "cpu": int, "ram_mb": int, "disk_gb": int }`."""
    from hvm import get_db
    data = request.get_json() or {}
    node_id = data.get('node_id')
    if not node_id:
        return jsonify({'success': False, 'error': 'node_id is required'}), 400
    try:
        need_cpu = int(data.get('cpu') or 0)
        need_ram = int(data.get('ram_mb') or 0)
        need_disk = int(data.get('disk_gb') or 0)
    except (TypeError, ValueError):
        return jsonify({'success': False,
                        'error': 'cpu/ram_mb/disk_gb must be integers'}), 400
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM nodes WHERE id = ?', (node_id,))
            node = cur.fetchone()
            if not node:
                return jsonify({'success': False, 'error': 'Node not found'}), 404
            cur.execute('SELECT * FROM vps WHERE node_id = ?', (node_id,))
            existing = [dict(r) for r in cur.fetchall()]
        node = dict(node)
        # Simplistic accounting based on config strings stored on each VPS.
        def _parse_int(s, default=0):
            try:
                import re as _re
                m = _re.search(r'(\d+)', str(s or ''))
                return int(m.group(1)) if m else default
            except Exception:
                return default
        used_cpu = sum(_parse_int(v.get('cpu'), 0) for v in existing)
        used_ram = sum(_parse_int(v.get('ram'), 0) for v in existing)
        used_disk = sum(_parse_int(v.get('disk'), 0) for v in existing)
        cap_cpu = int(node.get('max_cpu') or 0)
        cap_ram = int(node.get('max_ram') or 0)
        cap_disk = int(node.get('max_disk') or 0)
        ok = (
            (cap_cpu == 0 or used_cpu + need_cpu <= cap_cpu) and
            (cap_ram == 0 or used_ram + need_ram <= cap_ram) and
            (cap_disk == 0 or used_disk + need_disk <= cap_disk)
        )
        return jsonify({
            'success': True,
            'sufficient': ok,
            'used':      {'cpu': used_cpu, 'ram_mb': used_ram, 'disk_gb': used_disk},
            'capacity':  {'cpu': cap_cpu,  'ram_mb': cap_ram,  'disk_gb': cap_disk},
            'requested': {'cpu': need_cpu, 'ram_mb': need_ram, 'disk_gb': need_disk},
        })
    except Exception as e:
        logger.error(f"API resource check error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/system/live-stats', methods=['GET'])
@require_admin_api
def api_system_live_stats():
    """Real-time cross-node stats snapshot."""
    from hvm import get_db
    try:
        import psutil as _ps  # type: ignore
    except ImportError:
        _ps = None
    payload = {'success': True, 'timestamp': datetime.now().isoformat()}
    if _ps:
        try:
            payload['local'] = {
                'cpu_percent': _ps.cpu_percent(interval=0.2),
                'memory_percent': _ps.virtual_memory().percent,
                'disk_percent': _ps.disk_usage('/').percent if hasattr(_ps, 'disk_usage') else None,
                'uptime_seconds': int(datetime.now().timestamp() - _ps.boot_time()),
            }
        except Exception as e:
            payload['local_error'] = str(e)
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT COUNT(*) AS c FROM vps WHERE status = "running"')
            payload['running_vps'] = cur.fetchone()['c']
            cur.execute('SELECT COUNT(*) AS c FROM vps')
            payload['total_vps'] = cur.fetchone()['c']
            cur.execute('SELECT COUNT(*) AS c FROM nodes')
            payload['total_nodes'] = cur.fetchone()['c']
    except Exception:
        pass
    return jsonify(payload)


# ---------------------------------------------------------------------------
# Emergency operations
# ---------------------------------------------------------------------------

@api_bp.route('/emergency/stop-all', methods=['POST'])
@require_admin_api
def api_emergency_stop_all():
    """Stop every running VPS across all nodes. Use with care."""
    from hvm import get_db, run_sync, execute_lxc, log_activity
    stopped, failed = [], []
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT id, container_name, node_id FROM vps WHERE status = "running"')
            running = [dict(r) for r in cur.fetchall()]
        for v in running:
            try:
                run_sync(execute_lxc(v['container_name'], 'stop',
                                     node_id=v['node_id'], timeout=30,
                                     operation_type='stop'))
                stopped.append(v['id'])
            except Exception as e:
                failed.append({'id': v['id'], 'error': str(e)})
        with get_db() as conn:
            conn.execute('UPDATE vps SET status = "stopped" WHERE status = "running"')
            conn.commit()
        log_activity(request.api_key_info['user_id'], 'api_emergency_stop_all',
                     None, None, {'stopped': len(stopped), 'failed': len(failed)})
        return jsonify({'success': True,
                        'stopped': stopped, 'failed': failed,
                        'total': len(running)})
    except Exception as e:
        logger.error(f"API emergency stop-all error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/emergency/reboot-all', methods=['POST'])
@require_admin_api
def api_emergency_reboot_all():
    """Reboot every running VPS across all nodes."""
    from hvm import get_db, run_sync, execute_lxc, log_activity
    rebooted, failed = [], []
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT id, container_name, node_id FROM vps WHERE status = "running"')
            running = [dict(r) for r in cur.fetchall()]
        for v in running:
            try:
                run_sync(execute_lxc(v['container_name'], 'restart',
                                     node_id=v['node_id'], timeout=30,
                                     operation_type='restart'))
                rebooted.append(v['id'])
            except Exception as e:
                failed.append({'id': v['id'], 'error': str(e)})
        log_activity(request.api_key_info['user_id'], 'api_emergency_reboot_all',
                     None, None, {'rebooted': len(rebooted), 'failed': len(failed)})
        return jsonify({'success': True, 'rebooted': rebooted,
                        'failed': failed, 'total': len(running)})
    except Exception as e:
        logger.error(f"API emergency reboot-all error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/emergency/clear-suspensions', methods=['POST'])
@require_admin_api
def api_clear_suspensions():
    """Unsuspend every currently-suspended VPS."""
    from hvm import get_db, log_activity
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT COUNT(*) AS c FROM vps WHERE status = "suspended"')
            n = cur.fetchone()['c']
            cur.execute('UPDATE vps SET status = "stopped" WHERE status = "suspended"')
            conn.commit()
        log_activity(request.api_key_info['user_id'], 'api_clear_suspensions',
                     None, None, {'count': n})
        return jsonify({'success': True, 'unsuspended': n})
    except Exception as e:
        logger.error(f"API clear suspensions error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/emergency/reset-ports', methods=['POST'])
@require_admin_api
def api_reset_ports():
    """Wipe the port-allocations table (use only if it's gotten inconsistent)."""
    from hvm import get_db, log_activity
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('DELETE FROM ports')
            conn.commit()
        log_activity(request.api_key_info['user_id'], 'api_reset_ports')
        return jsonify({'success': True, 'message': 'Ports table cleared'})
    except Exception as e:
        logger.error(f"API reset ports error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ---------------------------------------------------------------------------
# API-key management — toggle active state
# ---------------------------------------------------------------------------

@api_bp.route('/api-keys/<int:key_id>/toggle', methods=['POST'])
@require_admin_api
def api_toggle_api_key(key_id):
    """Toggle (or set) an API key's active state.

    Body: `{ "is_active": true/false }` (optional — toggles if absent)."""
    from hvm import get_db, log_activity
    data = request.get_json() or {}
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT id, is_active FROM api_keys WHERE id = ?', (key_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({'success': False, 'error': 'API key not found'}), 404
            if 'is_active' in data:
                new_val = 1 if data['is_active'] else 0
            else:
                new_val = 0 if row['is_active'] else 1
            cur.execute('UPDATE api_keys SET is_active = ? WHERE id = ?',
                        (new_val, key_id))
            conn.commit()
        log_activity(request.api_key_info['user_id'], 'api_toggle_api_key',
                     'api_key', str(key_id), {'is_active': new_val})
        return jsonify({'success': True, 'is_active': bool(new_val)})
    except Exception as e:
        logger.error(f"API toggle key error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Backups — full CRUD
# ---------------------------------------------------------------------------

@api_bp.route('/backups/<filename>/restore', methods=['POST'])
@require_admin_api
def api_backup_restore(filename):
    """Restore the panel DB from a previous backup file."""
    import os as _os
    import shutil as _shutil
    from hvm import DATABASE_PATH, log_activity
    backup_dir = 'backups'
    try:
        src = _os.path.join(backup_dir, filename)
        if not _os.path.isfile(src):
            return jsonify({'success': False, 'error': 'Backup file not found'}), 404
        # Stash current DB before overwrite so we can recover on failure.
        snap = DATABASE_PATH + '.pre-restore'
        _shutil.copy2(DATABASE_PATH, snap)
        _shutil.copy2(src, DATABASE_PATH)
        log_activity(request.api_key_info['user_id'], 'api_backup_restore',
                     None, None, {'file': filename})
        return jsonify({'success': True,
                        'message': f'Database restored from {filename}',
                        'snapshot': snap})
    except Exception as e:
        logger.error(f"API restore error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/backups/<filename>', methods=['DELETE'])
@require_admin_api
def api_backup_delete(filename):
    """Delete a backup file."""
    import os as _os
    from hvm import log_activity
    backup_dir = 'backups'
    try:
        path = _os.path.join(backup_dir, filename)
        if not _os.path.isfile(path):
            return jsonify({'success': False, 'error': 'Backup file not found'}), 404
        _os.remove(path)
        log_activity(request.api_key_info['user_id'], 'api_backup_delete',
                     None, None, {'file': filename})
        return jsonify({'success': True, 'message': f'{filename} deleted'})
    except Exception as e:
        logger.error(f"API delete backup error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/backups/<filename>/download', methods=['GET'])
@require_admin_api
def api_backup_download(filename):
    """Stream a backup file as an attachment."""
    import os as _os
    from flask import send_file
    backup_dir = 'backups'
    path = _os.path.join(backup_dir, filename)
    if not _os.path.isfile(path):
        return jsonify({'success': False, 'error': 'Backup file not found'}), 404
    return send_file(path, as_attachment=True, download_name=filename)


# ---------------------------------------------------------------------------
# OS Icons
# ---------------------------------------------------------------------------

@api_bp.route('/os-icons', methods=['GET'])
@require_api_key
def api_list_os_icons():
    """List uploaded OS icons."""
    from hvm import get_db
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT os_name, icon_path, uploaded_at FROM os_icons ORDER BY os_name')
            rows = [dict(r) for r in cur.fetchall()]
        return jsonify({'success': True, 'icons': rows, 'count': len(rows)})
    except Exception as e:
        logger.error(f"API list icons error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/os-icons/<os_name>', methods=['GET'])
@require_api_key
def api_get_os_icon(os_name):
    """Get a single OS icon record."""
    from hvm import get_db
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM os_icons WHERE os_name = ?', (os_name,))
            row = cur.fetchone()
            if not row:
                return jsonify({'success': False, 'error': 'Icon not found'}), 404
        return jsonify({'success': True, 'icon': dict(row)})
    except Exception as e:
        logger.error(f"API get icon error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/os-icons/<os_name>', methods=['DELETE'])
@require_admin_api
def api_delete_os_icon(os_name):
    """Delete an OS icon (and the underlying file)."""
    import os as _os
    from hvm import get_db, log_activity
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT icon_path FROM os_icons WHERE os_name = ?', (os_name,))
            row = cur.fetchone()
            if not row:
                return jsonify({'success': False, 'error': 'Icon not found'}), 404
            try:
                _os.remove(row['icon_path'].lstrip('/'))
            except Exception:
                pass
            cur.execute('DELETE FROM os_icons WHERE os_name = ?', (os_name,))
            conn.commit()
        log_activity(request.api_key_info['user_id'], 'api_delete_os_icon',
                     'os_icon', os_name)
        return jsonify({'success': True, 'message': f'{os_name} icon deleted'})
    except Exception as e:
        logger.error(f"API delete icon error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Ports — admin extensions
# ---------------------------------------------------------------------------

@api_bp.route('/ports/custom', methods=['POST'])
@require_admin_api
def api_admin_create_custom_port():
    """Admin-create a custom port forward bypassing the user-quota check."""
    from hvm import get_db, log_activity
    data = request.get_json() or {}
    required = ('vps_id', 'public_port', 'private_port', 'protocol')
    missing = [r for r in required if data.get(r) in (None, '')]
    if missing:
        return jsonify({'success': False,
                        'error': f'Missing fields: {", ".join(missing)}'}), 400
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''INSERT INTO ports
                           (vps_id, public_port, private_port, protocol, created_at, created_by)
                           VALUES (?, ?, ?, ?, ?, ?)''',
                        (int(data['vps_id']), int(data['public_port']),
                         int(data['private_port']), data['protocol'],
                         datetime.now().isoformat(),
                         request.api_key_info['user_id']))
            port_id = cur.lastrowid
            conn.commit()
        log_activity(request.api_key_info['user_id'], 'api_admin_create_port',
                     'port', str(port_id), data)
        return jsonify({'success': True, 'port_id': port_id}), 201
    except Exception as e:
        logger.error(f"API admin create port error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Container stats (per-VPS metrics from the node-agent)
# ---------------------------------------------------------------------------

@api_bp.route('/vps/<int:vps_id>/container-stats', methods=['GET'])
@require_api_key
def api_vps_container_stats(vps_id):
    """Live container stats (CPU, RAM, disk, IO) from the node-agent."""
    from hvm import get_db, get_container_stats, run_sync
    info = request.api_key_info
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''SELECT id, container_name, node_id, user_id
                           FROM vps WHERE id = ?''', (vps_id,))
            vps = cur.fetchone()
            if not vps:
                return jsonify({'success': False, 'error': 'VPS not found'}), 404
            if not info.get('is_admin') and vps['user_id'] != info['user_id']:
                return jsonify({'success': False, 'error': 'Access denied'}), 403
        stats = run_sync(get_container_stats(vps['container_name'], vps['node_id']))
        return jsonify({'success': True, 'stats': stats or {}})
    except Exception as e:
        logger.error(f"API container stats error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Endpoint catalogue — discoverable from the API itself
# ---------------------------------------------------------------------------

@api_bp.route('/endpoints', methods=['GET'])
@require_api_key
def api_list_endpoints():
    """Return every endpoint registered on this API blueprint.

    Handy for auto-generated SDKs, scripts and the /admin/api page."""
    from flask import current_app
    rules = []
    for rule in current_app.url_map.iter_rules():
        if not rule.rule.startswith('/api/v1'):
            continue
        rules.append({
            'path': rule.rule,
            'methods': sorted(m for m in rule.methods
                              if m not in {'HEAD', 'OPTIONS'}),
            'endpoint': rule.endpoint,
        })
    rules.sort(key=lambda r: r['path'])
    return jsonify({'success': True, 'count': len(rules), 'endpoints': rules})



# ============================================================================

__all__ = ['api_bp']
