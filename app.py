#!/usr/bin/env python3
"""
Bepass Panic Control - Interface de Controle de Pânico
Sistema de abertura emergencial de catracas via BeBox
"""

import os
import hashlib
import json
import subprocess
import threading
import logging
import time
import socket
from datetime import datetime, timedelta
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configuração de logging
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('panic_control.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Use FLASK_SECRET_KEY from .env, or generate one if not available
app.secret_key = os.getenv('FLASK_SECRET_KEY', os.urandom(24).hex())
app.permanent_session_lifetime = timedelta(hours=2)

# === BLOQUEIO DE LOGIN ===
_login_attempts = {}  # {ip: {'count': N, 'blocked_until': datetime}}
LOGIN_MAX_ATTEMPTS = 3
LOGIN_BLOCK_MINUTES = 15

# === RATE LIMITING ===
_rate_limits = {}  # {ip: [timestamp, timestamp, ...]}
RATE_LIMIT_MAX = 10  # max acoes por minuto
RATE_LIMIT_WINDOW = 60  # segundos

# === USUARIOS ONLINE ===
_online_users = {}  # {username: {'ip': x, 'last_seen': datetime}}

# === DETECCAO DE PANICO LOCAL ===
_detected_local_panics = set()  # tracker para nao logar repetidamente

# Desabilitar logs do Werkzeu)
logging.getLogger('werkzeug').setLevel(logging.ERROR)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_login_users():
    """Carrega usuarios de login do dashboard"""
    users_path = os.path.join(BASE_DIR, 'login_users.json')
    if os.path.exists(users_path):
        with open(users_path, 'r') as f:
            return json.load(f).get('users', {})
    return {}


def load_panic_auth():
    """Carrega senhas de autorização dos usuários"""
    auth_path = os.path.join(BASE_DIR, 'panic_auth.json')
    if os.path.exists(auth_path):
        with open(auth_path, 'r') as f:
            return json.load(f)
    return {'authorized_users': {}}

AUDIT_LOG_PATH = os.path.join(BASE_DIR, 'logs/audit_actions.json')
IMMUTABLE_LOG_PATH = os.path.join(BASE_DIR, 'logs/immutable_audit.log')


def _check_login_blocked(ip):
    """Verifica se IP esta bloqueado por tentativas de login"""
    if ip in _login_attempts:
        info = _login_attempts[ip]
        if info.get('blocked_until') and datetime.now() < info['blocked_until']:
            remaining = (info['blocked_until'] - datetime.now()).seconds // 60 + 1
            return True, remaining
        if info.get('blocked_until') and datetime.now() >= info['blocked_until']:
            del _login_attempts[ip]
    return False, 0


def _record_login_attempt(ip, success):
    """Registra tentativa de login"""
    if success:
        _login_attempts.pop(ip, None)
        return
    if ip not in _login_attempts:
        _login_attempts[ip] = {'count': 0}
    _login_attempts[ip]['count'] += 1
    if _login_attempts[ip]['count'] >= LOGIN_MAX_ATTEMPTS:
        _login_attempts[ip]['blocked_until'] = datetime.now() + timedelta(minutes=LOGIN_BLOCK_MINUTES)


def _check_rate_limit(ip):
    """Verifica rate limit para acoes de panico"""
    now = time.time()
    if ip not in _rate_limits:
        _rate_limits[ip] = []
    # Limpar entradas antigas
    _rate_limits[ip] = [t for t in _rate_limits[ip] if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_limits[ip]) >= RATE_LIMIT_MAX:
        return False
    _rate_limits[ip].append(now)
    return True


def _update_online_user(username):
    """Atualiza registro de usuario online"""
    _online_users[username] = {
        'ip': _get_client_ip(),
        'last_seen': datetime.now().isoformat()
    }

def _get_client_ip():
    """Obtem IP real do cliente (suporta proxy)"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    if request.headers.get('X-Real-Ip'):
        return request.headers.get('X-Real-Ip')
    return request.remote_addr or 'unknown'

def _get_mac_from_ip(ip):
    """Tenta obter MAC address via ARP table"""
    try:
        result = subprocess.run(
            ['arp', '-n', ip],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if ip in line:
                    parts = line.split()
                    for part in parts:
                        if ':' in part and len(part) == 17:
                            return part
                        if '-' in part and len(part) == 17:
                            return part
    except Exception:
        pass
    return 'unknown'

def _get_hostname_from_ip(ip):
    """Tenta resolver hostname via reverse DNS"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        return 'unknown'


def _get_user_agent():
    """Obtem User-Agent do request"""
    try:
        return request.headers.get('User-Agent', 'unknown')
    except Exception:
        return 'unknown'


def _get_session_duration():
    """Calcula tempo de sessao do usuario"""
    try:
        login_time = session.get('login_time')
        if login_time:
            delta = datetime.now() - datetime.fromisoformat(login_time)
            minutes = int(delta.total_seconds() // 60)
            if minutes < 60:
                return f"{minutes}min"
            return f"{minutes // 60}h{minutes % 60}min"
    except Exception:
        pass
    return 'unknown'


def log_audit(username, action, details, status, result, origin='DASHBOARD'):
    """Registra ação de auditoria completa - append-only, nao deletavel"""
    os.makedirs('logs', exist_ok=True)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    client_ip = _get_client_ip()
    client_mac = _get_mac_from_ip(client_ip)
    user_agent = _get_user_agent()
    hostname = _get_hostname_from_ip(client_ip)
    session_duration = _get_session_duration()

    # Log texto (append-only)
    log_line = f"{timestamp} | USER: {username} | IP: {client_ip} | MAC: {client_mac} | HOST: {hostname} | UA: {user_agent} | SESSION: {session_duration} | ORIGIN: {origin} | ACTION: {action} | DETAILS: {details} | STATUS: {status} | RESULT: {result}"
    with open('logs/audit.log', 'a') as f:
        f.write(log_line + '\n')

    # Log JSON (append-only)
    audit_entry = {
        'timestamp': timestamp,
        'username': username,
        'client_ip': client_ip,
        'client_mac': client_mac,
        'hostname': hostname,
        'user_agent': user_agent,
        'session_duration': session_duration,
        'origin': origin,
        'action': action,
        'details': details,
        'status': status,
        'result': result
    }
    try:
        existing = []
        if os.path.exists(AUDIT_LOG_PATH):
            with open(AUDIT_LOG_PATH, 'r') as f:
                existing = json.load(f)
        existing.append(audit_entry)
        with open(AUDIT_LOG_PATH, 'w') as f:
            json.dump(existing, f, indent=2)
    except Exception as e:
        logger.error(f"Erro ao salvar audit JSON: {e}")

    # Log imutavel separado (append-only, so root pode alterar)
    try:
        with open(IMMUTABLE_LOG_PATH, 'a') as f:
            f.write(log_line + '\n')
    except Exception:
        pass

    logger.warning(log_line)


def verify_panic_password(username, password):
    """Verifica se a senha de autorização está correta"""
    auth = load_panic_auth()
    user_password = auth.get('authorized_users', {}).get(username)
    return user_password and user_password == password

def log_action_history(username, action, details):
    """Registra no histórico de ações do usuário"""
    os.makedirs('data', exist_ok=True)
    history_path = os.path.join(BASE_DIR, 'data/action_history.json')

    try:
        if os.path.exists(history_path):
            with open(history_path, 'r') as f:
                data = json.load(f)
        else:
            data = {'actions': []}

        action_entry = {
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'action': action,
            'details': details
        }

        data['actions'].append(action_entry)
        data['actions'] = data['actions'][-100:]

        with open(history_path, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.error(f"Erro ao registrar histórico: {str(e)}")

def get_user_action_history(username, limit=20):
    """Retorna histórico de ações do usuário"""
    history_path = os.path.join(BASE_DIR, 'data/action_history.json')

    try:
        if os.path.exists(history_path):
            with open(history_path, 'r') as f:
                data = json.load(f)

            user_actions = [a for a in data.get('actions', []) if a['username'] == username]
            return user_actions[-limit:]
        return []
    except Exception:
        return []

def check_device_health(ip, bebox_id):
    """Verifica saúde de um dispositivo"""
    config = load_config()
    ssh_user = config.get('ssh_user', 'bepass')
    ssh_password = config.get('ssh_password', '')

    try:
        result = subprocess.run(
            ['sshpass', '-p', ssh_password, 'ssh', '-o', 'StrictHostKeyChecking=no',
             '-o', 'ConnectTimeout=5', f'{ssh_user}@{ip}', 'echo ok'],
            capture_output=True,
            text=True,
            timeout=10
        )

        return {
            'bebox': bebox_id,
            'ip': ip,
            'status': 'online' if result.returncode == 0 else 'offline',
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        return {
            'bebox': bebox_id,
            'ip': ip,
            'status': 'unreachable',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }


def load_config():
    """Carrega configuração do .env (variáveis de ambiente)"""
    return {
        'panic_hash': os.getenv('PANIC_HASH', ''),
        'ssh_user': os.getenv('SSH_USER', 'bepass'),
        'ssh_port': int(os.getenv('SSH_PORT', 22)),
        'ssh_password': os.getenv('SSH_PASSWORD', ''),
        'ssh_key_path': os.getenv('SSH_KEY_PATH', '~/.ssh/id_rsa'),
        'bebox_api_port': int(os.getenv('BEBOX_API_PORT', 3005)),
        'app_port': int(os.getenv('APP_PORT', 3456)),
        'login': {
            'username': os.getenv('LOGIN_USERNAME', ''),
            'password': os.getenv('LOGIN_PASSWORD', '')
        }
    }

def load_beboxes():
    """Carrega lista de dispositivos BeBox"""
    beboxes_path = os.path.join(BASE_DIR, 'beboxes.json')
    with open(beboxes_path, 'r') as f:
        return json.load(f)

def get_panic_hash():
    """Obtém o hash de pânico do .env"""
    return os.getenv('PANIC_HASH', '')

def save_panic_hash(new_hash):
    """Atualiza o hash de pânico"""
    logger.info(f"Hash de pânico atualizado: {new_hash[:8]}...")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            log_audit('anonymous', 'UNAUTHORIZED_ACCESS', f"Tentativa de acesso: {request.path}", 'BLOCKED', 'Sem sessao')
            return redirect(url_for('login'))
        # Atualiza usuario online
        _update_online_user(session.get('username', 'unknown'))
        return f(*args, **kwargs)
    return decorated_function

command_results = {}

# Panic status cache
_panic_status_cache = {
    'data': None,
    'timestamp': 0
}
_panic_status_lock = threading.Lock()
PANIC_CACHE_TTL = 60  # seconds

SHARED_LOGS_PATH = os.path.join(BASE_DIR, 'data/shared_logs.json')
max_logs = 100
is_operation_active = False

def _load_shared_logs():
    """Carrega logs do disco"""
    try:
        if os.path.exists(SHARED_LOGS_PATH):
            with open(SHARED_LOGS_PATH, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return []

def _save_shared_logs(logs):
    """Salva logs no disco"""
    try:
        os.makedirs(os.path.dirname(SHARED_LOGS_PATH), exist_ok=True)
        with open(SHARED_LOGS_PATH, 'w') as f:
            json.dump(logs, f)
    except Exception as e:
        logger.error(f"Erro ao salvar logs: {e}")

shared_logs = _load_shared_logs()

def add_shared_log(message, log_type='info'):
    """Adiciona log ao compartilhado e persiste em disco"""
    global shared_logs
    timestamp = datetime.now().strftime('%H:%M:%S')
    date_str = datetime.now().strftime('%d/%m')
    log_entry = {
        'time': timestamp,
        'date': date_str,
        'message': message,
        'type': log_type
    }
    shared_logs.insert(0, log_entry)
    # Manter apenas últimos 100 logs
    if len(shared_logs) > max_logs:
        shared_logs = shared_logs[:max_logs]
    _save_shared_logs(shared_logs)
    logger.info(f"[{log_type.upper()}] {message}")

def execute_panic_command(ip, bebox_id, panic_hash, result_key):
    """Executa o comando de pânico em uma BeBox via SSH"""
    config = load_config()
    ssh_user = config.get('ssh_user', 'bepass')
    api_port = config.get('bebox_api_port', 3005)
    
    # Comando curl para enviar ao BeBox
    curl_command = f'''curl --max-time 5 --location 'localhost:{api_port}/message' --header 'Content-Type: application/json' --data '{{"message": {{"access": "allowed","hash": "{panic_hash}|barcode","message": "Liberado"}}}}' '''

    # Comando SSH completo
    ssh_password = config.get('ssh_password', '')
    ssh_command = [
       'sshpass',
      '-p', ssh_password,
      'ssh',
      '-o', 'StrictHostKeyChecking=no',
      '-o', 'ConnectTimeout=5',
      f'{ssh_user}@{ip}',
      curl_command
  ]
    
    try:
        result = subprocess.run(
            ssh_command,
            capture_output=True,
            text=True,
            timeout=15
        )
        
        success = result.returncode == 0
        command_results[result_key] = {
            'bebox': bebox_id,
            'ip': ip,
            'success': success,
            'output': result.stdout if success else result.stderr,
            'timestamp': datetime.now().isoformat()
        }
        
        if success:
            logger.info(f"✓ Pânico enviado com sucesso para BeBox {bebox_id} ({ip})")
        else:
            logger.error(f"✗ Falha no BeBox {bebox_id} ({ip}): {result.stderr}")
            
    except subprocess.TimeoutExpired:
        command_results[result_key] = {
            'bebox': bebox_id,
            'ip': ip,
            'success': False,
            'output': 'Timeout - dispositivo não respondeu',
            'timestamp': datetime.now().isoformat()
        }
        logger.error(f"✗ Timeout no BeBox {bebox_id} ({ip})")
    except Exception as e:
        command_results[result_key] = {
            'bebox': bebox_id,
            'ip': ip,
            'success': False,
            'output': str(e),
            'timestamp': datetime.now().isoformat()
        }
        logger.error(f"✗ Erro no BeBox {bebox_id} ({ip}): {str(e)}")

@app.route('/')
def index():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        client_ip = _get_client_ip()

        # Verificar bloqueio
        blocked, remaining = _check_login_blocked(client_ip)
        if blocked:
            log_audit('blocked', 'LOGIN_BLOCKED', f"IP bloqueado: {client_ip}", 'BLOCKED', f"Aguardar {remaining} min")
            return render_template('login.html', error=f'IP bloqueado. Aguarde {remaining} minuto(s)')

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Carregar usuarios do login_users.json
        login_users = load_login_users()
        user_data = login_users.get(username)

        if user_data and user_data['password'] == password:
            _record_login_attempt(client_ip, True)
            session.permanent = True
            session['logged_in'] = True
            session['username'] = username
            session['user_name'] = user_data.get('name', username)
            session['user_role'] = user_data.get('role', 'operator')
            session['login_time'] = datetime.now().isoformat()
            log_audit(username, 'LOGIN', f"Login no dashboard ({user_data.get('name', '')} / {user_data.get('role', '')})", 'SUCCESS', 'Autenticado')
            return redirect(url_for('dashboard'))
        else:
            _record_login_attempt(client_ip, False)
            attempts_left = LOGIN_MAX_ATTEMPTS - _login_attempts.get(client_ip, {}).get('count', 0)
            log_audit(username or 'unknown', 'LOGIN_FAILED', f"Tentativa de login ({attempts_left} restantes)", 'FAILED', 'Credenciais invalidas')
            if attempts_left <= 0:
                return render_template('login.html', error=f'IP bloqueado por {LOGIN_BLOCK_MINUTES} minutos')
            return render_template('login.html', error=f'Credenciais inválidas ({attempts_left} tentativa(s) restante(s))')

    return render_template('login.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    log_audit(username, 'LOGOUT', 'Saiu do dashboard', 'SUCCESS', 'Deslogado')
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/audit-logs')
@login_required
def get_audit_logs():
    """Retorna logs de auditoria - somente leitura, nao deletavel"""
    try:
        if os.path.exists(AUDIT_LOG_PATH):
            with open(AUDIT_LOG_PATH, 'r') as f:
                logs = json.load(f)
            # Retorna os ultimos 200, mais recentes primeiro
            return jsonify({'logs': list(reversed(logs[-200:]))})
    except Exception as e:
        logger.error(f"Erro ao ler audit logs: {e}")
    return jsonify({'logs': []})


@app.route('/api/audit-logs/export/csv')
@login_required
def export_audit_csv():
    """Exporta logs de auditoria em CSV"""
    import io
    import csv

    username = session.get('username', 'unknown')
    log_audit(username, 'AUDIT_EXPORT', 'Exportou auditoria em CSV', 'SUCCESS', 'Download CSV')

    try:
        logs = []
        if os.path.exists(AUDIT_LOG_PATH):
            with open(AUDIT_LOG_PATH, 'r') as f:
                logs = json.load(f)

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Data/Hora', 'Usuario', 'IP', 'MAC', 'Hostname', 'User-Agent', 'Sessao', 'Origem', 'Acao', 'Detalhes', 'Status', 'Resultado'])
        for log in logs:
            writer.writerow([
                log.get('timestamp', ''),
                log.get('username', ''),
                log.get('client_ip', ''),
                log.get('client_mac', ''),
                log.get('hostname', ''),
                log.get('user_agent', ''),
                log.get('session_duration', ''),
                log.get('origin', 'DASHBOARD'),
                log.get('action', ''),
                log.get('details', ''),
                log.get('status', ''),
                log.get('result', '')
            ])

        from flask import Response
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=auditoria_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
        )
    except Exception as e:
        logger.error(f"Erro ao exportar CSV: {e}")
        return jsonify({'error': 'Erro ao exportar'}), 500


# Dashboard principal
@app.route('/dashboard')
@login_required
def dashboard():
    username = session.get('username', 'unknown')
    log_audit(username, 'DASHBOARD_ACCESS', 'Acessou o dashboard', 'SUCCESS', 'Pagina carregada')

    beboxes = load_beboxes()
    panic_hash = get_panic_hash()

    total_devices = 0
    setores_info = []
    for setor_id, setor_data in beboxes['setores'].items():
        count = len(setor_data['dispositivos'])
        total_devices += count
        setores_info.append({
            'id': setor_id,
            'nome': setor_data['nome'],
            'count': count,
            'dispositivos': setor_data['dispositivos']
        })

    def sort_key(s):
        sid = s['id']
        if sid == 'MEMORIAL':
            return (2, 'MEMORIAL')
        elif sid.isdigit():
            return (0, int(sid))
        else:
            return (1, sid)
    
    setores_info.sort(key=sort_key)
    
    return render_template('dashboard.html', 
                          setores=setores_info,
                          total_devices=total_devices,
                          panic_hash=panic_hash,
                          total_setores=len(setores_info))

@app.route('/api/setores')
@login_required
def api_setores():
    beboxes = load_beboxes()
    return jsonify(beboxes['setores'])

@app.route('/api/hash', methods=['GET', 'POST'])
@login_required
def api_hash():
    if request.method == 'POST':
        data = request.get_json()
        new_hash = data.get('hash', '').strip()
        if new_hash:
            save_panic_hash(new_hash)
            return jsonify({'success': True, 'hash': new_hash})
        return jsonify({'success': False, 'error': 'Hash vazio'})
    
    return jsonify({'hash': get_panic_hash()})

@app.route('/api/panic/verify-password', methods=['POST'])
@login_required
def verify_panic_pwd():
    """Verifica senha de autorizacao para acoes de panico"""
    data = request.get_json()
    password = data.get('password', '')
    username = session.get('username', '')

    if verify_panic_password(username, password):
        session['panic_authorized'] = True
        session['panic_auth_time'] = datetime.now().isoformat()
        log_audit(username, 'PANIC_AUTH', 'Senha de panico verificada', 'SUCCESS', 'Autorizado')
        return jsonify({'success': True})
    else:
        log_audit(username, 'PANIC_AUTH_FAILED', 'Senha de panico incorreta', 'FAILED', 'Nao autorizado')
        return jsonify({'success': False, 'error': 'Senha incorreta'})


@app.route('/api/online-users')
@login_required
def get_online_users():
    """Retorna usuarios online (ativos nos ultimos 10 min)"""
    cutoff = (datetime.now() - timedelta(minutes=10)).isoformat()
    online = []
    for user, info in _online_users.items():
        if info['last_seen'] > cutoff:
            online.append({'username': user, 'ip': info['ip'], 'last_seen': info['last_seen']})
    return jsonify({'users': online, 'count': len(online)})


@app.route('/api/panic/device', methods=['POST'])
@login_required
def panic_device():
    """Envia comando de pânico para um único dispositivo"""
    global is_operation_active

    # Rate limit
    if not _check_rate_limit(_get_client_ip()):
        return jsonify({'success': False, 'error': 'Muitas acoes em pouco tempo. Aguarde.'})

    # Verificar senha de panico
    if not session.get('panic_authorized'):
        return jsonify({'success': False, 'error': 'NEED_AUTH', 'message': 'Senha de panico necessaria'})

    data = request.get_json()
    ip = data.get('ip')
    bebox_id = data.get('bebox_id')

    if not ip:
        return jsonify({'success': False, 'error': 'IP não fornecido'})

    is_operation_active = True
    add_shared_log(f"⏳ Enviando pânico para BeBox {bebox_id} ({ip})...", 'info')

    panic_hash = get_panic_hash()
    result_key = f"{ip}_{datetime.now().timestamp()}"

    # Executar em thread separada
    thread = threading.Thread(
        target=execute_panic_command,
        args=(ip, bebox_id, panic_hash, result_key)
    )
    thread.start()
    thread.join(timeout=20)

    result = command_results.get(result_key, {
        'success': False,
        'output': 'Comando não completado',
        'ip': ip,
        'bebox': bebox_id
    })

    # Log compartilhado
    username = session.get('username', 'unknown')
    if result.get('success'):
        add_shared_log(f"✓ BeBox {bebox_id} (IP: {ip}) - LIBERADO", 'success')
        log_audit(username, 'PANIC_DEVICE', f"BeBox {bebox_id} (IP: {ip})", 'SUCCESS', 'Panico ativado')
    else:
        add_shared_log(f"✗ BeBox {bebox_id} (IP: {ip}) - ERRO: {result.get('output', 'Erro desconhecido')}", 'error')
        log_audit(username, 'PANIC_DEVICE', f"BeBox {bebox_id} (IP: {ip})", 'FAILED', result.get('output', 'Erro'))

    is_operation_active = False
    return jsonify(result)

@app.route('/api/panic/setor', methods=['POST'])
@login_required
def panic_setor():
    """Envia comando de pânico para todos os dispositivos de um setor"""
    global is_operation_active

    if not _check_rate_limit(_get_client_ip()):
        return jsonify({'success': False, 'error': 'Muitas acoes em pouco tempo. Aguarde.'})

    if not session.get('panic_authorized'):
        return jsonify({'success': False, 'error': 'NEED_AUTH', 'message': 'Senha de panico necessaria'})

    data = request.get_json()
    setor_id = data.get('setor_id')

    if not setor_id:
        return jsonify({'success': False, 'error': 'Setor não fornecido'})

    beboxes = load_beboxes()
    setor = beboxes['setores'].get(setor_id)

    if not setor:
        return jsonify({'success': False, 'error': 'Setor não encontrado'})

    is_operation_active = True
    setor_name = setor.get('nome', setor_id)
    add_shared_log(f"⏳ Iniciando pânico no setor {setor_name}...", 'info')

    panic_hash = get_panic_hash()
    threads = []
    result_keys = []
    failure_details = []

    for device in setor['dispositivos']:
        result_key = f"{device['ip_rasp']}_{datetime.now().timestamp()}"
        result_keys.append((result_key, device))

        thread = threading.Thread(
            target=execute_panic_command,
            args=(device['ip_rasp'], device['bebox'], panic_hash, result_key)
        )
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join(timeout=30)

    results = []
    success_count = 0
    for key, device in result_keys:
        result = command_results.get(key, {'success': False, 'output': 'Sem resposta'})
        result['ip'] = device['ip_rasp']
        result['bebox'] = device['bebox']
        results.append(result)
        if result.get('success'):
            success_count += 1
            add_shared_log(f"✓ BeBox {device['bebox']} (IP: {device['ip_rasp']}) - LIBERADO", 'success')
        else:
            failure_details.append(f"BeBox {device['bebox']} ({device['ip_rasp']})")
            add_shared_log(f"✗ BeBox {device['bebox']} (IP: {device['ip_rasp']}) - ERRO: {result.get('output', 'Erro desconhecido')}", 'error')

    if failure_details:
        add_shared_log(f"📋 FALHAS em {len(failure_details)} device(s): {', '.join(failure_details)}", 'error')

    add_shared_log(f"📊 {setor_name} - Resumo: {success_count} ✓ sucesso, {len(result_keys) - success_count} ✗ falhas", 'success' if len(result_keys) - success_count == 0 else 'error')

    username = session.get('username', 'unknown')
    failed_count = len(result_keys) - success_count
    log_audit(username, 'PANIC_SETOR', f"Setor {setor_name}: {success_count} OK, {failed_count} falhas", 'SUCCESS' if success_count > 0 else 'FAILED', f"{success_count}/{len(result_keys)}")

    is_operation_active = False
    return jsonify({
        'success': success_count > 0,
        'total': len(result_keys),
        'success_count': success_count,
        'failed_count': len(result_keys) - success_count,
        'results': results
    })

@app.route('/api/panic/all', methods=['POST'])
@login_required
def panic_all():
    """Envia comando de pânico para TODOS os dispositivos do estádio"""
    global is_operation_active

    if not _check_rate_limit(_get_client_ip()):
        return jsonify({'success': False, 'error': 'Muitas acoes em pouco tempo. Aguarde.'})

    if not session.get('panic_authorized'):
        return jsonify({'success': False, 'error': 'NEED_AUTH', 'message': 'Senha de panico necessaria'})

    # Dupla confirmacao: exige que o frontend envie o campo 'confirm_text' = 'CONFIRMAR'
    data = request.get_json() or {}
    if data.get('confirm_text') != 'CONFIRMAR':
        return jsonify({'success': False, 'error': 'NEED_CONFIRM', 'message': 'Digite CONFIRMAR para prosseguir'})

    beboxes = load_beboxes()
    panic_hash = get_panic_hash()
    threads = []
    result_keys = []
    failure_details = []

    is_operation_active = True
    add_shared_log("⏳ ⚠️ INICIANDO PÂNICO TOTAL DO ESTÁDIO...", 'info')
    logger.warning("⚠️ INICIANDO PÂNICO TOTAL DO ESTÁDIO ⚠️")

    for setor_id, setor in beboxes['setores'].items():
        for device in setor['dispositivos']:
            result_key = f"{device['ip_rasp']}_{datetime.now().timestamp()}"
            result_keys.append((result_key, setor_id, device))

            thread = threading.Thread(
                target=execute_panic_command,
                args=(device['ip_rasp'], device['bebox'], panic_hash, result_key)
            )
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join(timeout=60)

    results_by_setor = {}
    total_success = 0
    total_failed = 0

    for key, setor_id, device in result_keys:
        result = command_results.get(key, {'success': False, 'output': 'Sem resposta'})
        result['ip'] = device['ip_rasp']
        result['bebox'] = device['bebox']

        if setor_id not in results_by_setor:
            results_by_setor[setor_id] = {'success': 0, 'failed': 0, 'results': []}

        if result.get('success'):
            results_by_setor[setor_id]['success'] += 1
            total_success += 1
            add_shared_log(f"✓ BeBox {device['bebox']} (IP: {device['ip_rasp']}) - LIBERADO", 'success')
        else:
            results_by_setor[setor_id]['failed'] += 1
            total_failed += 1
            failure_details.append(f"BeBox {device['bebox']} ({device['ip_rasp']})")
            add_shared_log(f"✗ BeBox {device['bebox']} (IP: {device['ip_rasp']}) - ERRO: {result.get('output', 'Erro desconhecido')}", 'error')

        results_by_setor[setor_id]['results'].append(result)

    if failure_details:
        add_shared_log(f"📋 FALHAS em {len(failure_details)} device(s): {', '.join(failure_details)}", 'error')

    add_shared_log(f"📊 PÂNICO TOTAL - Resumo: {total_success} ✓ sucesso, {total_failed} ✗ falhas em {len(result_keys)} dispositivos", 'success' if total_failed == 0 else 'error')

    logger.info(f"Pânico total concluído: {total_success} sucesso, {total_failed} falhas")

    username = session.get('username', 'unknown')
    log_audit(username, 'PANIC_ALL', f"Panico total: {total_success} OK, {total_failed} falhas em {len(result_keys)} devices", 'SUCCESS' if total_success > 0 else 'FAILED', f"{total_success}/{len(result_keys)}")

    is_operation_active = False

    return jsonify({
        'success': total_success > 0,
        'total': len(result_keys),
        'success_count': total_success,
        'failed_count': total_failed,
        'results_by_setor': results_by_setor
    })

@app.route('/api/logs', methods=['GET'])
@login_required
def get_logs():
    """Retorna logs compartilhados para sincronização em tempo real"""
    return jsonify({
        'logs': shared_logs,
        'is_active': is_operation_active
    })

@app.route('/api/test/connection', methods=['POST'])
@login_required
def test_connection():
    """Testa a conexão SSH com um dispositivo"""
    data = request.get_json()
    ip = data.get('ip')
    
    if not ip:
        return jsonify({'success': False, 'error': 'IP não fornecido'})
    
    config = load_config()
    ssh_user = config.get('ssh_user', 'bepass')
    
    try:
        result = subprocess.run(                                                               
      ['sshpass', '-p', ssh_password, 'ssh', '-o', 'StrictHostKeyChecking=no',           
       '-o', 'ConnectTimeout=5', f'{ssh_user}@{ip}', 'echo ok'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        return jsonify({
            'success': result.returncode == 0,
            'output': result.stdout.strip() if result.returncode == 0 else result.stderr
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/health/devices', methods=['GET'])
@login_required
def health_devices():
    """Verifica saúde de todos os dispositivos"""
    beboxes = load_beboxes()
    results = []

    for setor_id, setor in beboxes['setores'].items():
        for device in setor['dispositivos']:
            health = check_device_health(device['ip_rasp'], device['bebox'])
            results.append(health)

    return jsonify({
        'devices': results,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/action-history', methods=['GET'])
@login_required
def action_history():
    """Retorna histórico de ações do usuário"""
    username = session.get('username')
    history = get_user_action_history(username, limit=20)
    return jsonify({'actions': history})



def check_panic_file(ip, bebox_id, ssh_user, ssh_password):
    """Verifica via SSH se o arquivo panico.txt existe no dispositivo"""
    try:
        result = subprocess.run(
            ['sshpass', '-p', ssh_password, 'ssh', '-o', 'StrictHostKeyChecking=no',
             '-o', 'ConnectTimeout=5', f'{ssh_user}@{ip}',
             'test -f /var/www/html/panico.txt && cat /var/www/html/panico.txt'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            content = result.stdout.strip()
            return {
                'bebox': bebox_id,
                'ip': ip,
                'panic_active': True,
                'panic_hash': content if content else None
            }
        return {
            'bebox': bebox_id,
            'ip': ip,
            'panic_active': False,
            'panic_hash': None
        }
    except Exception:
        return {
            'bebox': bebox_id,
            'ip': ip,
            'panic_active': False,
            'panic_hash': None,
            'error': True
        }


def _fetch_panic_status():
    """Busca status de panico de todos os dispositivos em paralelo"""
    config = load_config()
    beboxes = load_beboxes()
    ssh_user = config.get('ssh_user', 'bepass')
    ssh_password = config.get('ssh_password', '')
    system_hash = get_panic_hash()

    # Load action history to check if panic was triggered by system
    history_path = os.path.join(BASE_DIR, 'data/action_history.json')
    system_triggered_ips = set()
    try:
        if os.path.exists(history_path):
            with open(history_path, 'r') as f:
                data = json.load(f)
            for action in data.get('actions', []):
                details = action.get('details', '')
                if 'panic' in action.get('action', '').lower() or 'liberado' in details.lower():
                    # Extract IP from details if present
                    if 'IP:' in details:
                        ip_part = details.split('IP:')[-1].strip().rstrip(')')
                        system_triggered_ips.add(ip_part)
    except Exception:
        pass

    devices = []
    for setor_id, setor in beboxes['setores'].items():
        for device in setor['dispositivos']:
            devices.append(device)

    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(check_panic_file, d['ip_rasp'], d['bebox'], ssh_user, ssh_password): d
            for d in devices
        }
        for future in as_completed(futures):
            result = future.result()
            # Determine if triggered by system
            if result['panic_active'] and result.get('panic_hash'):
                result['triggered_by_system'] = (result['panic_hash'] == system_hash)
            else:
                result['triggered_by_system'] = False

            # Detectar panico local (QR code na catraca, sem dashboard)
            if result['panic_active'] and not result['triggered_by_system']:
                result['origin'] = 'LOCAL QRCODE'
                bebox_key = f"local_panic_{result['bebox']}"
                if bebox_key not in _detected_local_panics:
                    _detected_local_panics.add(bebox_key)
                    log_audit('CATRACA', 'PANIC_LOCAL_QRCODE',
                              f"BeBox {result['bebox']} (IP: {result['ip']}) - Panico ativado localmente via QR Code",
                              'DETECTED', f"Hash: {result.get('panic_hash', 'N/A')[:12]}",
                              origin='LOCAL QRCODE')
            elif result['panic_active'] and result['triggered_by_system']:
                result['origin'] = 'DASHBOARD'
            else:
                result['origin'] = '-'
                # Se nao esta em panico, limpar tracker
                bebox_key = f"local_panic_{result['bebox']}"
                _detected_local_panics.discard(bebox_key)

            results.append(result)

    return {
        'devices': results,
        'timestamp': datetime.now().isoformat(),
        'system_hash': system_hash[:12] if system_hash else None
    }


@app.route('/api/panic/status')
@login_required
def panic_status():
    """Retorna status de panico de todos os dispositivos (com cache de 60s)"""
    global _panic_status_cache
    now = time.time()

    with _panic_status_lock:
        if _panic_status_cache['data'] and (now - _panic_status_cache['timestamp']) < PANIC_CACHE_TTL:
            return jsonify(_panic_status_cache['data'])

    # Fetch fresh data outside lock
    data = _fetch_panic_status()

    with _panic_status_lock:
        _panic_status_cache['data'] = data
        _panic_status_cache['timestamp'] = now

    return jsonify(data)


@app.route('/api/panic/status/quick')
@login_required
def panic_status_quick():
    """Retorna ultimo resultado em cache sem fazer SSH"""
    with _panic_status_lock:
        if _panic_status_cache['data']:
            return jsonify(_panic_status_cache['data'])
    return jsonify({'devices': [], 'timestamp': None})


def remove_panic_file(ip, bebox_id, ssh_user, ssh_password):
    """Remove o arquivo panico.txt de um dispositivo via SSH"""
    try:
        result = subprocess.run(
            ['sshpass', '-p', ssh_password, 'ssh', '-o', 'StrictHostKeyChecking=no',
             '-o', 'ConnectTimeout=5', f'{ssh_user}@{ip}',
             'rm -f /var/www/html/panico.txt'],
            capture_output=True,
            text=True,
            timeout=10
        )
        return {
            'bebox': bebox_id,
            'ip': ip,
            'success': result.returncode == 0,
            'output': result.stdout.strip() if result.returncode == 0 else result.stderr.strip()
        }
    except Exception as e:
        return {
            'bebox': bebox_id,
            'ip': ip,
            'success': False,
            'output': str(e)
        }


@app.route('/api/panic/disable/device', methods=['POST'])
@login_required
def panic_disable_device():
    """Remove panico.txt de um unico dispositivo"""
    global _panic_status_cache

    if not _check_rate_limit(_get_client_ip()):
        return jsonify({'success': False, 'error': 'Muitas acoes em pouco tempo. Aguarde.'})

    if not session.get('panic_authorized'):
        return jsonify({'success': False, 'error': 'NEED_AUTH', 'message': 'Senha de panico necessaria'})

    data = request.get_json()
    ip = data.get('ip')
    bebox_id = data.get('bebox_id')

    if not ip:
        return jsonify({'success': False, 'error': 'IP nao fornecido'})

    config = load_config()
    ssh_user = config.get('ssh_user', 'bepass')
    ssh_password = config.get('ssh_password', '')

    add_shared_log(f"Desabilitando panico no BeBox {bebox_id} ({ip})...", 'info')

    result = remove_panic_file(ip, bebox_id, ssh_user, ssh_password)

    if result['success']:
        add_shared_log(f"BeBox {bebox_id} ({ip}) - panico removido", 'success')
    else:
        add_shared_log(f"BeBox {bebox_id} ({ip}) - erro ao remover: {result.get('output', '')}", 'error')

    # Invalidate cache
    with _panic_status_lock:
        _panic_status_cache['data'] = None
        _panic_status_cache['timestamp'] = 0

    username = session.get('username', 'unknown')
    log_action_history(username, 'disable_panic_device', f"Desabilitou panico BeBox {bebox_id} (IP: {ip})")
    log_audit(username, 'DISABLE_PANIC_DEVICE', f"BeBox {bebox_id} (IP: {ip})", 'SUCCESS' if result['success'] else 'FAILED', result.get('output', ''))

    return jsonify(result)


@app.route('/api/panic/disable/setor', methods=['POST'])
@login_required
def panic_disable_setor():
    """Remove panico.txt de todos os dispositivos de um setor"""
    global _panic_status_cache

    if not _check_rate_limit(_get_client_ip()):
        return jsonify({'success': False, 'error': 'Muitas acoes em pouco tempo. Aguarde.'})

    if not session.get('panic_authorized'):
        return jsonify({'success': False, 'error': 'NEED_AUTH', 'message': 'Senha de panico necessaria'})

    data = request.get_json()
    setor_id = data.get('setor_id')

    if not setor_id:
        return jsonify({'success': False, 'error': 'Setor nao fornecido'})

    beboxes = load_beboxes()
    setor = beboxes['setores'].get(setor_id)
    if not setor:
        return jsonify({'success': False, 'error': 'Setor nao encontrado'})

    config = load_config()
    ssh_user = config.get('ssh_user', 'bepass')
    ssh_password = config.get('ssh_password', '')
    setor_name = setor.get('nome', setor_id)

    add_shared_log(f"Desabilitando panico no setor {setor_name}...", 'info')

    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(remove_panic_file, d['ip_rasp'], d['bebox'], ssh_user, ssh_password): d
            for d in setor['dispositivos']
        }
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            if result['success']:
                add_shared_log(f"BeBox {result['bebox']} ({result['ip']}) - panico removido", 'success')
            else:
                add_shared_log(f"BeBox {result['bebox']} ({result['ip']}) - erro: {result.get('output', '')}", 'error')

    success_count = sum(1 for r in results if r['success'])
    failed_count = len(results) - success_count

    add_shared_log(f"Desabilitar panico {setor_name} - {success_count} OK, {failed_count} falhas", 'success' if failed_count == 0 else 'error')

    with _panic_status_lock:
        _panic_status_cache['data'] = None
        _panic_status_cache['timestamp'] = 0

    username = session.get('username', 'unknown')
    log_audit(username, 'DISABLE_PANIC_SETOR', f"Setor {setor_name}: {success_count} OK, {failed_count} falhas", 'SUCCESS' if success_count > 0 else 'FAILED', f"{success_count}/{len(results)}")

    return jsonify({
        'success': success_count > 0,
        'total': len(results),
        'success_count': success_count,
        'failed_count': failed_count,
        'results': results
    })


@app.route('/api/panic/disable', methods=['POST'])
@login_required
def panic_disable():
    """Remove panico.txt de todos os dispositivos (desabilita panico geral)"""
    global is_operation_active, _panic_status_cache

    if not _check_rate_limit(_get_client_ip()):
        return jsonify({'success': False, 'error': 'Muitas acoes em pouco tempo. Aguarde.'})

    if not session.get('panic_authorized'):
        return jsonify({'success': False, 'error': 'NEED_AUTH', 'message': 'Senha de panico necessaria'})

    config = load_config()
    beboxes = load_beboxes()
    ssh_user = config.get('ssh_user', 'bepass')
    ssh_password = config.get('ssh_password', '')

    is_operation_active = True
    add_shared_log("Desabilitando panico em todos os dispositivos...", 'info')

    devices = []
    for setor_id, setor in beboxes['setores'].items():
        for device in setor['dispositivos']:
            devices.append(device)

    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(remove_panic_file, d['ip_rasp'], d['bebox'], ssh_user, ssh_password): d
            for d in devices
        }
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            if result['success']:
                add_shared_log(f"BeBox {result['bebox']} ({result['ip']}) - panico removido", 'success')
            else:
                add_shared_log(f"BeBox {result['bebox']} ({result['ip']}) - erro ao remover: {result.get('output', '')}", 'error')

    success_count = sum(1 for r in results if r['success'])
    failed_count = len(results) - success_count

    add_shared_log(f"Desabilitar panico - {success_count} OK, {failed_count} falhas", 'success' if failed_count == 0 else 'error')

    # Invalidate cache so next heartbeat reflects the change
    with _panic_status_lock:
        _panic_status_cache['data'] = None
        _panic_status_cache['timestamp'] = 0

    username = session.get('username', 'unknown')
    log_action_history(username, 'disable_panic', f"Desabilitou panico geral: {success_count} OK, {failed_count} falhas")
    log_audit(username, 'DISABLE_PANIC_ALL', f"Desabilitar geral: {success_count} OK, {failed_count} falhas em {len(results)} devices", 'SUCCESS' if success_count > 0 else 'FAILED', f"{success_count}/{len(results)}")

    is_operation_active = False
    return jsonify({
        'success': success_count > 0,
        'total': len(results),
        'success_count': success_count,
        'failed_count': failed_count,
        'results': results
    })


def generate_md5_hash_from_date():
    today = datetime.now().strftime("%d%m%Y")
    return hashlib.md5(today.encode()).hexdigest(), today

def check_and_update_daily_hash():
    from dotenv import load_dotenv, set_key
    load_dotenv()
    last_date = os.getenv("LAST_HASH_DATE", "")
    today = datetime.now().strftime("%d%m%Y")
    if last_date != today:
        new_hash, _ = generate_md5_hash_from_date()
        set_key(".env", "PANIC_HASH", new_hash)
        set_key(".env", "LAST_HASH_DATE", today)
        os.environ["PANIC_HASH"] = new_hash
        return True
    return False



@app.route('/api/generate-hash')
@login_required
def api_generate_hash():
    """Gera hash baseado na data atual"""
    new_hash, date_str = generate_md5_hash_from_date()
    
    # Atualiza o .env
    try:
        from dotenv import set_key
        set_key('.env', 'PANIC_HASH', new_hash)
        set_key('.env', 'LAST_HASH_DATE', date_str)
    except:
        pass
    
    username = session.get('username', 'unknown')
    log_audit(username, 'HASH_GENERATED', f"Hash gerado para {date_str[:2]}/{date_str[2:4]}/{date_str[4:]}", 'SUCCESS', f"Hash: {new_hash[:12]}...")

    return jsonify({
        'hash': new_hash,
        'date': f"{date_str[:2]}/{date_str[2:4]}/{date_str[4:]}"
    })

if __name__ == '__main__':
    config = load_config()
    port = config.get('app_port', 3456)
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                 BEPASS PANIC CONTROL                          ║
║              Sistema de Controle de Pânico                    ║
╠══════════════════════════════════════════════════════════════╣
║  Servidor iniciado em: http://0.0.0.0:{port}                   ║
║  Configure a URL no seu navegador conforme seu ambiente       ║
║  Credenciais: Configure em .env                              ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
