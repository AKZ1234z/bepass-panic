#!/usr/bin/env python3
"""
Bepass Panic Control - Interface de Controle de Pânico
Sistema de abertura emergencial de catracas via BeBox
"""

import os
import json
import subprocess
import threading
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
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
app.permanent_session_lifetime = timedelta(hours=8)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

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
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

command_results = {}

shared_logs = []
max_logs = 100
is_operation_active = False

def add_shared_log(message, log_type='info'):
    """Adiciona log ao compartilhado para sincronização em tempo real"""
    global shared_logs
    timestamp = datetime.now().strftime('%H:%M:%S')
    log_entry = {
        'time': timestamp,
        'message': message,
        'type': log_type
    }
    shared_logs.insert(0, log_entry)
    # Manter apenas últimos 100 logs
    if len(shared_logs) > max_logs:
        shared_logs = shared_logs[:max_logs]
    logger.info(f"[{log_type.upper()}] {message}")

def execute_panic_command(ip, bebox_id, panic_hash, result_key):
    """Executa o comando de pânico em uma BeBox via SSH"""
    config = load_config()
    ssh_user = config.get('ssh_user', 'bepass')
    api_port = config.get('bebox_api_port', 3005)
    
    # Comando curl para enviar ao BeBox
    curl_command = f'''curl --max-time 5 --location 'localhost:{api_port}/message' --header 'Content-Type: application/json' --data '{{"message": {{"access": "allowed","hash": "{panic_hash}|barcode","message": "Liberado"}}}}' '''
    
    # Comando SSH completo
    ssh_command = [
        'ssh',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'ConnectTimeout=5',
        '-o', 'BatchMode=yes',
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
        config = load_config()
        username = request.form.get('username')
        password = request.form.get('password')
        
        if (username == config['login']['username'] and 
            password == config['login']['password']):
            session.permanent = True
            session['logged_in'] = True
            session['username'] = username
            logger.info(f"Login bem-sucedido: {username}")
            return redirect(url_for('dashboard'))
        else:
            logger.warning(f"Tentativa de login falhou: {username}")
            return render_template('login.html', error='Credenciais inválidas')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Dashboard principal
@app.route('/dashboard')
@login_required
def dashboard():
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

@app.route('/api/panic/device', methods=['POST'])
@login_required
def panic_device():
    """Envia comando de pânico para um único dispositivo"""
    global is_operation_active

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
    if result.get('success'):
        add_shared_log(f"✓ BeBox {bebox_id} (IP: {ip}) - LIBERADO", 'success')
    else:
        add_shared_log(f"✗ BeBox {bebox_id} (IP: {ip}) - ERRO: {result.get('output', 'Erro desconhecido')}", 'error')

    is_operation_active = False
    return jsonify(result)

@app.route('/api/panic/setor', methods=['POST'])
@login_required
def panic_setor():
    """Envia comando de pânico para todos os dispositivos de um setor"""
    global is_operation_active

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
            ['ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=5',
             '-o', 'BatchMode=yes', f'{ssh_user}@{ip}', 'echo ok'],
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
