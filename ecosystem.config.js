module.exports = {
  apps: [{
    name: 'bepass-panic',
    script: 'app.py',
    interpreter: 'python3',
    cwd: '/home/bepass/.bepass/bepass-panic-v2',
    
    // Versão e descrição
    version: '1.1.2',
    
    // Configurações de execução
    instances: 1,
    exec_mode: 'fork',
    autorestart: true,
    watch: false,
    max_memory_restart: '500M',
    
    // Restart inteligente
    restart_delay: 3000,
    max_restarts: 10,
    min_uptime: '10s',
    
    // Variáveis de ambiente
    env: {
      NODE_ENV: 'production',
      FLASK_ENV: 'production',
      PORT: 3456
    },
    
    // Logs organizados
    error_file: '/home/bepass/.bepass/bepass-panic-v2/logs/error.log',
    out_file: '/home/bepass/.bepass/bepass-panic-v2/logs/output.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss',
    merge_logs: true,
    
    // Tempo e recursos
    kill_timeout: 5000,
    listen_timeout: 3000,
  }]
};
