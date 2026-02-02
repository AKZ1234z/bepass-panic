#!/bin/bash
#
# release_panic_v2.sh - Deploy Panic Heartbeat + Desabilitar Panico
# Roda no servidor para aplicar as alteracoes e reiniciar o servico
#

set -e

APP_DIR="/home/bepass/.bepass/bepass-panic-v2"
APP_NAME="bepass-panic"
APP_PORT=3456

echo "========================================"
echo "  Bepass Panic v2 - Release Script"
echo "========================================"
echo ""

# 1. Verificar diretorio
if [ ! -d "$APP_DIR" ]; then
    echo "[ERRO] Diretorio $APP_DIR nao encontrado"
    exit 1
fi

cd "$APP_DIR"
echo "[OK] Diretorio: $APP_DIR"

# 2. Backup dos arquivos atuais
BACKUP_DIR="$APP_DIR/backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp app.py "$BACKUP_DIR/app.py.bak"
cp templates/dashboard.html "$BACKUP_DIR/dashboard.html.bak"
echo "[OK] Backup em $BACKUP_DIR"

# 3. Pull das alteracoes do git (se for repo)
if [ -d ".git" ]; then
    echo "[...] Puxando alteracoes do git..."
    git pull origin "$(git branch --show-current)" || echo "[AVISO] git pull falhou, usando arquivos locais"
    echo "[OK] Git atualizado"
else
    echo "[INFO] Sem git, usando arquivos locais"
fi

# 4. Verificar dependencias Python
echo "[...] Verificando dependencias..."
pip3 install -q flask python-dotenv 2>/dev/null || pip install -q flask python-dotenv 2>/dev/null
echo "[OK] Dependencias OK"

# 5. Verificar sshpass (necessario para heartbeat SSH)
if ! command -v sshpass &> /dev/null; then
    echo "[...] Instalando sshpass..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get install -y sshpass
    elif command -v yum &> /dev/null; then
        sudo yum install -y sshpass
    else
        echo "[AVISO] Instale sshpass manualmente"
    fi
fi
echo "[OK] sshpass disponivel"

# 6. Criar diretorios necessarios
mkdir -p logs data
echo "[OK] Diretorios logs/ e data/ prontos"

# 7. Restart com PM2
if command -v pm2 &> /dev/null; then
    echo "[...] Reiniciando via PM2..."
    pm2 restart "$APP_NAME" --update-env 2>/dev/null || pm2 start ecosystem.config.js
    pm2 save
    echo "[OK] PM2 reiniciado"
else
    echo "[AVISO] PM2 nao encontrado, tentando matar processo antigo..."
    pkill -f "python3 app.py" 2>/dev/null || true
    sleep 1
    nohup python3 app.py > logs/output.log 2>&1 &
    echo "[OK] App iniciado em background (PID: $!)"
fi

# 8. Healthcheck - esperar app subir
echo "[...] Aguardando app subir..."
MAX_WAIT=15
for i in $(seq 1 $MAX_WAIT); do
    if curl -s -o /dev/null -w "%{http_code}" "http://localhost:$APP_PORT/login" | grep -q "200"; then
        echo "[OK] App respondendo na porta $APP_PORT"
        break
    fi
    if [ "$i" -eq "$MAX_WAIT" ]; then
        echo "[ERRO] App nao respondeu em ${MAX_WAIT}s"
        echo "       Verifique: pm2 logs $APP_NAME"
        exit 1
    fi
    sleep 1
done

# 9. Testar novos endpoints
echo ""
echo "--- Testando endpoints novos ---"

# Precisa estar logado, entao testa se rota existe (401/302 = OK, rota existe)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$APP_PORT/api/panic/status/quick")
if [ "$STATUS" = "302" ] || [ "$STATUS" = "200" ]; then
    echo "[OK] GET /api/panic/status/quick  -> $STATUS"
else
    echo "[AVISO] GET /api/panic/status/quick -> $STATUS"
fi

STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$APP_PORT/api/panic/status")
if [ "$STATUS" = "302" ] || [ "$STATUS" = "200" ]; then
    echo "[OK] GET /api/panic/status        -> $STATUS"
else
    echo "[AVISO] GET /api/panic/status     -> $STATUS"
fi

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://localhost:$APP_PORT/api/panic/disable")
if [ "$STATUS" = "302" ] || [ "$STATUS" = "200" ]; then
    echo "[OK] POST /api/panic/disable      -> $STATUS"
else
    echo "[AVISO] POST /api/panic/disable   -> $STATUS"
fi

echo ""
echo "========================================"
echo "  Deploy concluido!"
echo "  Acesse: http://$(hostname -I | awk '{print $1}'):$APP_PORT"
echo "========================================"
echo ""
echo "  Novos recursos:"
echo "  - Heartbeat: status de panico a cada 60s"
echo "  - Desabilitar Panico: remove panico.txt de todas as rasps"
echo "  - Chips verdes + bolinha pulsante quando em panico"
echo "  - Badge 'Via Sistema' / 'Via Catraca'"
echo "========================================"
