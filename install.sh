#!/bin/bash
#
# Bepass Panic Control - Script de Instalação
# Este script configura o sistema de controle de pânico no servidor
#

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo ""
echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║                 BEPASS PANIC CONTROL                          ║${NC}"
echo -e "${RED}║              Instalação do Sistema                            ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Diretório de instalação
INSTALL_DIR="/opt/bepass-panic"
SERVICE_NAME="bepass-panic"

# Verificar se é root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}Aviso: Executando sem sudo. Algumas operações podem falhar.${NC}"
    echo -e "${YELLOW}Para instalação completa, execute: sudo ./install.sh${NC}"
    echo ""
    INSTALL_DIR="$HOME/bepass-panic"
fi

echo -e "${GREEN}[1/6]${NC} Verificando dependências..."

# Verificar Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Erro: Python3 não encontrado. Instale com: sudo apt install python3 python3-pip${NC}"
    exit 1
fi
echo "  ✓ Python3 encontrado: $(python3 --version)"

# Verificar pip
if ! command -v pip3 &> /dev/null; then
    echo -e "${YELLOW}  pip3 não encontrado. Tentando instalar...${NC}"
    if [ "$EUID" -eq 0 ]; then
        apt-get update && apt-get install -y python3-pip
    else
        echo -e "${RED}Erro: Instale pip3 com: sudo apt install python3-pip${NC}"
        exit 1
    fi
fi
echo "  ✓ pip3 encontrado"

# Verificar SSH
if ! command -v ssh &> /dev/null; then
    echo -e "${RED}Erro: SSH não encontrado. Instale com: sudo apt install openssh-client${NC}"
    exit 1
fi
echo "  ✓ SSH encontrado"

echo ""
echo -e "${GREEN}[2/6]${NC} Criando diretório de instalação..."
mkdir -p "$INSTALL_DIR"
echo "  ✓ Diretório: $INSTALL_DIR"

echo ""
echo -e "${GREEN}[3/6]${NC} Copiando arquivos..."
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/app.py"
echo "  ✓ Arquivos copiados"

echo ""
echo -e "${GREEN}[4/6]${NC} Instalando dependências Python..."
pip3 install -r "$INSTALL_DIR/requirements.txt" --quiet
echo "  ✓ Flask instalado"

echo ""
echo -e "${GREEN}[5/6]${NC} Configurando chaves SSH..."

SSH_KEY="$HOME/.ssh/id_rsa"
if [ ! -f "$SSH_KEY" ]; then
    echo "  Gerando nova chave SSH..."
    ssh-keygen -t rsa -b 4096 -f "$SSH_KEY" -N "" -q
    echo "  ✓ Chave SSH gerada"
else
    echo "  ✓ Chave SSH existente encontrada"
fi

echo ""
echo -e "${YELLOW}  IMPORTANTE: Copie a chave pública para os BeBoxes:${NC}"
echo ""
echo "  cat $SSH_KEY.pub"
echo ""
echo "  E adicione em cada BeBox no arquivo: /home/bepass/.ssh/authorized_keys"
echo ""

# Criar serviço systemd (apenas se root)
if [ "$EUID" -eq 0 ]; then
    echo ""
    echo -e "${GREEN}[6/6]${NC} Criando serviço systemd..."
    
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=Bepass Panic Control System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/app.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
    systemctl start ${SERVICE_NAME}
    
    echo "  ✓ Serviço criado e iniciado"
    echo ""
    echo -e "${GREEN}  Comandos úteis:${NC}"
    echo "    sudo systemctl status ${SERVICE_NAME}  # Ver status"
    echo "    sudo systemctl restart ${SERVICE_NAME} # Reiniciar"
    echo "    sudo systemctl stop ${SERVICE_NAME}    # Parar"
    echo "    sudo journalctl -u ${SERVICE_NAME} -f  # Ver logs"
else
    echo ""
    echo -e "${GREEN}[6/6]${NC} Pulando criação de serviço (execute como root para isso)"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                 INSTALAÇÃO CONCLUÍDA!                        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Diretório: $INSTALL_DIR"
echo ""
echo -e "  ${YELLOW}Para iniciar manualmente:${NC}"
echo "    cd $INSTALL_DIR && python3 app.py"
echo ""
echo -e "  ${YELLOW}Acesso:${NC}"
echo "    Configure a URL no seu .env (APP_PORT)"
echo ""
echo -e "  ${YELLOW}Credenciais:${NC}"
echo "    Configure em .env (LOGIN_USERNAME, LOGIN_PASSWORD)"
echo ""
echo -e "  ${YELLOW}Hash de Pânico:${NC}"
echo "    Configure em .env (PANIC_HASH)"
echo ""
