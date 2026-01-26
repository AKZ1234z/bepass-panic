# Bepass Panic Control

Sistema de controle de pânico para liberação emergencial de catracas via BeBox.

## Visão Geral

Este sistema permite enviar comandos de "modo pânico" para os dispositivos BeBox (Raspberry Pi) que controlam as catracas. O comando de pânico libera as catracas automaticamente, permitindo a evacuação rápida do local.

## Requisitos

- Python 3.8+
- Flask
- SSH client
- Acesso SSH configurado para os BeBoxes
- Arquivo `.env` com credenciais (veja `.env.example`)

## Setup Inicial

### 1. Clonar/Copiar Projeto
```bash
git clone <repository> bepass-panic
cd bepass-panic
```

### 2. Configurar Credenciais
```bash
# Copiar arquivo de exemplo
cp .env.example .env

# Editar .env com suas credenciais
nano .env
```

### 3. Instalar Dependências
```bash
pip install -r requirements.txt
```

### 4. Executar Aplicação
```bash
python3 app.py
```

O servidor iniciará na porta configurada no `.env` (padrão: 3456).

## Configuração via .env

Todas as credenciais devem estar no arquivo `.env`:

- `LOGIN_USERNAME` - Usuário para login no dashboard
- `LOGIN_PASSWORD` - Senha para login
- `PANIC_HASH` - Hash de pânico diário
- `SSH_USER` - Usuário SSH para BeBoxes
- `SSH_PASSWORD` - Senha SSH (opcional, se não usar chave)
- `SSH_KEY_PATH` - Caminho para chave SSH privada
- `APP_PORT` - Porta da aplicação

**IMPORTANTE:** Nunca commitar `.env` com credenciais reais. Use `.gitignore`.

## Funcionalidades

### Dashboard Principal

- Visualização de todos os setores e dispositivos
- Contagem total de dispositivos
- Exibição do hash ativo

### Modos de Pânico

1. **Dispositivo Individual:** Clique em qualquer chip de BeBox para enviar pânico apenas para aquele dispositivo
2. **Setor/Portão:** Botão "Pânico" em cada card de setor para liberar todas as catracas daquele portão
3. **Estádio Completo:** Botão "LIBERAR TODO ESTÁDIO" para pânico total

### Atualização de Hash

O hash pode ser atualizado diretamente pela interface web durante a sessão.

### Logs em Tempo Real

Todas as ações são registradas:
- Na interface web (Log de Execução em tempo real)
- Sincronização automática entre múltiplos usuários

## Configuração SSH

Para que o sistema funcione, configure acesso SSH sem senha:

```bash
# Gerar chave SSH (se ainda não existir)
ssh-keygen -t rsa -b 4096

# Configurar no .env
SSH_KEY_PATH=~/.ssh/sua_chave
```

## API Endpoints

| Endpoint | Método | Descrição |
|----------|--------|-----------|
| `/login` | GET/POST | Autenticação |
| `/dashboard` | GET | Dashboard principal |
| `/api/logs` | GET | Obter logs em tempo real |
| `/api/hash` | GET/POST | Obter ou atualizar hash |
| `/api/panic/device` | POST | Pânico em dispositivo único |
| `/api/panic/setor` | POST | Pânico em setor |
| `/api/panic/all` | POST | Pânico total |

## Estrutura de Arquivos

```
bepass-panic/
├── app.py                  # Aplicação Flask principal
├── .env                    # Variáveis de ambiente (não commitar!)
├── .env.example           # Template de .env
├── .gitignore             # Ignora arquivos sensíveis
├── beboxes.json           # Lista de dispositivos por setor
├── requirements.txt       # Dependências Python
├── install.sh             # Script de instalação (systemd)
├── templates/
│   ├── login.html         # Página de login
│   └── dashboard.html     # Dashboard principal
└── static/
    └── logo-bepass.png    # Logo da aplicação
```

## Troubleshooting

### Erro de conexão SSH

1. Verificar `.env` - certifique-se que SSH_KEY_PATH está correto
2. Testar manualmente a chave SSH
3. Verificar permissões: `ls -la ~/.ssh/`

### Timeout nos dispositivos

1. Aumentar timeout no código se necessário
2. Verificar latência da rede
3. Alguns dispositivos podem estar offline

### Dashboard não carrega

1. Verificar se credenciais em `.env` estão corretas
2. Verificar logs da aplicação: `tail -f app.log`
3. Certifique-se que a porta está disponível

## Segurança

✅ **Melhorias de Segurança:**
- Credenciais centralizadas em `.env` (não commitadas)
- Arquivo `.gitignore` protege dados sensíveis
- SSH key-based authentication
- Logs de todas as operações
- Autenticação obrigatória em todas as funcionalidades
- Sincronização segura entre múltiplos usuários

⚠️ **Antes de Deploy em Produção:**
- Trocar todas as senhas padrão em `.env`
- Usar HTTPS (não HTTP)
- Configurar firewall para aceitar apenas IPs autorizados
- Fazer backup regularmente
- Revisar logs periodicamente

## Suporte

Sistema desenvolvido para operações de emergência no controle de acesso.
