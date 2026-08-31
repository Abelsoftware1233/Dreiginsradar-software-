#!/usr/bin/env bash
#
# deploy.sh — Cybersecurity Trend Predictor (Signalis)
# =======================================================
# Zet de volledige stack (backend + frontend) op als systemd-service,
# draaiend op ÉÉN poort: 4444.
#
#   - API leeft onder       http://<host>:4444/api/...
#   - Dashboard leeft onder http://<host>:4444/          (redirect naar /app/)
#
# Wat dit script doet (idempotent — veilig om opnieuw te draaien):
#   1. Valideert dat het als root/sudo draait (nodig voor systemd + poort).
#   2. Maakt een dedicated systeemgebruiker aan (geen login, geen home-writes
#      buiten de installdir) zodat de service niet als root hoeft te draaien.
#   3. Kopieert dit project naar een installatie-directory.
#   4. Zet een Python-venv op en installeert requirements.txt daarin.
#   5. Genereert een systemd unit-file en herlaadt systemd.
#   6. Enablet + (her)start de service.
#   7. Toont de status en een korte health-check.
#
# Gebruik:
#   sudo ./deploy.sh                 # installeren/updaten + starten
#   sudo ./deploy.sh --uninstall     # service stoppen en verwijderen
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuratie — pas aan indien nodig
# ---------------------------------------------------------------------------
APP_NAME="cybersec-predict"
APP_PORT="4444"
APP_USER="signalis"
APP_GROUP="signalis"
INSTALL_DIR="/opt/${APP_NAME}"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
VENV_DIR="${INSTALL_DIR}/venv"

# Map waar dit script zelf staat (= project-root, met backend/ en frontend/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Kleurtjes voor leesbare output (val terug op platte tekst als niet-tty)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    C_GREEN='\033[0;32m'; C_YELLOW='\033[0;33m'; C_RED='\033[0;31m'; C_BLUE='\033[0;34m'; C_RESET='\033[0m'
else
    C_GREEN=''; C_YELLOW=''; C_RED=''; C_BLUE=''; C_RESET=''
fi

log()  { echo -e "${C_BLUE}[deploy]${C_RESET} $1"; }
ok()   { echo -e "${C_GREEN}[ok]${C_RESET} $1"; }
warn() { echo -e "${C_YELLOW}[let op]${C_RESET} $1"; }
err()  { echo -e "${C_RED}[fout]${C_RESET} $1" >&2; }

# ---------------------------------------------------------------------------
# --uninstall pad
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--uninstall" ]]; then
    log "Service ${APP_NAME} verwijderen…"
    systemctl stop "${APP_NAME}.service" 2>/dev/null || true
    systemctl disable "${APP_NAME}.service" 2>/dev/null || true
    rm -f "${SERVICE_FILE}"
    systemctl daemon-reload
    warn "Service verwijderd. Installatiemap (${INSTALL_DIR}) en gebruiker (${APP_USER}) zijn NIET verwijderd."
    warn "Handmatig opruimen indien gewenst:"
    echo "    sudo rm -rf ${INSTALL_DIR}"
    echo "    sudo userdel ${APP_USER}"
    exit 0
fi

# ---------------------------------------------------------------------------
# 1. Root-check
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    err "Dit script heeft root nodig (systemd-unit + poortbinding + gebruikersbeheer)."
    err "Start opnieuw met: sudo ./deploy.sh"
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. Vereisten checken
# ---------------------------------------------------------------------------
log "Vereisten controleren…"

if ! command -v python3 >/dev/null 2>&1; then
    err "python3 niet gevonden. Installeer eerst Python 3.10+."
    exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
log "Python versie gevonden: ${PY_VERSION}"

if ! python3 -m venv --help >/dev/null 2>&1; then
    err "python3-venv ontbreekt. Installeer met bv.: apt install python3-venv"
    exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
    HAS_SYSTEMD=1
else
    warn "systemctl niet gevonden — systemd-service wordt overgeslagen."
    warn "De app wordt wel geïnstalleerd; start 'm dan handmatig (zie einde van dit script)."
    HAS_SYSTEMD=0
fi

# Poort 4444 al in gebruik door iets anders dan onze eigen service?
if command -v ss >/dev/null 2>&1; then
    if ss -ltn "( sport = :${APP_PORT} )" | grep -q ":${APP_PORT}"; then
        if systemctl is-active --quiet "${APP_NAME}.service" 2>/dev/null; then
            log "Poort ${APP_PORT} is al in gebruik door de bestaande ${APP_NAME}-service — dat is prima, wordt zo herstart."
        else
            warn "Poort ${APP_PORT} lijkt al in gebruik door een ANDER proces. Controleer met: ss -ltnp | grep ${APP_PORT}"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 3. Systeemgebruiker aanmaken (idempotent)
# ---------------------------------------------------------------------------
if id "${APP_USER}" >/dev/null 2>&1; then
    log "Gebruiker '${APP_USER}' bestaat al, hergebruiken."
else
    log "Systeemgebruiker '${APP_USER}' aanmaken (geen login, geen eigen home)…"
    useradd --system --no-create-home --shell /usr/sbin/nologin "${APP_USER}"
    ok "Gebruiker '${APP_USER}' aangemaakt."
fi

# ---------------------------------------------------------------------------
# 4. Bestanden naar installatiemap kopiëren
# ---------------------------------------------------------------------------
log "Bestanden kopiëren naar ${INSTALL_DIR}…"
mkdir -p "${INSTALL_DIR}"

if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
        --exclude 'venv' \
        --exclude '__pycache__' \
        --exclude '*.pyc' \
        --exclude '.git' \
        "${SCRIPT_DIR}/" "${INSTALL_DIR}/"
else
    cp -r "${SCRIPT_DIR}/backend" "${SCRIPT_DIR}/frontend" "${SCRIPT_DIR}/README.md" "${INSTALL_DIR}/" 2>/dev/null || true
fi
ok "Bestanden gekopieerd."

# ---------------------------------------------------------------------------
# 5. Python-venv opzetten + dependencies installeren
# ---------------------------------------------------------------------------
if [[ -d "${VENV_DIR}" ]]; then
    log "Virtuele omgeving bestaat al, dependencies bijwerken…"
else
    log "Virtuele omgeving aanmaken in ${VENV_DIR}…"
    python3 -m venv "${VENV_DIR}"
fi

log "Dependencies installeren (dit kan even duren)…"
"${VENV_DIR}/bin/pip" install --upgrade pip --quiet
"${VENV_DIR}/bin/pip" install -r "${INSTALL_DIR}/backend/requirements.txt" --quiet
ok "Dependencies geïnstalleerd."

# ---------------------------------------------------------------------------
# 6. Eigendom/rechten zetten
# ---------------------------------------------------------------------------
log "Eigendom instellen op ${APP_USER}:${APP_GROUP}…"
chown -R "${APP_USER}:${APP_GROUP}" "${INSTALL_DIR}"
ok "Rechten gezet."

# ---------------------------------------------------------------------------
# 7. systemd unit-file genereren
# ---------------------------------------------------------------------------
if [[ $HAS_SYSTEMD -eq 1 ]]; then
    log "systemd-service schrijven naar ${SERVICE_FILE}…"

    cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Cybersecurity Trend Predictor (Signalis)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_GROUP}
WorkingDirectory=${INSTALL_DIR}/backend
ExecStart=${VENV_DIR}/bin/uvicorn main:app --host 0.0.0.0 --port ${APP_PORT}
Restart=on-failure
RestartSec=3

# Alles op poort ${APP_PORT} — geen andere poorten nodig (geen aparte
# frontend-server: FastAPI serveert /app/* mee vanuit hetzelfde process).

# --- Hardening (behoudt functionaliteit, beperkt de blast radius) ---
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${INSTALL_DIR}
# Poort ${APP_PORT} is een unprivileged poort (>1024), dus GEEN
# CAP_NET_BIND_SERVICE of root nodig om eraan te binden.

[Install]
WantedBy=multi-user.target
EOF

    ok "systemd unit-file geschreven."

    log "systemd herladen…"
    systemctl daemon-reload

    log "Service enablen (autostart bij boot)…"
    systemctl enable "${APP_NAME}.service" --quiet

    log "Service (her)starten…"
    systemctl restart "${APP_NAME}.service"

    sleep 2

    if systemctl is-active --quiet "${APP_NAME}.service"; then
        ok "Service '${APP_NAME}' draait."
    else
        err "Service is niet actief. Logs bekijken met:"
        echo "    sudo journalctl -u ${APP_NAME}.service -n 50 --no-pager"
        exit 1
    fi

    # ---------------------------------------------------------------------
    # 8. Health-check
    # ---------------------------------------------------------------------
    log "Health-check uitvoeren op http://localhost:${APP_PORT}/api/health …"
    if command -v curl >/dev/null 2>&1; then
        sleep 1
        if curl -sf "http://localhost:${APP_PORT}/api/health" >/dev/null; then
            ok "API reageert correct."
        else
            warn "API reageerde niet binnen de verwachte tijd. Check de logs:"
            echo "    sudo journalctl -u ${APP_NAME}.service -f"
        fi
    else
        warn "curl niet gevonden — health-check overgeslagen."
    fi

    echo ""
    ok "Klaar. Cybersecurity Trend Predictor draait op poort ${APP_PORT}."
    echo ""
    echo "  Dashboard:  http://<server-ip>:${APP_PORT}/"
    echo "  API:        http://<server-ip>:${APP_PORT}/api/categories"
    echo ""
    echo "Nuttige commando's:"
    echo "  sudo systemctl status ${APP_NAME}      # status bekijken"
    echo "  sudo systemctl restart ${APP_NAME}     # herstarten"
    echo "  sudo systemctl stop ${APP_NAME}        # stoppen"
    echo "  sudo journalctl -u ${APP_NAME} -f      # live logs volgen"
    echo "  sudo ./deploy.sh --uninstall           # service verwijderen"
    echo ""
    echo "Draait deze server achter een firewall? Zorg dat poort ${APP_PORT}/tcp"
    echo "open staat, bv.: sudo ufw allow ${APP_PORT}/tcp"

else
    echo ""
    ok "Installatie voltooid (zonder systemd-service, systemctl ontbreekt)."
    echo ""
    echo "Start de app handmatig met:"
    echo "    sudo -u ${APP_USER} ${VENV_DIR}/bin/uvicorn main:app \\"
    echo "        --host 0.0.0.0 --port ${APP_PORT} \\"
    echo "        --app-dir ${INSTALL_DIR}/backend"
fi
