#!/bin/bash
# =============================================================================
# AnalisisRootkits.sh
# =============================================================================


# === Verificación de directorio base ===
BASE_DIR="/home/kali/TFM"

if [ ! -d "$BASE_DIR" ]; then
  echo "[*] Creando directorio base en $BASE_DIR ..."
  mkdir -p "$BASE_DIR"
  chown kali:kali "$BASE_DIR" 2>/dev/null || true
fi





# === Rutas/base ===
BASE_DIR="/home/kali/TFM"
LOG_FILE="$BASE_DIR/analisis.log"
QUAR_DIR="$BASE_DIR/quarantine"
BASELINE_MD5="$BASE_DIR/baseline_md5.txt"
BASELINE_SHA="$BASE_DIR/baseline_sha256.txt"
FS_WHITELIST="$BASE_DIR/whitelist_fs.txt"
USERS_WHITELIST="$BASE_DIR/whitelist_users.txt"
PROCS_WHITELIST="$BASE_DIR/whitelist_procs.txt"

mkdir -p "$BASE_DIR" "$QUAR_DIR"
touch "$LOG_FILE" "$FS_WHITELIST" "$USERS_WHITELIST" "$PROCS_WHITELIST"

# Inicializar whitelist de procesos críticos si está vacío
if [ ! -s "$PROCS_WHITELIST" ]; then
  cat >"$PROCS_WHITELIST" <<EOF
systemd
sshd
dbus-daemon
NetworkManager
bash
zsh
login
agetty
EOF
fi

# === Colores ===
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
NC='\033[0m' # Sin color

# === Utilidades visuales ===
title() { echo -e "${BLUE}=== $* ===${NC}"; }
opt()   { printf "%b%s%b) %s\n" "${MAGENTA}" "$1" "${NC}" "$2"; }
idx()   { printf "%b%s%b" "${MAGENTA}" "$1" "${NC}"; }
info()  { echo -e "${CYAN}$*${NC}"; }
ok()    { echo -e "${GREEN}$*${NC}"; }
warn()  { echo -e "${YELLOW}$*${NC}"; }
crit()  { echo -e "${RED}$*${NC}"; }

# === Utilidades ===
log() {
  local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
  echo -e "$msg" | tee -a "$LOG_FILE"
}

pause() {
  read -rp "$(printf '%b%s%b' "${MAGENTA}" 'Presiona Enter para continuar...' "${NC}")"
}

ask_choice(){
  local min="$1" max="$2" c
  while true; do
    read -rp "$(idx '#? ') " c
    [[ "$c" =~ ^[0-9]+$ ]] && ((c>=min && c<=max)) && { echo "$c"; return; }
    echo "Opción no válida (elige ${min}-${max})."
  done
}

ask_indices(){
  local n="$1" line idx out=()
  read -rp "$(idx '> ') " line
  [[ "$line" =~ ^[Aa][Ll][Ll]$ ]] && {
    for ((i=1;i<=n;i++)); do out+=("$i"); done
    printf "%s\n" "${out[@]}"; return
  }
  for tok in $line; do
    if [[ "$tok" =~ ^[0-9]+$ ]] && (( tok>=1 && tok<=n )); then
      out+=("$tok")
    else
      echo "Índice inválido: $tok (1..$n o ALL)" >&2
      return 1
    fi
  done
  printf "%s\n" "${out[@]}"
}

confirm_yn(){
  local ans
  while true; do
    read -rp "$1 $(idx '[y/N]'): " ans
    case "$ans" in
      [Yy]*) return 0 ;;
      [Nn]*|"") return 1 ;;
      *) echo "Responde y o n";;
    esac
  done
}

# === Preflight ligero (sin romper estructura) ===
need_cmds=(ps ls ss awk sed grep find stat rsync dpkg apt-get visudo chsh usermod userdel passwd)
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  warn "Este script debería ejecutarse como root para aplicar todas las acciones."
fi
for c in "${need_cmds[@]}"; do
  command -v "$c" >/dev/null 2>&1 || warn "Falta comando: $c (algunas funciones podrían no operar)"
done

# === Gestión de iptables (puertos) ===
have_iptables(){
  command -v iptables >/dev/null 2>&1
}
have_ip6tables(){
  command -v ip6tables >/dev/null 2>&1
}
block_port(){
  local p="$1"
  have_iptables || { log "[!] iptables no disponible"; return 1; }
  iptables -C INPUT -p tcp --dport "$p" -j DROP 2>/dev/null || iptables -A INPUT -p tcp --dport "$p" -j DROP
  have_ip6tables && ( ip6tables -C INPUT -p tcp --dport "$p" -j DROP 2>/dev/null || ip6tables -A INPUT -p tcp --dport "$p" -j DROP )
}
unblock_port(){
  local p="$1"
  have_iptables || { log "[!] iptables no disponible"; return 1; }
  while iptables -C INPUT -p tcp --dport "$p" -j DROP 2>/dev/null; do
    iptables -D INPUT -p tcp --dport "$p" -j DROP || break
  done
  if have_ip6tables; then
    while ip6tables -C INPUT -p tcp --dport "$p" -j DROP 2>/dev/null; do
      ip6tables -D INPUT -p tcp --dport "$p" -j DROP || break
    done
  fi
}
list_blocked_ports(){
  have_iptables || return 0
  {
    iptables -S INPUT 2>/dev/null
    have_ip6tables && ip6tables -S INPUT 2>/dev/null
  } | awk '/^-A INPUT/ && /-p tcp/ && /--dport/ && /-j DROP/ {for(i=1;i<=NF;i++) if($i=="--dport"){print $(i+1)}}' | sort -n | uniq
}
# Puertos “seguros” para no bloquear sin querer
is_safe_port(){
  case "$1" in
    22|53|67|68|80|123|443) return 0 ;;
    *) return 1 ;;
  esac
}

# =============================================================================
# MÓDULO: PROCESOS
# =============================================================================
manage_procs_whitelist(){
  title "Whitelist de procesos"
  nl -ba "$PROCS_WHITELIST" | sed -n '1,200p'
  echo
  opt 1 "Añadir proceso"
  opt 2 "Eliminar proceso"
  opt 3 "Vaciar whitelist"
  opt 4 "Volver"
  case "$(ask_choice 1 4)" in
    1) read -rp "Nombre o ruta de proceso a añadir: " p; [ -n "$p" ] && { echo "$p" >> "$PROCS_WHITELIST"; sort -u -o "$PROCS_WHITELIST" "$PROCS_WHITELIST"; log "[+] Añadido a whitelist: $p"; } ; pause;;
    2) read -rp "Proceso exacto a eliminar: " p; [ -n "$p" ] && { grep -Fvx "$p" "$PROCS_WHITELIST" > "$PROCS_WHITELIST.tmp"; mv -f "$PROCS_WHITELIST.tmp" "$PROCS_WHITELIST"; log "[+] Eliminado de whitelist: $p"; } ; pause;;
    3) : > "$PROCS_WHITELIST"; log "[+] Whitelist vaciada."; pause;;
    4) return ;;
  esac
}

# Copia forense del proceso (exe/maps + extras) a cuarentena
forensic_copy_proc(){
  local pid="$1" dest="$QUAR_DIR/procs/$pid"
  mkdir -p "$dest/fd"
  for f in cmdline environ status maps smaps stat; do
    cp "/proc/$pid/$f" "$dest/$f" 2>/dev/null || true
  done
  cp -a "/proc/$pid/fd" "$dest/fd" 2>/dev/null || true
  cp "/proc/$pid/exe" "$dest/exe_copy" 2>/dev/null || true
  local exe; exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
  [ -n "$exe" ] && [ -f "$exe" ] && cp -a "$exe" "$dest/original_exe" 2>/dev/null || true
  log "[*] Forense: capturado PID $pid en $dest"
}

# Parse sockets sospechosos de un PID (LISTEN)
pid_listen_ports(){
  local pid="$1"
  ss -tulpnH 2>/dev/null | awk -v target="$pid" '
    $1=="LISTEN" && $0 ~ ("pid=" target) {
      p=$5; sub(/.*:/,"",p); if (p ~ /^[0-9]+$/) print p;
    }' | sort -n | uniq
}

check_processes() {
  info "[*] Escaneando procesos..."

  # --- detectar "ocultos" (presentes en /proc pero no en ps) ---
  local pids_ps pids_proc hidden
  pids_ps=$(ps -eo pid= | awk '{print $1}' | sort -n | uniq)
  pids_proc=$(ls -1 /proc 2>/dev/null | awk '/^[0-9]+$/' | sort -n | uniq)
  hidden=$(comm -23 <(echo "$pids_proc") <(echo "$pids_ps"))

  results=()

  if [ -n "$hidden" ]; then
    while read -r pid; do
      [ -z "$pid" ] && continue
      name=$(cat "/proc/$pid/comm" 2>/dev/null)
      exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "-")
      results+=("$pid|$name|$exe|oculto")
    done <<< "$hidden"
  fi

  # --- detectar ejecutables borrados ---
  local deleted
  deleted=$(
    for d in /proc/[0-9]*; do
      pid="${d##*/}"
      [ -r "$d/maps" ] || continue
      if grep -q ' (deleted)$' "$d/maps" 2>/dev/null; then
        echo "$pid"
      fi
    done | sort -n | uniq
  )

  # Fallback adicional: exe resuelto a un path inexistente
  if [ -z "$deleted" ]; then
    deleted=$(
      for d in /proc/[0-9]*; do
        pid="${d##*/}"
        exe_path=$(readlink -f "$d/exe" 2>/dev/null || true)
        [ -n "$exe_path" ] && [ ! -e "$exe_path" ] && echo "$pid"
      done | sort -n | uniq
    )
  fi

  if [ -n "$deleted" ]; then
    while read -r pid; do
      [ -z "$pid" ] && continue
      name=$(cat "/proc/$pid/comm" 2>/dev/null)
      exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "-")
      results+=("$pid|$name|$exe|deleted")
    done <<< "$deleted"
  fi

  # --- aplicar whitelist (nombre o ruta exacta) ---
  filtered=()
  while IFS= read -r line; do
    pid=$(echo "$line" | cut -d'|' -f1)
    name=$(echo "$line" | cut -d'|' -f2)
    exe=$(echo "$line" | cut -d'|' -f3)
    skip=0
    grep -Fxq "$name" "$PROCS_WHITELIST" && skip=1
    [ "$exe" != "-" ] && grep -Fxq "$exe" "$PROCS_WHITELIST" && skip=1
    [ "$skip" -eq 0 ] && filtered+=("$line")
  done < <(printf "%s\n" "${results[@]}")

  if [ "${#filtered[@]}" -eq 0 ]; then
    ok "[+] No se detectaron procesos sospechosos."
    log "Procesos: OK"
    pause
    return
  fi

  crit "[!] Procesos sospechosos:"
  printf "%-5s %-7s %-20s %-35s %s\n" "IDX" "PID" "NOMBRE" "EXE" "MOTIVO"
  for i in "${!filtered[@]}"; do
    pid=$(echo "${filtered[$i]}" | cut -d'|' -f1)
    name=$(echo "${filtered[$i]}" | cut -d'|' -f2)
    exe=$(echo "${filtered[$i]}" | cut -d'|' -f3)
    motivo=$(echo "${filtered[$i]}" | cut -d'|' -f4)
    printf "%-5s %-7s %-20s %-35s %s\n" "$((i+1))" "$pid" "$name" "$exe" "$motivo"
  done

  echo
  opt 1 "Matar proceso(s)"
  opt 2 "Matar + bloquear puertos asociados"
  opt 3 "Enviar a cuarentena (binario y maps)"
  opt 4 "Añadir a whitelist"
  opt 5 "Gestionar whitelist"
  opt 6 "Volver"
  case "$(ask_choice 1 6)" in
    1)
      echo "Introduce índices a matar (ej: 1 3) o ALL:"
      mapfile -t sel < <(ask_indices "${#filtered[@]}") || { pause; return; }
      for id in "${sel[@]}"; do
        line="${filtered[id-1]}"
        pid=$(echo "$line" | cut -d'|' -f1)
        forensic_copy_proc "$pid"
        kill -9 "$pid" 2>/dev/null && log "[+] Proceso $pid matado"
      done
      pause
      ;;
    2)
      echo "Introduce índices (ej: 1 3) o ALL:"
      mapfile -t sel < <(ask_indices "${#filtered[@]}") || { pause; return; }
      for id in "${sel[@]}"; do
        line="${filtered[id-1]}"
        pid=$(echo "$line" | cut -d'|' -f1)
        ports=$(pid_listen_ports "$pid")
        forensic_copy_proc "$pid"
        kill -9 "$pid" 2>/dev/null && log "[+] Proceso $pid matado"
        for p in $ports; do
          block_port "$p" && log "[+] Puerto $p bloqueado"
        done
      done
      pause
      ;;
    3)
      echo "Introduce índices a enviar a cuarentena (ej: 1 3) o ALL:"
      mapfile -t sel < <(ask_indices "${#filtered[@]}") || { pause; return; }
      for id in "${sel[@]}"; do
        line="${filtered[id-1]}"
        pid=$(echo "$line" | cut -d'|' -f1)
        exe=$(echo "$line" | cut -d'|' -f3)
        dest="$QUAR_DIR/procs/$pid"
        mkdir -p "$dest"
        [ -f "$exe" ] && cp -a "$exe" "$dest/" 2>/dev/null
        cp "/proc/$pid/maps" "$dest/maps" 2>/dev/null || true
        cp "/proc/$pid/exe" "$dest/exe_copy" 2>/dev/null || true
        kill -9 "$pid" 2>/dev/null
        log "[+] Proceso $pid en cuarentena en $dest"
      done
      pause
      ;;
    4)
      echo "Introduce índices a añadir a whitelist (ej: 1 3) o ALL:"
      mapfile -t sel < <(ask_indices "${#filtered[@]}") || { pause; return; }
      for id in "${sel[@]}"; do
        line="${filtered[id-1]}"
        name=$(echo "$line" | cut -d'|' -f2)
        exe=$(echo "$line" | cut -d'|' -f3)
        echo "$name" >> "$PROCS_WHITELIST"
        [ "$exe" != "-" ] && echo "$exe" >> "$PROCS_WHITELIST"
      done
      sort -u -o "$PROCS_WHITELIST" "$PROCS_WHITELIST"
      log "[+] Añadidos a whitelist"
      pause
      ;;
    5) manage_procs_whitelist ;;
    6) return ;;
  esac
}

# =============================================================================
# MÓDULO: RED
# =============================================================================

parse_ss_suspects(){
  # Devuelve líneas "PORT PID" de sockets TCP LISTEN en 0.0.0.0 o [::]
  # Soporta formatos variados de 'ss -tulpn'
  ss -H -lntup 2>/dev/null | awk '
    $2=="LISTEN" {
      addr=$5
      # Sólo nos interesan binds a 0.0.0.0:* o [::]:*
      if (addr ~ /^0\.0\.0\.0:[0-9]+$/ || addr ~ /^\[::\]:[0-9]+$/) {
        port=addr
        sub(/.*:/,"",port)
        if (port ~ /^[0-9]+$/) {
          pid="-"
          if (match($0,/pid=([0-9]+)/,m)) pid=m[1]
          print port, pid
        }
      }
    }
  ' | sort -n | uniq
}

check_network() {
  info "[*] Escaneando conexiones de red..."
  local lines
  lines=$(ss -tulpn 2>/dev/null | grep -E 'LISTEN' | grep -E '0\.0\.0\.0|:::' || true)

  if [ -n "$lines" ]; then
    crit "[!] Conexiones sospechosas (bind a 0.0.0.0 / :::):"
    echo "$lines"

    # Parsear candidatos (puerto y pid)
    local suspects=()
    mapfile -t suspects < <(parse_ss_suspects)

    echo
    info "[?] ¿Qué deseas hacer con los procesos que abren estos puertos?"
    opt 1 "Cerrar TODOS los procesos detectados y bloquear puertos (respeta puertos seguros)"
    opt 2 "Cerrar procesos específicos (introducir PIDs) y bloquear sus puertos"
    opt 3 "Sólo bloquear/desbloquear puertos manualmente"
    opt 4 "Volver"

    case "$(ask_choice 1 4)" in
      1)
        if [ "${#suspects[@]}" -eq 0 ]; then
          warn "[!] No pude extraer PIDs automáticamente de la salida de ss."
          warn "    Pasa por la opción 2 para introducir PIDs manualmente."
          pause
          return
        fi
        for sp in "${suspects[@]}"; do
          p="${sp%% *}"; pid="${sp##* }"
          # Mata PID si está
          if [[ "$pid" =~ ^[0-9]+$ ]]; then
            kill -9 "$pid" 2>/dev/null && echo "[+] Proceso $pid cerrado" && log "Cerrado proceso $pid"
          else
            warn "[*] Sin PID extraíble para puerto $p; no se mata proceso."
          fi
          # Bloquea puerto salvo si es "seguro"
          if is_safe_port "$p"; then
            echo "[*] Saltando puerto seguro $p"
          else
            block_port "$p" && echo "[+] Puerto $p bloqueado"
          fi
        done
        log "Red: cierre masivo + bloqueo (con safelist) aplicado"
        pause
        ;;

      2)
        echo "Introduce los PID a cerrar, separados por espacios (ej: 1234 5678):"
        read -r pids
        for pid in $pids; do
          if [[ "$pid" =~ ^[0-9]+$ ]]; then
            # Descubrir qué puertos abre ese PID en LISTEN
            mapfile -t ports < <(ss -H -lntup 2>/dev/null | awk -v target="$pid" '
              $2=="LISTEN" && $0 ~ ("pid=" target) {
                addr=$5; port=addr; sub(/.*:/,"",port)
                if (port ~ /^[0-9]+$/) print port
              }
            ' | sort -n | uniq)
            # Matar proceso
            kill -9 "$pid" 2>/dev/null && echo "[+] Proceso $pid cerrado" && log "Cerrado proceso $pid"
            # Bloquear sus puertos (salvo seguros)
            for p in "${ports[@]}"; do
              if is_safe_port "$p"; then
                echo "[*] Saltando puerto seguro $p"
              else
                block_port "$p" && echo "[+] Puerto $p bloqueado"
              fi
            done
          else
            warn "[!] PID inválido: $pid"
          fi
        done
        log "Red: cierre selectivo + bloqueo aplicado"
        pause
        ;;

      3)
        while true; do
          title "Gestión de puertos bloqueados"
          mapfile -t bl < <(list_blocked_ports)
          if [ "${#bl[@]}" -gt 0 ]; then
            crit "Puertos bloqueados: ${bl[*]}"
          else
            echo "No hay puertos bloqueados."
          fi
          opt 1 "Bloquear uno o varios puertos nuevos"
          opt 2 "Abrir puertos bloqueados"
          opt 3 "Volver"
          case "$(ask_choice 1 3)" in
            1)
              echo "Introduce puertos a BLOQUEAR (ej: 22 80 31337):"
              read -r ports
              for p in $ports; do
                [[ "$p" =~ ^[0-9]+$ ]] || { echo "Puerto inválido: $p"; continue; }
                if is_safe_port "$p"; then
                  echo "[*] Saltando puerto seguro $p"
                else
                  block_port "$p" && echo "[+] Puerto $p bloqueado"
                fi
              done
              ;;
            2)
              mapfile -t bl < <(list_blocked_ports)
              if [ "${#bl[@]}" -eq 0 ]; then echo "No hay puertos bloqueados."; continue; fi
              echo "Escribe puertos a ABRIR (ej: 22 80) o ALL:"
              read -r toopen
              if [[ "$toopen" =~ ^[Aa][Ll][Ll]$ ]]; then
                for p in "${bl[@]}"; do unblock_port "$p" && echo "[+] Puerto $p abierto"; done
              else
                for p in $toopen; do
                  [[ "$p" =~ ^[0-9]+$ ]] || { echo "Puerto inválido: $p"; continue; }
                  unblock_port "$p" && echo "[+] Puerto $p abierto"
                done
              fi
              ;;
            3) break ;;
          esac
        done
        ;;

      4) return ;;
    esac

  else
    ok "[+] No se detectaron conexiones sospechosas."
    local bl_now; bl_now=$(list_blocked_ports | tr '\n' ' ')
    [ -n "$bl_now" ] && crit "Puertos bloqueados: ${bl_now}" || echo "No hay puertos bloqueados."
    opt 1 "Bloquear puertos"
    opt 2 "Abrir puertos"
    opt 3 "Volver"
    case "$(ask_choice 1 3)" in
      1)
        echo "Introduce puertos a BLOQUEAR:"
        read -r ports
        for p in $ports; do
          [[ "$p" =~ ^[0-9]+$ ]] && {
            if is_safe_port "$p"; then
              echo "[*] Saltando puerto seguro $p"
            else
              block_port "$p"; echo "[+] Puerto $p bloqueado"
            fi
          } || echo "Inválido: $p"
        done
        pause
        ;;
      2)
        echo "Introduce puertos a ABRIR (o ALL):"
        read -r toopen
        if [[ "$toopen" =~ ^[Aa][Ll][Ll]$ ]]; then
          mapfile -t bl < <(list_blocked_ports)
          for p in "${bl[@]}"; do unblock_port "$p" && echo "[+] Puerto $p abierto"; done
        else
          for p in $toopen; do
            [[ "$p" =~ ^[0-9]+$ ]] && { unblock_port "$p"; echo "[+] Puerto $p abierto"; } || echo "Inválido: $p"
          done
        fi
        pause
        ;;
      3) return ;;
    esac
    log "Red: OK"
  fi
}

# =============================================================================
# MÓDULO: INTEGRIDAD DE BINARIOS
# =============================================================================

recrear_baseline_algo(){
  local algo="$1" out filecount=0
  case "$algo" in
    sha256sum) out="$BASELINE_SHA" ;;
    md5sum)    out="$BASELINE_MD5" ;;
    *) return 1 ;;
  esac
  # Conjunto de binarios “críticos” (ajustable)
  local bins="
/bin/bash /bin/dash /bin/su /bin/mount
/usr/bin/ls /usr/bin/ps /usr/bin/ss /usr/bin/find /usr/bin/awk /usr/bin/sed /usr/bin/grep /usr/bin/gawk
/usr/bin/sha256sum /usr/bin/md5sum /usr/bin/sudo /usr/bin/ssh /usr/bin/ssh-keygen /usr/bin/systemctl
/usr/sbin/sshd /usr/bin/login /usr/bin/passwd
/usr/lib/systemd/systemd
"
  : > "$out"
  for b in $bins; do
    [ -f "$b" ] || continue
    "$algo" "$b" >> "$out"
    filecount=$((filecount+1))
  done
  ok "[+] Baseline re-creada en $out ($filecount binarios)."
}

# --- Remediación: reinstalar desde apt o extraer del .deb si falla ---
_restore_bin_from_pkg(){
  # $1: ruta binario
  local bin_path="$1" pkg tmpd deb src
  log "[*] Comprobando estado de dpkg/apt..."
  dpkg --configure -a >/dev/null 2>&1 || true
  apt-get -f install -y  >/dev/null 2>&1 || true

  pkg=$(dpkg -S "$bin_path" 2>/dev/null | sed 's/:.*//' | head -n1)
  if [ -n "$pkg" ]; then
    info "[*] [Resolver] Reinstalando paquete ${pkg} para ${bin_path}…"
    if apt-get install --reinstall -y "$pkg" >/dev/null 2>&1; then
      ok "[+] Restaurado desde repos: $pkg ($bin_path)"
      return 0
    fi
    warn "[!] Falló la reinstalación de $pkg. Probando restauración directa del .deb…"
    tmpd="$(mktemp -d)"
    ( cd "$tmpd" && apt-get download "$pkg" >/dev/null 2>&1 ) || true
    deb="$(ls -1 "$tmpd"/*.deb 2>/dev/null | head -n1 || true)"
    if [ -n "$deb" ]; then
      dpkg -x "$deb" "$tmpd/ex" >/dev/null 2>&1 || true
      src="$tmpd/ex/${bin_path#/}"
      if [ -f "$src" ]; then
        install -o root -g root -m 0755 "$src" "$bin_path" && ok "[+] Fichero restaurado desde .deb: $bin_path"
        rm -rf "$tmpd"
        return 0
      else
        warn "[!] No se encontró $bin_path dentro del .deb"
      fi
    else
      warn "[!] No se pudo descargar .deb de $pkg"
    fi
    rm -rf "$tmpd"
  else
    warn "[!] No se encontró paquete dueño de $bin_path"
  fi
  return 1
}

# --- Acción sobre diffs para un ALGORITMO concreto (SHA-256 o MD5) ---
compare_baseline_algo(){
  local algo="$1" file="$2" label="$3"
  [ -f "$file" ] || return 0

  # Ejecutar verificación y quedarnos con fallos (incluye “FAILED open or read”)
  local raw diffs
  raw=$("$algo" -c "$file" 2>/dev/null || true)
  diffs=$(echo "$raw" | grep -v ': OK$' || true)

  title "Integridad de binarios — ${label}"
  if [ -n "$diffs" ]; then
    crit "[!] Binarios no conformes (${label}):"
    # Mostrar rutas limpias (quitar sufijo ': FAILED*')
    echo "$diffs" | sed -E 's/: FAILED.*$//'
    echo
    crit "[?] Se encontraron posibles amenazas en [Integridad de binarios — ${label}]:"
    echo "$diffs"
    echo

    opt 1 "Resolver (reinstalar o restaurar desde .deb) — ${label}"
    opt 2 "Eliminar (mover a cuarentena) — ${label}"
    opt 3 "Ignorar — ${label}"
    opt 4 "Volver — ${label}"
    opt 5 "Salir"

    case "$(ask_choice 1 5)" in
      1)
        # Intentar restaurar cada binario afectado
        while IFS= read -r line; do
          # line puede ser "/ruta: FAILED ..." o "/ruta"
          local bin_path="${line%%:*}"
          # Copia forense previa si existe el fichero
          if [ -f "$bin_path" ]; then
            local dest="$QUAR_DIR/bin$(dirname "$bin_path")"
            mkdir -p "$dest"
            cp -a --preserve=mode,ownership,timestamps "$bin_path" "$dest/" 2>/dev/null || true
            log "[*] Copia forense previa: $bin_path -> $dest/"
          fi
          _restore_bin_from_pkg "$bin_path" || warn "[!] No se pudo restaurar $bin_path"
        done <<< "$(echo "$diffs")"
        # Re-crear baselines tras intentar resolver
        command -v sha256sum >/dev/null 2>&1 && recrear_baseline_algo sha256sum
        recrear_baseline_algo md5sum
        log "Baseline recreada"
        ;;
      2)
        # Mover a cuarentena (si existe)
        while IFS= read -r line; do
          local bin_path="${line%%:*}"
          [ -f "$bin_path" ] || { warn "[!] Ausente: $bin_path (no se puede mover)"; continue; }
          local dest="$QUAR_DIR/bin$(dirname "$bin_path")"
          mkdir -p "$dest"
          mv -f "$bin_path" "$dest/" && ok "[+] Movido a cuarentena: $bin_path -> $dest/"
          log "Cuarentena: $bin_path"
        done <<< "$(echo "$diffs")"
        ;;
      3) : ;;   # Ignorar
      4) return ;;
      5) exit 0 ;;
    esac
  else
    ok "[+] Todos los binarios coinciden con la baseline (${label})."
    log "Integridad binarios: OK (${label})"
  fi
}

check_binaries(){
  info "[*] Verificando integridad de binarios críticos..."
  if [ ! -f "$BASELINE_SHA" ] && [ ! -f "$BASELINE_MD5" ]; then
    warn "[!] No hay baseline. Creando ambas (SHA-256 y MD5)…"
    command -v sha256sum >/dev/null 2>&1 && recrear_baseline_algo sha256sum
    recrear_baseline_algo md5sum
    echo "    (Vuelve a ejecutar para comparar.)"
    pause; return
  fi

  opt 1 "Comparar con baseline (etiquetado por algoritmo)"
  opt 2 "Re-crear baseline (SHA-256 y MD5)"
  opt 3 "Verificar paquetes (dpkg -V)"
  opt 4 "Informe/diagnóstico ampliado"
  opt 5 "Volver"

  case "$(ask_choice 1 5)" in
    1)
      # SHA-256 primero (con su propio menú) y luego MD5 (con su menú),
      # ambos claramente etiquetados para evitar confusión.
      if command -v sha256sum >/dev/null 2>&1 && [ -f "$BASELINE_SHA" ]; then
        compare_baseline_algo sha256sum "$BASELINE_SHA" "SHA-256"
      fi
      if [ -f "$BASELINE_MD5" ]; then
        compare_baseline_algo md5sum "$BASELINE_MD5" "MD5"
      fi
      pause
      ;;
    2)
      command -v sha256sum >/dev/null 2>&1 && recrear_baseline_algo sha256sum
      recrear_baseline_algo md5sum
      log "Baseline recreada"
      pause
      ;;
    3)
      info "[*] Ejecutando dpkg -V (puede tardar)…"
      dpkg -V | sed -n '1,200p' || true
      pause
      ;;
    4)
      info "[*] Resumen:"
      echo "  - Baseline SHA: $BASELINE_SHA $( [ -f "$BASELINE_SHA" ] && echo '(ok)' || echo '(no existe)' )"
      echo "  - Baseline MD5: $BASELINE_MD5 $( [ -f "$BASELINE_MD5" ] && echo '(ok)' || echo '(no existe)' )"
      echo "  - Paquetes que podrían haber cambiado (muestras):"
      dpkg -V | head -n 20 || true
      pause
      ;;
    5) return ;;
  esac
}

# =============================================================================
# MÓDULO: ARCHIVOS SOSPECHOSOS
# =============================================================================
scan_suid_sgid(){
  find "$1" -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null
}
scan_temporales_exec(){
  find /tmp /var/tmp /dev/shm -type f -perm -111 2>/dev/null
}

apply_fs_whitelist(){
  grep -Fvx -f "$FS_WHITELIST" 2>/dev/null || cat
}

fs_menu(){
  title "Archivos sospechosos"
  opt 1 "Escaneo completo CON whitelist"
  opt 2 "Escaneo completo SIN whitelist"
  opt 3 "Escanear directorios seleccionados"
  opt 4 "Ver/editar whitelist"
  opt 5 "Volver"

  local choice; choice="$(ask_choice 1 5)"

  local -a results=()

  case "$choice" in
    1)
      info "[*] Escaneo completo (SUID/SGID en '/', ejecutables en temporales) CON whitelist…"
      mapfile -t results < <(
        { scan_suid_sgid "/" ; scan_temporales_exec ; } \
        | sort -u \
        | grep -Fvx -f "$FS_WHITELIST"
      )
      ;;
    2)
      info "[*] Escaneo completo (SUID/SGID en '/', ejecutables en temporales) SIN whitelist…"
      mapfile -t results < <(
        { scan_suid_sgid "/" ; scan_temporales_exec ; } \
        | sort -u
      )
      ;;
    3)
      echo "Introduce una o varias rutas base separadas por espacios (ej: / /home /opt):"
      read -r bases
      echo "¿Aplicar whitelist? "; opt 1 "Sí"; opt 2 "No"
      if [ "$(ask_choice 1 2)" = "1" ]; then
        mapfile -t results < <(
          for b in $bases; do
            info "[*] Escaneando SUID/SGID en '$b'…"
            scan_suid_sgid "$b"
          done \
          | sort -u \
          | grep -Fvx -f "$FS_WHITELIST"
        )
      else
        mapfile -t results < <(
          for b in $bases; do
            info "[*] Escaneando SUID/SGID en '$b'…"
            scan_suid_sgid "$b"
          done \
          | sort -u
        )
      fi
      ;;
    4)
      title "Whitelist FS"
      nl -ba "$FS_WHITELIST" | sed -n '1,200p'
      echo
      opt 1 "Añadir ruta"
      opt 2 "Eliminar ruta"
      opt 3 "Vaciar whitelist"
      opt 4 "Volver"
      case "$(ask_choice 1 4)" in
        1)
          read -rp "Ruta a añadir: " rr
          [ -n "$rr" ] && { echo "$rr" >> "$FS_WHITELIST"; sort -u -o "$FS_WHITELIST" "$FS_WHITELIST"; log "[+] Añadida."; }
          pause
          ;;
        2)
          read -rp "Ruta exacta a eliminar: " rr
          [ -n "$rr" ] && { grep -Fvx "$rr" "$FS_WHITELIST" > "$FS_WHITELIST.tmp" 2>/dev/null || true; mv -f "$FS_WHITELIST.tmp" "$FS_WHITELIST"; log "[+] Eliminada si existía."; }
          pause
          ;;
        3)
          : > "$FS_WHITELIST"
          log "[+] Whitelist vaciada."
          pause
          ;;
        4) return ;;
      esac
      return
      ;;
    5)
      return
      ;;
  esac

  if [ "${#results[@]}" -eq 0 ]; then
    ok "[+] No se detectaron archivos sospechosos."
    log "Filesystem: OK"
    pause
    return
  fi

  crit "[!] Archivos sospechosos encontrados:"
  for i in "${!results[@]}"; do
    printf "%6s  %s\n" "$((i+1))" "${results[$i]}"
  done

  echo
  info "[?] ¿Qué deseas hacer?"
  opt 1 "Resolver (quitar SUID/SGID)"
  opt 2 "Eliminar (mover a cuarentena)"
  opt 3 "Eliminar (definitivo)"
  opt 4 "Actuar sobre rutas específicas"
  opt 5 "Volver"

  case "$(ask_choice 1 5)" in
    1)
      echo "Introduce índices a RESOLVER (ej: 1 3 7) o ALL:"
      mapfile -t sel < <(ask_indices "${#results[@]}") || { echo "Selección inválida."; pause; return; }
      for id in "${sel[@]}"; do
        f="${results[id-1]}"
        chmod u-s,g-s "$f" 2>/dev/null && ok "[+] Quitado SUID/SGID: $f" && log "Quitado SUID/SGID: $f"
      done
      pause
      ;;
    2)
      echo "Introduce índices a CUARENTENA (ej: 2 4) o ALL:"
      mapfile -t sel < <(ask_indices "${#results[@]}") || { echo "Selección inválida."; pause; return; }
      for id in "${sel[@]}"; do
        f="${results[id-1]}"
        dest="$QUAR_DIR$(dirname "$f")"
        mkdir -p "$dest"
        mv -f "$f" "$dest/" && ok "[+] Movido a cuarentena: $f -> $dest/$(basename "$f")" && log "Cuarentena: $f"
      done
      pause
      ;;
    3)
      echo "Introduce índices a ELIMINAR DEFINITIVO (ej: 5 7) o ALL:"
      mapfile -t sel < <(ask_indices "${#results[@]}") || { echo "Selección inválida."; pause; return; }
      if confirm_yn "Confirmar eliminación definitiva de seleccionados"; then
        for id in "${sel[@]}"; do
          f="${results[id-1]}"
          rm -f -- "$f" && ok "[+] Eliminado definitivamente: $f" && log "Eliminado definitivo: $f"
        done
      fi
      pause
      ;;
    4)
      echo "Introduce índices (ej: 1 3 7) o ALL:"
      mapfile -t sel < <(ask_indices "${#results[@]}") || { echo "Selección inválida."; pause; return; }
      echo "Acción: "; opt 1 "Quitar SUID/SGID"; opt 2 "Cuarentena"; opt 3 "Eliminar (definitivo)"; opt 4 "Añadir a whitelist"; opt 5 "volver";
      case "$(ask_choice 1 4)" in
        1) for id in "${sel[@]}"; do f="${results[id-1]}"; chmod u-s,g-s "$f" 2>/dev/null && ok "[+] Quitado SUID/SGID: $f" && log "Quitado SUID/SGID: $f"; done; pause;;
        2) for id in "${sel[@]}"; do f="${results[id-1]}"; dest="$QUAR_DIR$(dirname "$f")"; mkdir -p "$dest"; mv -f "$f" "$dest/" && ok "[+] Movido a cuarentena: $f -> $dest/" && log "Cuarentena: $f"; done; pause;;
        3) if confirm_yn "Confirmar eliminación definitiva de seleccionados"; then for id in "${sel[@]}"; do f="${results[id-1]}"; rm -f -- "$f" && ok "[+] Eliminado definitivamente: $f" && log "Eliminado definitivo: $f"; done; fi; pause;;
        4) for id in "${sel[@]}"; do f="${results[id-1]}"; echo "$f" >> "$FS_WHITELIST"; done; sort -u -o "$FS_WHITELIST" "$FS_WHITELIST"; ok "[+] Añadidos a whitelist."; log "FS whitelist actualizada"; pause;;

	5) return;;
      esac
      ;;
    5) return ;;
  esac
}

# =============================================================================
# MÓDULO: USUARIOS
# ============================================================================

# --- helpers base ---
_lock_user()        { passwd -l "$1" >/dev/null 2>&1; }
_unlock_user()      { passwd -u "$1" >/dev/null 2>&1; }
_nologin_user()     { chsh -s /usr/sbin/nologin "$1" >/dev/null 2>&1; }
_delete_user() {
  local u="$1"
  pkill -KILL -u "$u" 2>/dev/null || true
  userdel -r -f "$u"
}

_quarantine_user_home() {
  local u="$1" home="$2"
  [ -d "$home" ] || return 0
  local dest="$QUAR_DIR/users/${u}_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$(dirname "$dest")"
  rsync -a --remove-source-files "$home"/ "$dest"/ 2>/dev/null || true
  rmdir "$home" 2>/dev/null || true
  log "[+] HOME de $u trasladado a: $dest"
}

_move_home_to_dest(){
  local home="$1" dest="$2"
  [ -d "$home" ] || return 0
  mkdir -p "$dest"
  rsync -a --remove-source-files "$home"/ "$dest"/ 2>/dev/null || true
  rmdir "$home" 2>/dev/null || true
}

_quarantine_user_full(){
  local u="$1"
  local uid shell home groups ts dest meta
  uid=$(id -u "$u" 2>/dev/null || echo "?")
  shell=$(getent passwd "$u" | awk -F: '{print $7}')
  home=$(getent passwd "$u"  | awk -F: '{print $6}')
  groups=$(id -nG "$u" 2>/dev/null || echo "")
  ts=$(date +%Y%m%d_%H%M%S)
  dest="$QUAR_DIR/users/${u}_${ts}"
  mkdir -p "$dest"

  meta="$dest/.meta"
  {
    echo "user=$u"
    echo "uid=$uid"
    echo "home=$home"
    echo "shell_prev=$shell"
    echo "groups=$groups"
    echo "timestamp=$(date -Is)"
  } > "$meta"

  pkill -KILL -u "$u" 2>/dev/null || true
  if [ "$u" != "root" ]; then
    _lock_user "$u"
    _nologin_user "$u"
  fi

  if [ -f "/var/spool/cron/crontabs/$u" ]; then
    mkdir -p "$dest/cron"
    mv -f "/var/spool/cron/crontabs/$u" "$dest/cron/" 2>/dev/null || true
  fi
  for d in /var/spool/at /var/spool/atjobs; do
    [ -d "$d" ] || continue
    find "$d" -maxdepth 1 -type f -user "$u" -exec mv -f {} "$dest/" \; 2>/dev/null || true
  done

  _move_home_to_dest "$home" "$dest/home"
  log "[+] Usuario $u enviado a CUARENTENA completa (lock + nologin + HOME + cron). Meta: $meta"
}

# --- helpers para auditorías ---
_quar_stamp(){ date +%Y%m%d_%H%M%S; }
_quar_dir_for(){ local sub="$1"; local d="$QUAR_DIR/$sub"; mkdir -p "$d"; echo "$d"; }
_safe_mv_to_quar(){ # $1 ruta, $2 subcarpeta relativa
  local src="$1" sub="$2" ts base dest
  ts="$(_quar_stamp)"; base="$(basename "$src")"
  dest="$(_quar_dir_for "$sub")/${base}.${ts}"
  mv -f -- "$src" "$dest" && log "[+] A cuarentena: $src -> $dest" && echo "$dest"
}

# ---- Auditoría sudoers (con acciones) ----
audit_sudoers(){
  title "Auditoría sudoers"
  info "[*] Usuarios en grupos privilegiados (sudo/admin/wheel):"
  for g in sudo admin wheel; do
    getent group "$g" 2>/dev/null | awk -F: -v grp="$g" '{print "  - " grp ": " ($4==""?"(vacío)":$4)}' | sed 's/,/, /g'
  done
  echo

  mapfile -t NOPA < <(grep -Rni --include='*' -E 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null || true)
  if [ "${#NOPA[@]}" -eq 0 ]; then
    echo "[*] Reglas NOPASSWD: (ninguna encontrada)"
  else
    echo "[*] Reglas NOPASSWD en /etc/sudoers y /etc/sudoers.d/:"
    for i in "${!NOPA[@]}"; do
      printf "  %3d) %s\n" "$((i+1))" "${NOPA[$i]}"
    done
  fi
  echo

  echo "[*] Permisos de ficheros sudoers (esperado: 440 / root:root):"
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    printf "  - %s %s %s:%s\n" "$f" "$(stat -c '%a' "$f")" "$(stat -c '%U' "$f")" "$(stat -c '%G' "$f")"
  done < <(find /etc/sudoers /etc/sudoers.d -maxdepth 1 -type f 2>/dev/null)
  echo

  if command -v visudo >/dev/null 2>&1; then
    echo "[*] Comprobación de sintaxis (visudo -c):"
    visudo -c >/dev/null 2>&1 && echo "  - OK" || echo "  - ERROR de sintaxis"
  fi

  echo
  info "[?] Acciones:"
  opt 1 "Ajustar permisos (chmod 440, chown root:root) en /etc/sudoers*"
  opt 2 "Acciones sobre NOPASSWD (quitar/quarentena de fichero)"
  opt 3 "Validar sintaxis y volver"
  opt 4 "Volver"
  case "$(ask_choice 1 4)" in
    1)
      while IFS= read -r f; do
        [ -f "$f" ] || continue
        chown root:root "$f" 2>/dev/null || true
        chmod 440 "$f" 2>/dev/null || true
        ok "[+] Permisos ajustados: $f"
      done < <(find /etc/sudoers /etc/sudoers.d -maxdepth 1 -type f 2>/dev/null)
      pause
      ;;
    2)
      if [ "${#NOPA[@]}" -eq 0 ]; then echo "(no hay NOPASSWD)"; pause; return; fi
      echo "Introduce índices de líneas NOPASSWD a tratar (ej: 1 3) o ALL:"
      mapfile -t sel < <(ask_indices "${#NOPA[@]}") || { pause; return; }
      info "Acción: "; opt 1 "Mover fichero a cuarentena"; opt 2 "Quitar NOPASSWD (reemplazar línea)"; opt 3 "Volver"
      case "$(ask_choice 1 3)" in
        1)
          for id in "${sel[@]}"; do
            line="${NOPA[id-1]}"; file="${line%%:*}"
            [ -e "$file" ] && _safe_mv_to_quar "$file" "sudoers" >/dev/null
          done
          pause
          ;;
        2)
          files_touched=()
          for id in "${sel[@]}"; do
            line="${NOPA[id-1]}"; file="${line%%:*}"
            files_touched+=("$file")
          done
          mapfile -t uniq_files < <(printf "%s\n" "${files_touched[@]}" | sort -u)
          for f in "${uniq_files[@]}"; do
            [ -f "$f" ] || continue
            if [ "$f" = "/etc/sudoers" ]; then
              tmp="/tmp/sudoers.filtered.$$"
              sed -E 's/[[:space:]]*NOPASSWD:?[[:space:]]*/ /g' "$f" > "$tmp"
              if visudo -c -f "$tmp" >/dev/null 2>&1; then
                _safe_mv_to_quar "$f" "sudoers" >/dev/null
                install -o root -g root -m 0440 "$tmp" "$f"
                ok "[+] NOPASSWD eliminado de /etc/sudoers (validado con visudo)"
              else
                warn "[!] Nuevo sudoers no válido. No se aplican cambios a $f"
              fi
              rm -f "$tmp"
            else
              bak_dir="$(_quar_dir_for "sudoers")"
              cp -a "$f" "$bak_dir/$(basename "$f").$(_quar_stamp).bak"
              sed -E -i 's/[[:space:]]*NOPASSWD:?[[:space:]]*/ /g' "$f"
              chmod 440 "$f"; chown root:root "$f"
              if ! visudo -c >/dev/null 2>&1; then
                warn "[!] WARNING: cambios en $f podrían ser inválidos (visudo -c falla). Revisa manualmente."
              else
                ok "[+] NOPASSWD eliminado en $f"
              fi
            fi
          done
          pause
          ;;
        3) : ;;
      esac
      ;;
    3)
      if command -v visudo >/dev/null 2>&1; then
        visudo -c && echo "OK" || echo "ERROR"
      fi
      pause
      ;;
    4) return ;;
  esac
}

# ---- Revisión de claves SSH (con acciones) ----
audit_ssh_keys(){
  title "Revisión de claves SSH (authorized_keys)"
  local USERS_WITH_KEYS=() AK_PATHS=()

  while IFS=: read -r user _ uid _ _ home shell; do
    [ -n "$home" ] && [ -d "$home" ] || continue
    local ak="$home/.ssh/authorized_keys"
    if [ -f "$ak" ]; then
      USERS_WITH_KEYS+=("$user")
      AK_PATHS+=("$ak")
      echo "Usuario: $user"
      printf "  ~/.ssh perms: "; stat -c "%a (%A)" "$home/.ssh" 2>/dev/null || echo "?"
      printf "  authorized_keys perms: "; stat -c "%a (%A)" "$ak" 2>/dev/null || echo "?"
      echo "  líneas en authorized_keys: $(wc -l < "$ak" 2>/dev/null || echo 0)"
      if command -v ssh-keygen >/dev/null 2>&1; then
        echo "  huellas:"
        awk '{if ($1 ~ /^ssh-|^ecdsa-|^ed25519/) print NR":"$0}' "$ak" 2>/dev/null \
          | while IFS= read -r L; do
              num="${L%%:*}"; key="${L#*:}"
              echo "$key" | ssh-keygen -lf - 2>/dev/null | sed "s/^/    [${num}] /"
            done
      fi
      echo
    fi
  done < /etc/passwd

  if [ "${#USERS_WITH_KEYS[@]}" -eq 0 ]; then
    echo "(no se encontraron authorized_keys)"
    pause
    return
  fi

  info "[?] Acciones sobre claves:"
  opt 1 "Eliminar líneas específicas de authorized_keys"
  opt 2 "Enviar authorized_keys a cuarentena (vaciar después)"
  opt 3 "Corregir permisos de ~/.ssh y authorized_keys"
  opt 4 "Volver"
  case "$(ask_choice 1 4)" in
    1)
      echo "Elige usuario por índice:"
      for i in "${!USERS_WITH_KEYS[@]}"; do
        printf "  %d) %s  -> %s\n" "$((i+1))" "${USERS_WITH_KEYS[$i]}" "${AK_PATHS[$i]}"
      done
      idx="$(ask_choice 1 ${#USERS_WITH_KEYS[@]})"
      u="${USERS_WITH_KEYS[$((idx-1))]}"; ak="${AK_PATHS[$((idx-1))]}"
      echo "Introduce números de línea a eliminar (como en el listado de huellas) o ALL:"
      read -r lines
      if [[ "$lines" =~ ^[Aa][Ll][Ll]$ ]]; then
        _safe_mv_to_quar "$ak" "ssh/$u" >/dev/null
        : > "$ak"
        ok "[+] authorized_keys vaciado para $u"
      else
        for n in $lines; do
          [[ "$n" =~ ^[0-9]+$ ]] && sed -i "${n}d" "$ak"
        done
        ok "[+] Eliminadas líneas seleccionadas en $ak"
      fi
      pause
      ;;
    2)
      echo "Elige usuario por índice:"
      for i in "${!USERS_WITH_KEYS[@]}"; do
        printf "  %d) %s  -> %s\n" "$((i+1))" "${USERS_WITH_KEYS[$i]}" "${AK_PATHS[$i]}"
      done
      idx="$(ask_choice 1 ${#USERS_WITH_KEYS[@]})"
      u="${USERS_WITH_KEYS[$((idx-1))]}"; ak="${AK_PATHS[$((idx-1))]}"
      _safe_mv_to_quar "$ak" "ssh/$u" >/dev/null
      : > "$ak"
      chown "$u:$u" "$ak" 2>/dev/null || true
      chmod 600 "$ak" 2>/dev/null || true
      ok "[+] $ak enviado a cuarentena y vaciado"
      pause
      ;;
    3)
      echo "Elige usuario por índice:"
      for i in "${!USERS_WITH_KEYS[@]}"; do
        printf "  %d) %s  -> %s\n" "$((i+1))" "${USERS_WITH_KEYS[$i]}" "${AK_PATHS[$i]}"
      done
      idx="$(ask_choice 1 ${#USERS_WITH_KEYS[@]})"
      u="${USERS_WITH_KEYS[$((idx-1))]}"; ak="${AK_PATHS[$((idx-1))]}"
      sshdir="$(dirname "$ak")"
      chmod 700 "$sshdir" 2>/dev/null || true
      chmod 600 "$ak" 2>/dev/null || true
      chown -R "$u:$u" "$sshdir" 2>/dev/null || true
      ok "[+] Permisos corregidos para $u"
      pause
      ;;
    4) return ;;
  esac
}

# ---- UID duplicados (con acciones) ----
audit_duplicate_uids(){
  title "Usuarios con UID duplicado"
  mapfile -t PAIRS < <(
    awk -F: '{print $3"\t"$1"\t"$6"\t"$7}' /etc/passwd \
      | sort -n \
      | awk '{
          cnt[$1]++; users[$1]=(users[$1]?users[$1]","$2:$2);
        }
        END{for (u in cnt) if (cnt[u]>1) print u"\t"users[u]}'
  )
  if [ "${#PAIRS[@]}" -eq 0 ]; then
    echo "  (ningún UID duplicado)"
    pause
    return
  fi

  for i in "${!PAIRS[@]}"; do
    uid="${PAIRS[$i]%%$'\t'*}"
    users="${PAIRS[$i]#*$'\t'}"
    printf "  %2d) UID %s: %s\n" "$((i+1))" "$uid" "$users"
  done

  echo
  info "[?] Acciones:"
  opt 1 "Bloquear usuarios de un UID duplicado"
  opt 2 "Cambiar UID de usuario(s) (usermod -u)"
  opt 3 "Enviar usuario(s) a cuarentena completa"
  opt 4 "Volver"
  case "$(ask_choice 1 4)" in
    1)
      echo "Elige grupo por índice (UID duplicado):"
      grp_idx="$(ask_choice 1 ${#PAIRS[@]})"
      sel_uid="$(echo "${PAIRS[$((grp_idx-1))]}" | cut -f1)"
      users_csv="$(echo "${PAIRS[$((grp_idx-1))]}" | cut -f2-)"
      IFS=',' read -r -a arr <<< "$users_csv"
      echo "Selecciona usuarios a BLOQUEAR (por nombre, espacios) o ALL:"
      echo "  Usuarios: ${arr[*]}"
      read -r pick
      [[ "$pick" =~ ^[Aa][Ll][Ll]$ ]] && pick="${arr[*]}"
      for u in $pick; do
        [ "$u" = "root" ] && { warn "[!] Saltando root."; continue; }
        _lock_user "$u" && log "[+] $u bloqueado."
      done
      pause
      ;;
    2)
      echo "Elige grupo por índice (UID duplicado):"
      grp_idx="$(ask_choice 1 ${#PAIRS[@]})"
      users_csv="$(echo "${PAIRS[$((grp_idx-1))]}" | cut -f2-)"
      IFS=',' read -r -a arr <<< "$users_csv"
      echo "Usuarios en este UID: ${arr[*]}"
      echo "Introduce pares \"usuario:nuevoUID\" separados por espacios (ej: hacker1:2001 prueba:2002):"
      read -r pairs
      for p in $pairs; do
        u="${p%%:*}"; newuid="${p##*:}"
        [[ "$u" = "root" ]] && { warn "[!] Saltando root."; continue; }
        [[ "$newuid" =~ ^[0-9]+$ ]] || { warn "[!] UID inválido: $newuid"; continue; }
        oldhome="$(getent passwd "$u" | awk -F: '{print $6}')"
        if usermod -u "$newuid" "$u" 2>/dev/null; then
          [ -d "$oldhome" ] && chown -R "$u:$u" "$oldhome" 2>/dev/null || true
          log "[+] $u -> UID $newuid"
        else
          warn "[!] Falló usermod para $u"
        fi
      done
      pause
      ;;
    3)
      echo "Elige grupo por índice (UID duplicado):"
      grp_idx="$(ask_choice 1 ${#PAIRS[@]})"
      users_csv="$(echo "${PAIRS[$((grp_idx-1))]}" | cut -f2-)"
      IFS=',' read -r -a arr <<< "$users_csv"
      echo "Selecciona usuarios a CUARENTENA COMPLETA (por nombre, espacios) o ALL:"
      echo "  Usuarios: ${arr[*]}"
      read -r pick
      [[ "$pick" =~ ^[Aa][Ll][Ll]$ ]] && pick="${arr[*]}"
      for u in $pick; do
        [ "$u" = "root" ] && { warn "[!] Saltando root."; continue; }
        _quarantine_user_full "$u"
      done
      pause
      ;;
    4) return ;;
  esac
}

# ---- Menú principal de USUARIOS ----
check_users() {
  log "[*] Escaneando cuentas de usuario…"

  # AVISO BLANDO: detectar UID=0 no-root (p.ej., 'rootkit') sin bloquear el módulo
  if getent passwd rootkit >/dev/null 2>&1; then
    rk_uid="$(getent passwd rootkit | awk -F: '{print $3}')"
    if [ "$rk_uid" = "0" ]; then
      echo -e "${RED}[ALERTA] Detectado usuario 'rootkit' con UID=0.${NC}"
      echo -e "${YELLOW}Se permitirán listados y acciones sobre otras cuentas, pero se bloquearán cambios sobre cuentas UID=0 (no-root).${NC}"
    fi
  fi

  title "Usuarios"
  opt 1 "Con whitelist"
  opt 2 "Sin whitelist"
  opt 3 "Comprobar baselines (MD5 + SHA256)"
  opt 4 "Recrear baselines (MD5 + SHA256)"
  opt 5 "Auditoría sudoers"
  opt 6 "Revisión de claves SSH"
  opt 7 "Usuarios con UID duplicado"
  opt 8 "Enviar USUARIO a cuarentena (lock + nologin + HOME)"
  opt 9 "Volver"
  local sel; sel="$(ask_choice 1 9)"

  case "$sel" in
    3)
      command -v sha256sum >/dev/null 2>&1 && compare_baseline_algo sha256sum "$BASELINE_SHA" "SHA-256"
      compare_baseline_algo md5sum "$BASELINE_MD5" "MD5"
      pause; return ;;
    4)
      command -v sha256sum >/dev/null 2>&1 && recrear_baseline_algo sha256sum
      recrear_baseline_algo md5sum
      log "Baseline recreada (invocada desde Usuarios)"
      pause; return ;;
    5) audit_sudoers; return ;;
    6) audit_ssh_keys; return ;;
    7) audit_duplicate_uids; return ;;
    8)
      read -rp "Usuario a enviar a CUARENTENA COMPLETA: " QUSER
      if [ -n "$QUSER" ]; then
        if [ "$QUSER" = "root" ]; then
          warn "[!] Saltando root."
        else
          q_uid="$(id -u "$QUSER" 2>/dev/null || echo 99999)"
          if [ "$q_uid" = "0" ]; then
            warn "[!] $QUSER tiene UID=0. Cuarentena completa bloqueada por seguridad."
          else
            _quarantine_user_full "$QUSER"
          fi
        fi
      else
        warn "[!] Usuario inválido."
      fi
      pause; return ;;
    9) return ;;
  esac

  local mode
  case "$sel" in
    1) mode="1" ;; 2) mode="2" ;;
    *) return ;;
  esac

  mapfile -t WL_USERS < <(grep -Ev '^\s*(#|$)' "$USERS_WHITELIST" 2>/dev/null || true)
  mapfile -t VALID_SHELLS < <(grep -Ev '^\s*(#|$)' /etc/shells 2>/dev/null || true)

  local USERS=() UIDS=() HOMES=() SHELLS=() REASONS=()

  while IFS=: read -r user pass uid gid gecos home shell; do
    if [ "$mode" = "1" ] && printf '%s\n' "${WL_USERS[@]}" | grep -qx "$user"; then
      continue
    fi
    reasons=()

    if [ "$uid" -eq 0 ] && [ "$user" != "root" ]; then
      reasons+=("UID=0 (cuenta con privilegios máximos)")
    fi

    if [ -n "$home" ] && [ -d "$home" ]; then
      owner="$(stat -c '%U' "$home" 2>/dev/null || echo "?")"
      if [ "$owner" != "$user" ] && [ "$owner" != "root" ]; then
        reasons+=("HOME pertenece a $owner")
      fi
      perms="$(stat -c '%A' "$home" 2>/dev/null || echo "")"
      echo "$perms" | grep -q "...w....w" && reasons+=("HOME writable por otros")
      id -nG "$user" 2>/dev/null | grep -Eq '\b(root|sudo|adm)\b' && echo "$perms" | grep -q "w" && reasons+=("HOME writable por grupos privilegiados: $(id -nG "$user" 2>/dev/null)")
    else
      reasons+=("HOME no existe: $home")
    fi

    if [ -z "$shell" ] || ! printf '%s\n' "${VALID_SHELLS[@]}" | grep -qx "$shell"; then
      reasons+=("shell no registrada: ${shell:-<vacía>}")
    fi

    if [ "$uid" -lt 1000 ] && printf '%s' "$shell" | grep -qE '/(bash|zsh|sh)$'; then
      reasons+=("UID<1000 con shell interactiva")
    fi

    if [ "${#reasons[@]}" -eq 0 ]; then
      USERS+=("$user"); UIDS+=("$uid"); HOMES+=("$home"); SHELLS+=("$shell"); REASONS+=("OK")
    else
      USERS+=("$user"); UIDS+=("$uid"); HOMES+=("$home"); SHELLS+=("$shell"); REASONS+=("$(IFS=' '; echo "${reasons[*]}")")
    fi
  done < /etc/passwd

  if [ "${#USERS[@]}" -eq 0 ]; then
    ok "[+] No hay usuarios para mostrar con el criterio seleccionado."
    log "Usuarios: listado vacío (criterio/whitelist)"
    pause
    return
  fi

  local tmpfile; tmpfile="$(mktemp)"; local ORDERED_IDX=() ROW=0
  for i in "${!USERS[@]}"; do
    score=0
    uid="${UIDS[$i]}"; shell="${SHELLS[$i]}"; reasons="${REASONS[$i]}"
    echo "$reasons" | grep -q "UID=0" && score=$((score+100))
    [ "$uid" -lt 1000 ] && echo "$shell" | grep -qE '/(bash|zsh|sh)$' && score=$((score+50))
    echo "$reasons" | grep -q "shell no registrada" && score=$((score+20))
    echo "$reasons" | grep -Eq "HOME (no existe|writable|pertenece)" && score=$((score+10))
    printf "%04d\t%d\n" "$((9999-score))" "$i" >> "$tmpfile"
  done

  # Cabecera en rojo y 'OK' en verde
  printf "${RED}%-4s %-18s %-6s %-36s %-24s %s${NC}\n" "ID" "USUARIO" "UID" "HOME" "SHELL" "MOTIVOS"
  while read -r _ idx; do
    motivos="${REASONS[$idx]}"
    if [[ "$motivos" == "OK" ]]; then
      motivos="${GREEN}OK${NC}"
    elif echo "$motivos" | grep -qE 'UID=0|shell no registrada|HOME no existe'; then
      motivos="${RED}${motivos}${NC}"
    elif echo "$motivos" | grep -qE 'writable|pertenece|UID<1000 con shell interactiva'; then
      motivos="${YELLOW}${motivos}${NC}"
    fi

    printf "%-4s %-18s %-6s %-36s %-24s %b\n" \
      "$((++ROW))" \
      "${USERS[$idx]}" \
      "${UIDS[$idx]}" \
      "$(printf '%.36s' "${HOMES[$idx]}")" \
      "$(printf '%.24s' "${SHELLS[$idx]}")" \
      "$motivos"

    ORDERED_IDX+=("$idx")
  done < <(sort "$tmpfile")
  rm -f "$tmpfile"

  echo
  info "[?] ¿Qué deseas hacer?"
  opt 1 "Bloquear (passwd -l)"
  opt 2 "Desbloquear (passwd -u)"
  opt 3 "Cambiar shell a nologin"
  opt 4 "Enviar HOME a cuarentena"
  opt 5 "Eliminar usuario (-r)"
  opt 6 "Añadir usuarios a whitelist"
  opt 7 "Ver/editar whitelist"
  opt 8 "Enviar USUARIO a cuarentena (lock + nologin + HOME)"
  opt 9 "Volver"
  case "$(ask_choice 1 9)" in
    1)
      echo "Índices a BLOQUEAR (ALL o ej: 1 3):"
      mapfile -t sel < <(ask_indices "${#USERS[@]}") || { pause; return; }
      for id in "${sel[@]}"; do
        u="${USERS[${ORDERED_IDX[$((id-1))]}]}"
        [[ "$u" == "root" ]] && { warn "[!] Saltando root."; continue; }
        u_uid="$(id -u "$u" 2>/dev/null || echo 99999)"
        [ "$u_uid" = "0" ] && { warn "[!] $u tiene UID=0. Bloqueo cancelado."; continue; }
        _lock_user "$u" && log "[+] $u bloqueada."
      done
      pause;;
    2)
      echo "Índices a DESBLOQUEAR (ALL o ej: 1 3):"
      mapfile -t sel < <(ask_indices "${#USERS[@]}") || { pause; return; }
      for id in "${sel[@]}"; do
        u="${USERS[${ORDERED_IDX[$((id-1))]}]}"
        _unlock_user "$u" && log "[+] $u desbloqueada."
      done
      pause;;
    3)
      echo "Índices para poner shell /usr/sbin/nologin (ALL o ej: 1 3):"
      mapfile -t sel < <(ask_indices "${#USERS[@]}") || { pause; return; }
      for id in "${sel[@]}"; do
        u="${USERS[${ORDERED_IDX[$((id-1))]}]}"
        [[ "$u" == "root" ]] && { warn "[!] Saltando root."; continue; }
        u_uid="$(id -u "$u" 2>/dev/null || echo 99999)"
        [ "$u_uid" = "0" ] && { warn "[!] $u tiene UID=0. Cambio de shell cancelado."; continue; }
        _nologin_user "$u" && log "[+] $u -> shell nologin."
      done
      pause;;
    4)
      echo "Índices para CUARENTENA de HOME (ALL o ej: 1 3):"
      mapfile -t sel < <(ask_indices "${#USERS[@]}") || { pause; return; }
      for id in "${sel[@]}"; do
        idxu="${ORDERED_IDX[$((id-1))]}"
        u="${USERS[$idxu]}"; h="${HOMES[$idxu]}"
        [[ "$u" == "root" ]] && { warn "[!] Saltando root."; continue; }
        u_uid="$(id -u "$u" 2>/dev/null || echo 99999)"
        [ "$u_uid" = "0" ] && { warn "[!] $u tiene UID=0. Cuarentena de HOME cancelada."; continue; }
        _quarantine_user_home "$u" "$h"
      done
      pause;;
    5)
      echo "Índices a ELIMINAR (-r) (ALL o ej: 1 3):"
      mapfile -t sel < <(ask_indices "${#USERS[@]}") || { pause; return; }
      for id in "${sel[@]}"; do
        u="${USERS[${ORDERED_IDX[$((id-1))]}]}"
        [[ "$u" == "root" ]] && { warn "[!] Saltando root."; continue; }
        u_uid="$(id -u "$u" 2>/dev/null || echo 99999)"
        if [ "$u_uid" = "0" ]; then
          warn "[!] $u tiene UID=0. Eliminación bloqueada por seguridad."
          info  "    Desprivilegia fuera del script (modo rescate) y reintenta."
          continue
        fi
        if confirm_yn "Confirmar eliminación de $u (-r)"; then
          if _delete_user "$u"; then
            ok "[+] Usuario $u eliminado (con -r)."
            log "[+] $u eliminado (con -r)."
          else
            crit "[!] No se pudo eliminar $u."
            info "Sugerencia: usa opción 8 (Cuarentena completa) y vuelve a intentar, o ejecuta: userdel -r -f $u"
          fi
        fi
      done
      pause;;
    6)
      echo "Índices para AÑADIR a whitelist (ALL o ej: 2 5):"
      mapfile -t sel < <(ask_indices "${#USERS[@]}") || { pause; return; }
      for id in "${sel[@]}"; do
        u="${USERS[${ORDERED_IDX[$((id-1))]}]}"
        echo "$u" >> "$USERS_WHITELIST"
      done
      sort -u -o "$USERS_WHITELIST" "$USERS_WHITELIST"
      log "[+] Usuarios añadidos a whitelist."
      pause;;
    7)
      title "Whitelist de usuarios"
      nl -ba "$USERS_WHITELIST" | sed -n '1,200p'
      echo
      opt 1 "Añadir usuario"
      opt 2 "Eliminar usuario"
      opt 3 "Vaciar whitelist"
      opt 4 "Volver"
      case "$(ask_choice 1 4)" in
        1) read -rp "Usuario a añadir: " uu; [ -n "$uu" ] && { echo "$uu" >> "$USERS_WHITELIST"; sort -u -o "$USERS_WHITELIST" "$USERS_WHITELIST"; log "[+] Añadido."; } ; pause;;
        2) read -rp "Usuario a eliminar: " uu; [ -n "$uu" ] && { grep -vx "$uu" "$USERS_WHITELIST" > "$USERS_WHITELIST.tmp" 2>/dev/null || true; mv -f "$USERS_WHITELIST.tmp" "$USERS_WHITELIST"; log "[+] Eliminado si existía."; } ; pause;;
        3) : > "$USERS_WHITELIST"; log "[+] Whitelist vaciada."; pause;;
        4) : ;;
      esac
      ;;
    8)
      echo "Índices a CUARENTENA COMPLETA (ALL o ej: 1 3):"
      mapfile -t sel < <(ask_indices "${#USERS[@]}") || { pause; return; }
      for id in "${sel[@]}"; do
        u="${USERS[${ORDERED_IDX[$((id-1))]}]}"
        [[ "$u" == "root" ]] && { warn "[!] Saltando root."; continue; }
        u_uid="$(id -u "$u" 2>/dev/null || echo 99999)"
        [ "$u_uid" = "0" ] && { warn "[!] $u tiene UID=0. Cuarentena completa cancelada."; continue; }
        _quarantine_user_full "$u"
      done
      pause;;
    9) return;;
  esac
}

# =============================================================================
# MÓDULO: CUARENTENA
# =============================================================================
quarantine_menu(){
  title "Cuarentena"
  opt 1 "Listar elementos"
  opt 2 "Restaurar ruta(s)"
  opt 3 "Eliminar DEFINITIVO ruta(s)"
  opt 4 "Vaciar cuarentena"
  opt 5 "Restaurar USUARIO (rápido, sin .meta)"
  opt 6 "Volver"
  case "$(ask_choice 1 6)" in
    1)
      info "[*] Contenido de $QUAR_DIR:"
      find "$QUAR_DIR" -mindepth 1 -print 2>/dev/null | sed -n '1,200p' || true
      pause
      ;;
    2)
      echo "Introduce ruta(s) completas dentro de cuarentena a restaurar (espacios):"
      read -r rr
      for p in $rr; do
        rel="${p#$QUAR_DIR}"
        [ "$rel" = "$p" ] && { echo "Ruta fuera de cuarentena: $p"; continue; }
        target="/$rel"
        if [ -e "$target" ]; then
          if ! confirm_yn "El destino $target ya existe. ¿Sobrescribir?"; then
            echo "[*] Saltando $p"
            continue
          fi
          rm -rf -- "$target"
        fi
        mkdir -p "$(dirname "$target")"
        mv -f "$p" "$target" && ok "[+] Restaurado: $p -> $target" && log "Restaurado: $target"
      done
      pause
      ;;
    3)
      echo "Introduce ruta(s) completas dentro de cuarentena a ELIMINAR definitivamente:"
      read -r rr
      if confirm_yn "Confirmar borrado definitivo"; then
        for p in $rr; do
          rm -rf -- "$p" && ok "[+] Eliminado: $p" && log "Cuarentena eliminado: $p"
        done
      fi
      pause
      ;;
    4)
      if confirm_yn "Vaciar TODO $QUAR_DIR"; then
        rm -rf "$QUAR_DIR"/* 2>/dev/null
        ok "[+] Cuarentena vaciada."
        log "Cuarentena vaciada"
      fi
      pause
      ;;
    5)
      echo "Introduce el NOMBRE del usuario a restaurar:"
      read -r user
      echo "Introduce la ruta a su carpeta en cuarentena (ej: $QUAR_DIR/users/${user}_YYYYmmdd_HHMMSS/home):"
      read -r src_home
      dest_home="/home/$user"

      if id "$user" >/dev/null 2>&1; then
        info "[*] El usuario $user ya existe, restaurando HOME..."
        passwd -u "$user" >/dev/null 2>&1 || true
        chsh -s /bin/bash "$user" 2>/dev/null || true
      else
        info "[*] Creando usuario $user..."
        useradd -m -d "$dest_home" -s /bin/bash "$user"
      fi

      if [ -d "$src_home" ]; then
        rsync -a "$src_home"/ "$dest_home"/ 2>/dev/null || true
        chown -R "$user":"$user" "$dest_home" 2>/dev/null || true
        ok "[+] HOME restaurado: $dest_home"
        log "Usuario $user restaurado desde $src_home"
      else
        warn "[!] No se encontró $src_home"
      fi
      pause
      ;;
    6) return ;;
  esac
}

# =============================================================================
# ESCANEOS
# =============================================================================
scan_all() {
  check_processes
  check_network
  check_binaries
  fs_menu
  check_users
  log "=== Escaneo completo finalizado ==="
  pause
}

scan_individual() {
  while true; do
    title "Escaneo Individual"
    opt 1 "Procesos"
    opt 2 "Conexiones de red"
    opt 3 "Integridad de binarios"
    opt 4 "Archivos sospechosos"
    opt 5 "Usuarios"
    opt 6 "Volver al menú principal"
    opt 7 "Salir"
    case "$(ask_choice 1 7)" in
      1) check_processes ;;
      2) check_network ;;
      3) check_binaries ;;
      4) fs_menu ;;
      5) check_users ;;
      6) return ;;
      7) exit 0 ;;
    esac
  done
}

# =============================================================================
# MENÚ PRINCIPAL
# =============================================================================
main_menu() {
  while true; do
    title "Análisis Rootkits"
    opt 1 "Escaneo completo"
    opt 2 "Escaneo individual"
    opt 3 "Cuarentena"
    opt 4 "Salir"
    case "$(ask_choice 1 4)" in
      1) scan_all ;;
      2) scan_individual ;;
      3) quarantine_menu ;;
      4) exit 0 ;;
    esac
  done
}

# === Inicio ===
main_menu
