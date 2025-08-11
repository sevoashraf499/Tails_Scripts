#!/bin/bash

# ============================
#  Tor & File Guardian Tool
# ============================

set -euo pipefail

# Define modes
MODE=""
FILE=""

# Unified required tools list
REQUIRED_PKGS=(
  ss zenity notify-send pulseaudio-utils nftables firejail 
  strace tcpdump inotify-tools mat2 bubblewrap xclip gedit less nano 
  eog ristretto evince zathura cat more
)

# ==============================
# 📦 Auto-install all packages
# ==============================
for pkg in "${REQUIRED_PKGS[@]}"; do
  if ! command -v "$pkg" &> /dev/null; then
    echo "📦 Installing missing package: $pkg"
    sudo apt update && sudo apt install -y "$pkg"
  fi
done

# ==============================
# 🔧 Ask user for operation mode
# ==============================
MODE=$(zenity --list --title="Guardian Mode" \
  --text="Select operation mode:" \
  --column="Mode" "Open Tor Browser" "Open File in Sandbox")

# ==============================
# 🚀 TOR BROWSER MODE
# ==============================
if [[ "$MODE" == "Open Tor Browser" ]]; then

NFT_FILE="$HOME/.config/firejail/onlytor.nft"

if [ ! -f "$NFT_FILE" ]; then
  echo "🔥 Netfilter file not found! Creating one..."
  mkdir -p "$(dirname "$NFT_FILE")"
  cat <<EOF > "$NFT_FILE"
table inet filter {
  chain output {
    type filter hook output priority 0;
    policy drop;
    ip daddr != 127.0.0.1 tcp dport != 9050 drop
    ip6 daddr != ::1 drop
    meta l4proto != tcp drop
    meta l4proto != udp drop
  }
}
EOF
fi

sudo nft -f "$NFT_FILE"

xclip -selection clipboard /dev/null || true
sudo modprobe -r uvcvideo snd_usb_audio usb_storage usbhid 2>/dev/null || true

bwrap --ro-bind / / \
      --dev /dev \
      --proc /proc \
      --tmpfs /proc \
      --tmpfs /tmp \
      --unshare-all \
      --new-session \
      firejail --noprofile --net=tor \
        --private \
        --private-dev \
        --nosound \
        --no3d \
        --x11=none \
        --caps.drop=all \
        --disable-mnt \
        --protocol=inet,inet6 \
        --blacklist=/home \
        --blacklist=/dev/snd \
        --name=tor \
        --nogroups \
        --seccomp \
        --nonewprivs \
        --nodbus \
        --notv \
        --noexec=/tmp \
        --noexec=/dev/shm \
        --read-only=/etc/resolv.conf \
        --env=TZ=UTC \
        --env=LANG=en_US.UTF-8 \
        --rlimit-fsize=1000000 \
        --rlimit-nofile=64 \
        --rlimit-nproc=20 \
        --unset=LD_PRELOAD \
        --unset=HTTP_PROXY \
        --unset=ALL_PROXY \
        --seccomp.drop=mmap,mprotect \
        ~/.local/share/torbrowser/tbb/x86_64/tor-browser_en-US/Browser/start-tor-browser --detach &

(
  LOGFILE="/tmp/tor_guardian.log"
  touch "$LOGFILE"
  INCIDENT_LOG="$HOME/tor_incidents.log"

  function check_leaks() {
    ss -tunp | awk '/ESTABLISHED/ && $5 !~ /127.0.0.1|::1/ {print}' >> "$LOGFILE"
  }

  while true; do
    check_leaks

    if [ -s "$LOGFILE" ]; then  
      TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

      if [ -n "$DISPLAY" ]; then
        notify-send "⚠️ Suspicious Traffic Detected" "Non-Tor connection found!"
        zenity --warning --text="Some apps may be leaking your IP! Check $LOGFILE" --width=300
        paplay /usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga &>/dev/null &
      fi

      echo "[$TIMESTAMP] 🚨 Non-Tor traffic detected!" >> "$INCIDENT_LOG"
      cat "$LOGFILE" >> "$INCIDENT_LOG"
      echo "----------------------------------------" >> "$INCIDENT_LOG"

      > "$LOGFILE"
    fi
    sleep 10
  done
) &

exit 0
fi

# ==============================
# 🗂️ FILE SANDBOX MODE
# ==============================
if [[ "$MODE" == "Open File in Sandbox" ]]; then
  FILE=$(zenity --file-selection --title="Select File to Open Securely")

  if [ -z "$FILE" ]; then
    echo "❌ No file selected. Exiting."
    exit 1
  fi

  LOG_DIR="$(mktemp -d /tmp/fsb_logs_XXXXXX)"
  BASENAME=$(basename "$FILE")
  TIMESTAMP=$(date +%Y%m%d_%H%M%S)
  MONITOR_LOG="$LOG_DIR/monitor_${BASENAME}_$TIMESTAMP.log"
  STRACE_LOG="$LOG_DIR/strace_${BASENAME}_$TIMESTAMP.log"
  TCPDUMP_LOG="$LOG_DIR/net_${BASENAME}_$TIMESTAMP.pcap"
  touch "$MONITOR_LOG" "$STRACE_LOG"

  mat2 -s "$FILE"
  xclip -selection clipboard /dev/null || true

  (
    while true; do
      inotifywait -q -e modify,open,attrib,delete_self,move_self "$FILE" >> "$MONITOR_LOG"
      if [ -s "$MONITOR_LOG" ]; then
        TS=$(date +%Y%m%d_%H%M%S)
        ALERT_FILE="$LOG_DIR/file_alert_$TS.log"
        cp "$MONITOR_LOG" "$ALERT_FILE"
        if [ -n "$DISPLAY" ]; then
          paplay /usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga &
          notify-send "🚨 File Changed" "See $ALERT_FILE"
          zenity --warning --text="Suspicious file change detected!\nSee: $ALERT_FILE" --width=300
        fi
      fi
      sleep 5
    done
  ) &
  MON_PID=$!

  sudo timeout 180 tcpdump -i any -w "$TCPDUMP_LOG" not port 9050 and not port 53 and not dst net 127.0.0.0/8 and not dst net ::1 > /dev/null 2>&1 &
  TCP_PID=$!

  ALLOWED_APPS=(gedit less nano eog ristretto evince zathura cat more)
  FILETYPE=$(xdg-mime query filetype "$FILE")
  APP=""
  for candidate in "${ALLOWED_APPS[@]}"; do
    if command -v "$candidate" &> /dev/null; then
      APP="$candidate"
      break
    fi
  done

  if [ -z "$APP" ]; then
    echo "❌ No safe viewer found!"
    kill "$MON_PID" "$TCP_PID"
    exit 1
  fi

  strace -f -e trace=process,execve,clone,fork,vfork,open,connect,ptrace -o "$STRACE_LOG" \
    bwrap --ro-bind / / \
          --dev /dev \
          --proc /proc \
          --tmpfs /proc/self/status \
          --tmpfs /tmp \
          --unshare-all \
          --new-session \
          firejail --noprofile \
            --net=none \
            --seccomp \
            --seccomp.drop=socket,connect,accept,accept4,listen,bind,execve,execveat,ptrace,fork,vfork,clone,kill,tkill,tgkill,open_by_handle_at,fanotify_init,fanotify_mark,process_vm_readv,process_vm_writev,reboot,delete_module,init_module,finit_module,unshare,mmap,mprotect \
            --private \
            --no3d \
            --nosound \
            --x11=none \
            --caps.drop=all \
            --disable-mnt \
            --private-dev \
            --nogroups \
            --nonewprivs \
            --noexec=/tmp \
            --noexec=/dev/shm \
            --blacklist=/home \
            --whitelist="$FILE" \
            --read-only="$FILE" \
            --rlimit-fsize=1000000 \
            --rlimit-nofile=64 \
            --rlimit-nproc=20 \
            --name=fileviewer \
            "$APP" "$FILE"

  trap 'kill "$MON_PID" "$TCP_PID"' EXIT

  dmesg | tail -n 30 >> "$LOG_DIR/dmesg_after_$TIMESTAMP.log"

  echo -e "\n📜 Monitoring Results for $FILE"
  echo "------------------------------"
  if [ -s "$MONITOR_LOG" ]; then
    echo "⚠️ File activity detected:"
    [ -n "$DISPLAY" ] && paplay /usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga &
    [ -n "$DISPLAY" ] && notify-send "🚨 File activity detected!" "See $MONITOR_LOG"
    cat "$MONITOR_LOG"
  else
    echo "✅ No file modifications detected."
  fi

  echo -e "\n🛁 System Calls:"
  echo "------------------------------"
  if grep -qE "execve|fork|clone|connect|open|ptrace" "$STRACE_LOG"; then
    [ -n "$DISPLAY" ] && paplay /usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga &
    [ -n "$DISPLAY" ] && notify-send "🚨 Suspicious system calls!" "See $STRACE_LOG"
    grep -E "execve|fork|clone|connect|open|ptrace" "$STRACE_LOG"
  else
    echo "✅ No suspicious system calls."
  fi

  echo -e "\n🌐 Network Dump:"
  echo "------------------------------"
  if [ -s "$TCPDUMP_LOG" ]; then
    echo "⚠️ Network activity captured! See pcap: $TCPDUMP_LOG"
    [ -n "$DISPLAY" ] && paplay /usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga &
    [ -n "$DISPLAY" ] && notify-send "🛁 Network Leak?" "Check $TCPDUMP_LOG (Wireshark)"
  else
    echo "✅ No unexpected network traffic."
  fi

  echo -e "\n📝 Logs saved in: $LOG_DIR"
fi

# ==============================
# 🚀 TOR BROWSER MODE
# ==============================
if [[ "$MODE" == "Open Tor Browser" ]]; then

NFT_FILE="$HOME/.config/firejail/onlytor.nft"

if [ ! -f "$NFT_FILE" ]; then
  echo "🔥 Netfilter file not found! Creating one..."
  mkdir -p "$(dirname "$NFT_FILE")"
  cat <<EOF > "$NFT_FILE"
table inet filter {
  chain output {
    type filter hook output priority 0;
    policy drop;
    ip daddr != 127.0.0.1 tcp dport != 9050 drop
    ip6 daddr != ::1 drop
    meta l4proto != tcp drop
    meta l4proto != udp drop
  }
}
EOF
fi

sudo nft -f "$NFT_FILE"

xclip -selection clipboard /dev/null || true
sudo modprobe -r uvcvideo snd_usb_audio usb_storage usbhid 2>/dev/null || true

bwrap --ro-bind / / \
      --dev /dev \
      --proc /proc \
      --tmpfs /proc/self/status \
      --tmpfs /tmp \
      --unshare-all \
      --new-session \
      firejail --noprofile --net=tor \
        --private \
        --private-dev \
        --nosound \
        --no3d \
        --x11=none \
        --caps.drop=all \
        --disable-mnt \
        --protocol=inet,inet6 \
        --blacklist=/home \
        --blacklist=/dev/snd \
        --name=tor \
        --nogroups \
        --seccomp \
        --nonewprivs \
        --nodbus \
        --notv \
        --noexec=/tmp \
        --noexec=/dev/shm \
        --read-only=/etc/resolv.conf \
        --env=TZ=UTC \
        --env=LANG=en_US.UTF-8 \
        --rlimit-fsize=1000000 \
        --rlimit-nofile=64 \
        --rlimit-nproc=20 \
        --unset=LD_PRELOAD \
        --unset=HTTP_PROXY \
        --unset=ALL_PROXY \
        --seccomp.drop=mmap,mprotect \
        torbrowser-launcher &

(
  LOGFILE="/tmp/tor_guardian.log"
  touch "$LOGFILE"
  INCIDENT_LOG="$HOME/tor_incidents.log"

  function check_leaks() {
    ss -tunp | awk '/ESTABLISHED/ && $5 !~ /127.0.0.1|::1/ {print}' >> "$LOGFILE"
  }

  while true; do
    check_leaks

    if [ -s "$LOGFILE" ]; then  
      TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

      if [ -n "$DISPLAY" ]; then
        notify-send "⚠️ Suspicious Traffic Detected" "Non-Tor connection found!"
        zenity --warning --text="Some apps may be leaking your IP! Check $LOGFILE" --width=300
        paplay /usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga &>/dev/null &
      fi

      echo "[$TIMESTAMP] 🚨 Non-Tor traffic detected!" >> "$INCIDENT_LOG"
      cat "$LOGFILE" >> "$INCIDENT_LOG"
      echo "----------------------------------------" >> "$INCIDENT_LOG"

      > "$LOGFILE"
    fi
    sleep 10
  done
) &

exit 0
fi

# ==============================
# 🗂️ FILE SANDBOX MODE
# ==============================
if [[ "$MODE" == "Open File in Sandbox" ]]; then
  FILE=$(zenity --file-selection --title="Select File to Open Securely")

  if [ -z "$FILE" ]; then
    echo "❌ No file selected. Exiting."
    exit 1
  fi

  LOG_DIR="$(mktemp -d /tmp/fsb_logs_XXXXXX)"
  BASENAME=$(basename "$FILE")
  TIMESTAMP=$(date +%Y%m%d_%H%M%S)
  MONITOR_LOG="$LOG_DIR/monitor_${BASENAME}_$TIMESTAMP.log"
  STRACE_LOG="$LOG_DIR/strace_${BASENAME}_$TIMESTAMP.log"
  TCPDUMP_LOG="$LOG_DIR/net_${BASENAME}_$TIMESTAMP.pcap"
  touch "$MONITOR_LOG" "$STRACE_LOG"

  mat2 -s "$FILE"
  xclip -selection clipboard /dev/null || true

  (
    while true; do
      inotifywait -q -e modify,open,attrib,delete_self,move_self "$FILE" >> "$MONITOR_LOG"
      if [ -s "$MONITOR_LOG" ]; then
        TS=$(date +%Y%m%d_%H%M%S)
        ALERT_FILE="$LOG_DIR/file_alert_$TS.log"
        cp "$MONITOR_LOG" "$ALERT_FILE"
        if [ -n "$DISPLAY" ]; then
          paplay /usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga &
          notify-send "🚨 File Changed" "See $ALERT_FILE"
          zenity --warning --text="Suspicious file change detected!\nSee: $ALERT_FILE" --width=300
        fi
      fi
      sleep 5
    done
  ) &
  MON_PID=$!

  sudo timeout 180 tcpdump -i any -w "$TCPDUMP_LOG" not port 9050 and not port 53 and not dst net 127.0.0.0/8 and not dst net ::1 > /dev/null 2>&1 &
  TCP_PID=$!

  ALLOWED_APPS=(gedit less nano eog ristretto evince zathura cat more)
  FILETYPE=$(xdg-mime query filetype "$FILE")
  APP=""
  for candidate in "${ALLOWED_APPS[@]}"; do
    if command -v "$candidate" &> /dev/null; then
      APP="$candidate"
      break
    fi
  done

  if [ -z "$APP" ]; then
    echo "❌ No safe viewer found!"
    kill "$MON_PID" "$TCP_PID"
    exit 1
  fi

  strace -f -e trace=process,execve,clone,fork,vfork,open,connect,ptrace -o "$STRACE_LOG" \
    bwrap --ro-bind / / \
          --dev /dev \
          --proc /proc \
          --tmpfs /proc/self/status \
          --tmpfs /tmp \
          --unshare-all \
          --new-session \
          firejail --noprofile \
            --net=none \
            --seccomp \
            --seccomp.drop=socket,connect,accept,accept4,listen,bind,execve,execveat,ptrace,fork,vfork,clone,kill,tkill,tgkill,open_by_handle_at,fanotify_init,fanotify_mark,process_vm_readv,process_vm_writev,reboot,delete_module,init_module,finit_module,unshare,mmap,mprotect \
            --private \
            --no3d \
            --nosound \
            --x11=none \
            --caps.drop=all \
            --disable-mnt \
            --private-dev \
            --nogroups \
            --nonewprivs \
            --noexec=/tmp \
            --noexec=/dev/shm \
            --blacklist=/home \
            --whitelist="$FILE" \
            --read-only="$FILE" \
            --rlimit-fsize=1000000 \
            --rlimit-nofile=64 \
            --rlimit-nproc=20 \
            --name=fileviewer \
            "$APP" "$FILE"

  trap 'kill "$MON_PID" "$TCP_PID"' EXIT

  dmesg | tail -n 30 >> "$LOG_DIR/dmesg_after_$TIMESTAMP.log"

  echo -e "\n📜 Monitoring Results for $FILE"
  echo "------------------------------"
  if [ -s "$MONITOR_LOG" ]; then
    echo "⚠️ File activity detected:"
    [ -n "$DISPLAY" ] && paplay /usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga &
    [ -n "$DISPLAY" ] && notify-send "🚨 File activity detected!" "See $MONITOR_LOG"
    cat "$MONITOR_LOG"
  else
    echo "✅ No file modifications detected."
  fi

  echo -e "\n🛁 System Calls:"
  echo "------------------------------"
  if grep -qE "execve|fork|clone|connect|open|ptrace" "$STRACE_LOG"; then
    [ -n "$DISPLAY" ] && paplay /usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga &
    [ -n "$DISPLAY" ] && notify-send "🚨 Suspicious system calls!" "See $STRACE_LOG"
    grep -E "execve|fork|clone|connect|open|ptrace" "$STRACE_LOG"
  else
    echo "✅ No suspicious system calls."
  fi

  echo -e "\n🌐 Network Dump:"
  echo "------------------------------"
  if [ -s "$TCPDUMP_LOG" ]; then
    echo "⚠️ Network activity captured! See pcap: $TCPDUMP_LOG"
    [ -n "$DISPLAY" ] && paplay /usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga &
    [ -n "$DISPLAY" ] && notify-send "🛁 Network Leak?" "Check $TCPDUMP_LOG (Wireshark)"
  else
    echo "✅ No unexpected network traffic."
  fi

  echo -e "\n📝 Logs saved in: $LOG_DIR"
fi


