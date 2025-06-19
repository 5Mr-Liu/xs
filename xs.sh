#!/usr/bin/env bash

# Exit on error, treat unset variables as an error, and ensure pipelines fail on error
set -eo pipefail

# --- Configuration ---
INSTALL_DIR="/usr/local/bin"
SS_EXECUTABLES=("ssserver" "sslocal" "ssmanager" "ssurl") # Binaries we expect in the tarball

# OS Specifics
OS_TYPE=""
ARCH_TYPE=""
CONFIG_DIR=""
CONFIG_FILE=""
SERVICE_NAME="shadowsocks-rust" # For systemd service name
PLIST_LABEL="com.shadowsocks-rust.ssserver" # For macOS launchd label
PLIST_FILE="" # Defined in detect_os_arch
LOG_FILE="" # Defined in detect_os_arch
ERROR_LOG_FILE="" # Defined in detect_os_arch

# Sudo prefix
SUDO_CMD=""

# Global flag for dependency installation behavior
INTERACTIVE_MODE="yes" # Assume interactive unless started with args

# --- Colors for Output ---
C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'

# --- Helper Functions (Output to stderr by default) ---
info() { echo -e "${C_BLUE}[INFO]${C_RESET} $1" >&2; }
warn() { echo -e "${C_YELLOW}[WARN]${C_RESET} $1" >&2; }
error() { echo -e "${C_RED}[ERROR]${C_RESET} $1" >&2; }
success() { echo -e "${C_GREEN}[SUCCESS]${C_RESET} $1" >&2; }

# Function to echo to stdout (for capturing output or direct display)
echo_stdout() { echo -e "$1"; }


info_manual_install() {
    local cmd_name="$1"
    local pkg_name="$1"
    if [[ "$cmd_name" == "jq" ]]; then pkg_name="jq"; fi
    if [[ "$cmd_name" == "curl" ]]; then pkg_name="curl"; fi
    if [[ "$cmd_name" == "tar" ]]; then pkg_name="tar"; fi
    if [[ "$cmd_name" == "unzip" ]]; then pkg_name="unzip"; fi

    warn "请参考以下命令手动安装 '$pkg_name':"
    echo -e "  Debian/Ubuntu:    ${C_GREEN}sudo apt update && sudo apt install -y $pkg_name${C_RESET}" >&2
    echo -e "  CentOS/RHEL/Fedora: ${C_GREEN}sudo dnf install -y $pkg_name${C_RESET} (或 ${C_GREEN}sudo yum install -y $pkg_name${C_RESET})" >&2
    echo -e "  Arch Linux:       ${C_GREEN}sudo pacman -S --noconfirm $pkg_name${C_RESET}" >&2
    echo -e "  macOS:            ${C_GREEN}brew install $pkg_name${C_RESET}" >&2
    if [[ "$cmd_name" != "$pkg_name" ]]; then
        info "请查阅您操作系统的文档来安装提供 '$cmd_name' 命令的包 (可能名为 '$pkg_name')。"
    fi
}

_install_dependency() {
    local cmd_name="$1"
    local pkg_name="$2"

    if [ -z "$pkg_name" ]; then
        pkg_name="$cmd_name"
    fi

    warn "命令 '$cmd_name' 未找到。"
    if [[ "$INTERACTIVE_MODE" != "yes" ]]; then
        error "非交互模式下，请手动安装 '$pkg_name' 后重试。"
        info_manual_install "$cmd_name"
        return 1
    fi

    read -rp "是否尝试自动安装 '$pkg_name'? (y/N): " install_confirm
    if [[ "$install_confirm" != "y" ]] && [[ "$install_confirm" != "Y" ]]; then
        info "自动安装已取消。"
        info_manual_install "$cmd_name"
        return 1
    fi

    info "正在尝试自动安装 '$pkg_name'..."
    local installed_successfully=0
    if [[ "$OS_TYPE" == "linux" ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            info "检测到 apt (Debian/Ubuntu)。正在更新包列表并安装..."
            ($SUDO_CMD apt-get update -qq && $SUDO_CMD apt-get install -y "$pkg_name") && installed_successfully=1
        elif command -v dnf >/dev/null 2>&1; then
            info "检测到 dnf (Fedora/RHEL/CentOS)。正在安装..."
            $SUDO_CMD dnf install -y "$pkg_name" && installed_successfully=1
        elif command -v yum >/dev/null 2>&1; then
            info "检测到 yum (CentOS/RHEL)。正在安装..."
            $SUDO_CMD yum install -y "$pkg_name" && installed_successfully=1
        elif command -v pacman >/dev/null 2>&1; then
            info "检测到 pacman (Arch Linux)。正在安装..."
            $SUDO_CMD pacman -S --noconfirm "$pkg_name" && installed_successfully=1
        else
            error "未找到支持的 Linux 包管理器 (apt, dnf, yum, pacman) 来安装 '$pkg_name'。"
        fi
    elif [[ "$OS_TYPE" == "macos" ]]; then
        if command -v brew >/dev/null 2>&1; then
            info "检测到 brew (macOS)。正在安装..."
            brew install "$pkg_name" && installed_successfully=1
        else
            error "在 macOS 上未找到 Homebrew (brew)。请先安装 Homebrew 以便自动安装 '$pkg_name'。"
            info "  你可以访问 https://brew.sh 获取安装指令。"
        fi
    else
        error "不支持的操作系统 '$OS_TYPE' 进行自动依赖安装。"
    fi

    if [[ "$installed_successfully" -eq 1 ]]; then
        if command -v "$cmd_name" >/dev/null 2>&1; then
            success "'$cmd_name' 安装成功。"
            return 0
        else
            error "'$pkg_name' 安装过程可能已执行，但命令 '$cmd_name' 仍然未找到。"
            info_manual_install "$cmd_name"
            return 1
        fi
    else
        error "安装 '$pkg_name' 失败。"
        info_manual_install "$cmd_name"
        return 1
    fi
}

check_command() {
    local cmd_to_check="$1"
    local pkg_name_for_install="$2"
    if [ -z "$pkg_name_for_install" ]; then
        pkg_name_for_install="$cmd_to_check"
    fi

    command -v "$cmd_to_check" >/dev/null 2>&1 || {
        _install_dependency "$cmd_to_check" "$pkg_name_for_install" || exit 1
    }
}

detect_os_arch() {
    OS_TYPE_RAW=$(uname -s)
    ARCH_TYPE_RAW=$(uname -m)

    case "$OS_TYPE_RAW" in
        Linux)
            OS_TYPE="linux"
            CONFIG_DIR="/etc/shadowsocks-rust"
            CONFIG_FILE="${CONFIG_DIR}/config.json"
            if [[ "$ARCH_TYPE_RAW" == "x86_64" ]]; then
                ARCH_TYPE="x86_64-unknown-linux-gnu"
            elif [[ "$ARCH_TYPE_RAW" == "aarch64" ]]; then
                ARCH_TYPE="aarch64-unknown-linux-gnu"
            else
                error "不支持的 Linux 架构: $ARCH_TYPE_RAW"
                exit 1
            fi
            ;;
        Darwin)
            OS_TYPE="macos"
            CONFIG_DIR="${HOME}/.config/shadowsocks-rust"
            CONFIG_FILE="${CONFIG_DIR}/config.json"
            PLIST_FILE="${HOME}/Library/LaunchAgents/${PLIST_LABEL}.plist"
            LOG_FILE="${HOME}/Library/Logs/${PLIST_LABEL}.log"
            ERROR_LOG_FILE="${HOME}/Library/Logs/${PLIST_LABEL}.error.log"

            if [[ "$ARCH_TYPE_RAW" == "x86_64" ]]; then
                ARCH_TYPE="x86_64-apple-darwin"
            elif [[ "$ARCH_TYPE_RAW" == "arm64" ]]; then
                ARCH_TYPE="aarch64-apple-darwin"
            else
                error "不支持的 macOS 架构: $ARCH_TYPE_RAW"
                exit 1
            fi
            ;;
        *)
            error "不支持的操作系统: $OS_TYPE_RAW"
            exit 1
            ;;
    esac
    info "检测到系统: $OS_TYPE, 架构: $ARCH_TYPE_RAW (GitHub 格式: $ARCH_TYPE)"
}

check_sudo() {
    if [[ "$EUID" -ne 0 ]]; then
        SUDO_CMD="sudo"
    else
        SUDO_CMD=""
    fi
}

_get_public_ip() {
    local ip_services=(
        "https://api.ipify.org?format=text"
        "https://icanhazip.com"
        "https://ifconfig.me/ip"
        "https://ipinfo.io/ip"
        "https://myip.dnsomatic.com"
        "https://checkip.amazonaws.com"
        "http://whatismyip.akamai.com"
    )
    local public_ip=""
    local user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

    info "正在尝试自动获取公网IP..."
    for service_url in "${ip_services[@]}"; do
        info "  尝试: $service_url"
        public_ip=$(curl -sSL -A "$user_agent" -m 5 "$service_url" 2>/dev/null || true)
        public_ip=$(echo "$public_ip" | xargs) 

        if [[ "$public_ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            success "  获取到公网IP: $public_ip"
            echo_stdout "$public_ip"
            return 0
        else
            warn "  从 $service_url 获取IP失败或格式无效: '$public_ip'"
            public_ip="" 
        fi
    done

    warn "所有自动获取公网IP的方法均失败。"
    if [[ "$INTERACTIVE_MODE" == "yes" ]]; then
        read -rp "是否手动输入您的公网IP地址? (y/N): " manual_ip_confirm
        if [[ "$manual_ip_confirm" == "y" ]] || [[ "$manual_ip_confirm" == "Y" ]]; then
            read -rp "请输入您的公网IP地址: " manual_ip
            manual_ip=$(echo "$manual_ip" | xargs)
            if [[ "$manual_ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                success "已使用手动输入的IP: $manual_ip"
                echo_stdout "$manual_ip"
                return 0
            else
                error "手动输入的IP '$manual_ip' 格式无效。将使用占位符。"
            fi
        else
            info "用户选择不手动输入IP。将使用占位符。"
        fi
    else
        info "非交互模式，无法提示手动输入IP。将使用占位符。"
    fi

    echo_stdout "YOUR_SERVER_IP"
    return 1
}

# --- Core Functions ---

download_and_install_ss() {
    info "正在获取最新版 Shadowsocks-Rust..."
    local latest_release_url="https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest"
    local download_url
    
    download_url=$(curl -sSL "$latest_release_url" | jq -r ".assets[] | select(.name | endswith(\"${ARCH_TYPE}.tar.xz\")) | .browser_download_url")
    local archive_type="tar.xz"

    if [ -z "$download_url" ] || [ "$download_url" == "null" ]; then
        warn "未找到 .tar.xz 压缩包，尝试 .zip..."
        download_url=$(curl -sSL "$latest_release_url" | jq -r ".assets[] | select(.name | endswith(\"${ARCH_TYPE}.zip\")) | .browser_download_url")
        archive_type="zip"
    fi

    if [ -z "$download_url" ] || [ "$download_url" == "null" ]; then
        error "未找到适用于 ${ARCH_TYPE} 的最新版 Shadowsocks-Rust。"
        error "请检查 GitHub Releases 页面: https://github.com/shadowsocks/shadowsocks-rust/releases"
        exit 1
    fi

    local filename=$(basename "$download_url")
    local temp_dir
    temp_dir=$(mktemp -d 2>/dev/null || mktemp -d -t 'ssrust_download') 

    info "正在下载 $filename ..."
    curl -L --progress-bar "$download_url" -o "${temp_dir}/${filename}"

    info "正在解压 $filename ..."
    if [[ "$archive_type" == "tar.xz" ]]; then
        tar -xJf "${temp_dir}/${filename}" -C "$temp_dir"
    elif [[ "$archive_type" == "zip" ]]; then
        check_command "unzip" 
        unzip -q "${temp_dir}/${filename}" -d "$temp_dir"
    fi
    
    local extracted_bin_dir="$temp_dir"
    local potential_subdir
    potential_subdir=$(find "$temp_dir" -maxdepth 1 -type d -name "shadowsocks-v*" -print -quit)
    if [ -n "$potential_subdir" ] && [ -d "$potential_subdir" ]; then
        extracted_bin_dir="$potential_subdir"
    fi

    for exe in "${SS_EXECUTABLES[@]}"; do
        if [ -f "${extracted_bin_dir}/${exe}" ]; then
            info "正在安装 ${exe} 到 ${INSTALL_DIR}..."
            $SUDO_CMD mkdir -p "${INSTALL_DIR}" 
            $SUDO_CMD cp "${extracted_bin_dir}/${exe}" "${INSTALL_DIR}/"
            $SUDO_CMD chmod +x "${INSTALL_DIR}/${exe}"
        else
            warn "在解压文件中未找到 ${exe} (在 ${extracted_bin_dir} 中)，跳过。"
        fi
    done

    rm -rf "$temp_dir"
    success "Shadowsocks-Rust 安装完成。"
    for exe in "${SS_EXECUTABLES[@]}"; do
        if command -v "$exe" >/dev/null 2>&1 ; then
            local exe_path="${INSTALL_DIR}/${exe}"
            if [ -x "$exe_path" ] && [[ "$(command -v "$exe")" == "$exe_path" ]]; then
                 info "已安装: $($exe_path --version)"
            fi
        fi
    done
}

_generate_random_password() {
    LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16
}

_generate_random_port() {
    shuf -i 10000-65534 -n 1
}

configure_shadowsocks_auto() {
    info "开始自动配置 Shadowsocks (ssserver)..."
    local server_addr="0.0.0.0"
    local server_port=$(_generate_random_port)
    local password=$(_generate_random_password)
    local method="aes-256-gcm" 

    _write_config "$server_addr" "$server_port" "$password" "$method"
    success "自动配置完成。"
    _display_config_info "$server_addr" "$server_port" "$password" "$method"
}

configure_shadowsocks_manual() {
    info "开始手动配置 Shadowsocks (ssserver)..."
    local server_addr_default="0.0.0.0"
    read -rp "服务器监听地址 (默认为 ${server_addr_default}): " server_addr
    server_addr=${server_addr:-$server_addr_default}

    local server_port_default=$(_generate_random_port)
    read -rp "服务器端口 (1-65535, 默认为 ${server_port_default}): " server_port
    server_port=${server_port:-$server_port_default}
    if ! [[ "$server_port" =~ ^[0-9]+$ ]] || [ "$server_port" -lt 1 ] || [ "$server_port" -gt 65535 ]; then
        error "无效的端口号: $server_port"
        return 1
    fi

    local password_default=$(_generate_random_password)
    read -rp "密码 (默认为 ${password_default}): " password
    password=${password:-$password_default}

    local method_default="aes-256-gcm"
    info "可用加密方法 (推荐):"
    info "  1. aes-256-gcm (推荐)"
    info "  2. chacha20-ietf-poly1305"
    info "  3. 2022-blake3-aes-128-gcm"
    info "  4. 2022-blake3-aes-256-gcm"
    info "  (更多方法请查阅 ssserver --help)"
    read -rp "加密方法 (默认为 ${method_default}): " method
    method=${method:-$method_default}

    _write_config "$server_addr" "$server_port" "$password" "$method"
    success "手动配置完成。"
    _display_config_info "$server_addr" "$server_port" "$password" "$method"
}

_write_config() {
    local server_addr="$1"
    local server_port="$2"
    local password="$3"
    local method="$4"

    info "正在创建配置文件: ${CONFIG_FILE}"
    if [[ "$CONFIG_DIR" == "$HOME"* ]]; then 
        mkdir -p "$CONFIG_DIR"
        chmod 700 "$CONFIG_DIR"
    else 
        $SUDO_CMD mkdir -p "$CONFIG_DIR"
        $SUDO_CMD chmod 700 "$CONFIG_DIR"
    fi

    local config_json
    config_json=$(cat <<EOF
{
    "server": "${server_addr}",
    "server_port": ${server_port},
    "password": "${password}",
    "method": "${method}",
    "mode": "tcp_and_udp",
    "timeout": 300
}
EOF
)
    local temp_config_file
    temp_config_file=$(mktemp 2>/dev/null || mktemp -t 'ssrust_config')
    echo "$config_json" > "$temp_config_file"

    if [[ "$CONFIG_DIR" == "$HOME"* ]]; then
        cp "$temp_config_file" "$CONFIG_FILE"
        chmod 600 "$CONFIG_FILE"
    else
        $SUDO_CMD cp "$temp_config_file" "$CONFIG_FILE"
        $SUDO_CMD chmod 600 "$CONFIG_FILE"
    fi
    rm "$temp_config_file"
}

_generate_full_clash_config() {
    local server_ip="$1"
    local server_port="$2"
    local password="$3"
    local method="$4"
    local proxy_name="$5"
    local clash_cipher="$method"

    local clash_config_content
clash_config_content=$(cat <<EOF
# Clash Configuration File Generated by Script
# Save this content as 'config.yaml' and import into your Clash client.

port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: info
external-controller: 127.0.0.1:9090
# secret: "" # Optional: uncomment and set a secret if needed

dns:
  enable: true 
  listen: 0.0.0.0:5353 
  ipv6: false 
  enhanced-mode: redir-host 
  nameserver:
    - https://dns.alidns.com/dns-query 
    - https://doh.pub/dns-query
    - tls://dns.rubyfish.cn:853 
  fallback: 
    - https://cloudflare-dns.com/dns-query
    - https://dns.google/dns-query
    - tls://1.0.0.1:853
  # fallback-filter:
  #   geoip: true
  #   geoip-code: CN 

# Proxy definitions
proxies:
  - name: "${proxy_name}"
    type: ss
    server: "${server_ip}"
    port: ${server_port}
    cipher: "${clash_cipher}"
    password: "${password}"
    udp: true

# Proxy Group definitions
proxy-groups:
  - name: "🚀 Proxy" 
    type: select
    proxies:
      - "${proxy_name}"
      - DIRECT 

  - name: "🌍 Global" 
    type: select
    proxies:
      - "🚀 Proxy" 
      - DIRECT

# Rule definitions
rules:
  - 'DOMAIN-SUFFIX,google.com,🚀 Proxy'
  - 'DOMAIN-SUFFIX,youtube.com,🚀 Proxy'
  - 'DOMAIN-KEYWORD,google,🚀 Proxy'
  - 'DOMAIN-SUFFIX,cn,DIRECT'
  - 'DOMAIN-SUFFIX,xn--fiqs8s,DIRECT' # .中国
  - 'GEOIP,CN,DIRECT'
  - 'MATCH,🚀 Proxy' 

EOF
)
    echo_stdout "\n${C_GREEN}--- 完整 Clash 配置文件内容 ---${C_RESET}"
    echo_stdout "请将以下所有内容复制并保存为一个名为 ${C_YELLOW}config.yaml${C_RESET} 的文件。"
    echo_stdout "然后将此 ${C_YELLOW}config.yaml${C_RESET} 文件导入到您的 Clash 客户端中。"
    echo_stdout "如果您在服务器上操作，可以执行类似命令保存: ${C_BLUE}$0 clash-config > config.yaml${C_RESET} (假设脚本名为 $0)"
    echo_stdout "---------------------------------------------------------------------"
    echo_stdout "${C_YELLOW}" # Start yellow color for the config
    echo_stdout "$clash_config_content"
    echo_stdout "${C_RESET}"  # Reset color
    echo_stdout "---------------------------------------------------------------------"
    if [[ "$server_ip" == "YOUR_SERVER_IP" ]]; then
        warn "重要: 请记得在上面的配置中，将代理服务器地址 '${C_YELLOW}YOUR_SERVER_IP${C_RESET}' 替换为您的实际公网IP地址！"
    fi
}


_display_config_info() {
    local server_addr="$1"
    local server_port="$2"
    local password="$3"
    local method="$4"
    
    local public_ip
    public_ip=$(_get_public_ip)

    echo_stdout "\n${C_GREEN}--- Shadowsocks 服务器配置信息 ---${C_RESET}"
    echo_stdout "服务器地址 (监听): ${C_YELLOW}${server_addr}${C_RESET}"
    echo_stdout "服务器端口: ${C_YELLOW}${server_port}${C_RESET}"
    echo_stdout "密码: ${C_YELLOW}${password}${C_RESET}"
    echo_stdout "加密方法: ${C_YELLOW}${method}${C_RESET}"
    echo_stdout "\n${C_GREEN}--- 客户端连接信息 ---${C_RESET}"
    echo_stdout "请将客户端 '服务器地址' 设置为: ${C_YELLOW}${public_ip}${C_RESET}"
    
    if [[ "$public_ip" == "YOUR_SERVER_IP" ]]; then
        warn "由于无法自动获取公网IP，并且您未提供或提供的IP无效，"
        warn "请在客户端和后续生成的Clash配置中手动将 '${C_YELLOW}YOUR_SERVER_IP${C_RESET}' 替换为您的实际公网IP。"
    else
        echo_stdout "(这是根据自动检测或您的输入得到的公网IP)"
    fi

    local ss_uri_encoded_userinfo
    ss_uri_encoded_userinfo=$(echo -n "${method}:${password}" | base64 | tr -d '\n' | tr '/+' '_-' | tr -d '=')
    local ss_uri="ss://${ss_uri_encoded_userinfo}@${public_ip}:${server_port}"

    echo_stdout "SS 链接 (可直接导入客户端):"
    echo_stdout "${C_YELLOW}${ss_uri}${C_RESET}"
    echo_stdout "\n二维码 (复制以下链接到浏览器生成):"
    echo_stdout "${C_BLUE}https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=$(rawurlencode "$ss_uri")${C_RESET}"


    info "\n${C_RED}--- 重要: 防火墙设置 ---${C_RESET}"
    info "请确保在您的服务器防火墙中为 Shadowsocks 打开端口: ${C_YELLOW}${server_port}/tcp${C_RESET} 和 ${C_YELLOW}${server_port}/udp${C_RESET}"
    
    local firewall_detected=0
    if command -v ufw >/dev/null 2>&1; then
        firewall_detected=1
        info "检测到 'ufw'。您可能需要运行 (如果 ufw 已启用):"
        info "  ${C_GREEN}sudo ufw allow ${server_port}/tcp${C_RESET}"
        info "  ${C_GREEN}sudo ufw allow ${server_port}/udp${C_RESET}"
        info "  ${C_GREEN}sudo ufw reload${C_RESET}"
    fi
    if command -v firewall-cmd >/dev/null 2>&1; then
        firewall_detected=1
        info "检测到 'firewalld'。您可能需要运行 (如果 firewalld 服务正在运行):"
        info "  ${C_GREEN}sudo firewall-cmd --permanent --add-port=${server_port}/tcp${C_RESET}"
        info "  ${C_GREEN}sudo firewall-cmd --permanent --add-port=${server_port}/udp${C_RESET}"
        info "  ${C_GREEN}sudo firewall-cmd --reload${C_RESET}"
    fi
    if [[ "$firewall_detected" -eq 0 ]]; then
        info "如果您使用其他防火墙 (如 iptables), 请手动配置。"
    fi
    info "" 

    if [[ "$INTERACTIVE_MODE" == "yes" ]]; then 
        read -rp "是否需要生成完整的 Clash 配置文件? (y/N): " generate_clash_full
        if [[ "$generate_clash_full" == "y" ]] || [[ "$generate_clash_full" == "Y" ]]; then
            local clash_proxy_name_default="SS-$(echo "$public_ip" | tr '.' '_')-${server_port}"
             if [[ "$public_ip" == "YOUR_SERVER_IP" ]]; then
                clash_proxy_name_default="SS-YOUR_SERVER_IP-${server_port}"
            fi
            read -rp "请输入 Clash 中的代理节点名称 (默认为 ${clash_proxy_name_default}): " clash_proxy_name
            clash_proxy_name=${clash_proxy_name:-$clash_proxy_name_default}
            
            _generate_full_clash_config "$public_ip" "$server_port" "$password" "$method" "$clash_proxy_name"
        fi
    fi
}

rawurlencode() {
  local string="${1}"
  local strlen=${#string}
  local encoded=""
  local pos c o

  for (( pos=0 ; pos<strlen ; pos++ )); do
     c=${string:$pos:1}
     case "$c" in
        [-_.~a-zA-Z0-9] ) o="${c}" ;;
        * )               printf -v o '%%%02x' "'$c"
     esac
     encoded+="${o}"
  done
  echo_stdout "${encoded}"
}

setup_service() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        error "配置文件 ${CONFIG_FILE} 不存在。请先配置 Shadowsocks。"
        return 1
    fi

    local save_logs_choice_default="N" 
    if [[ "$OS_TYPE" == "linux" ]]; then
        save_logs_choice_default="Y" 
    fi

    local save_logs_actual
    if [[ "$INTERACTIVE_MODE" == "yes" ]]; then
        read -rp "是否保存服务日志? (Y/N，默认为 ${save_logs_choice_default}): " save_logs_choice
        if [[ -z "$save_logs_choice" ]]; then 
            save_logs_choice="$save_logs_choice_default"
        fi
    else 
        warn "非交互模式，服务日志保存设置将使用默认值 (${save_logs_choice_default})。"
        save_logs_choice="$save_logs_choice_default"
    fi


    if [[ "$save_logs_choice" == "y" ]] || [[ "$save_logs_choice" == "Y" ]]; then
        save_logs_actual="yes"
    else
        save_logs_actual="no"
    fi

    if [[ "$OS_TYPE" == "linux" ]]; then
        setup_service_linux "$save_logs_actual"
    elif [[ "$OS_TYPE" == "macos" ]]; then
        setup_service_macos "$save_logs_actual"
    fi
}

setup_service_linux() {
    local save_logs="$1" 
    info "正在为 Linux (systemd) 设置服务..."
    local service_file="/etc/systemd/system/${SERVICE_NAME}.service"
    
    if id "shadowsocks" &>/dev/null; then
        info "用户 'shadowsocks' 已存在。"
    else
        info "正在创建 'shadowsocks' 系统用户 (无登录权限)..."
        if $SUDO_CMD useradd --system --shell /usr/sbin/nologin --no-create-home --user-group --comment "Shadowsocks Service User" shadowsocks; then
             info "用户 'shadowsocks' 已创建。"
        else
             warn "创建用户 'shadowsocks' 失败，尝试备用方法..."
             $SUDO_CMD useradd --system --shell /bin/false --no-create-home --user-group --comment "Shadowsocks Service User" shadowsocks || \
             error "无法创建 'shadowsocks' 用户。请检查权限或手动创建。"
        fi
    fi
    $SUDO_CMD chown -R shadowsocks:shadowsocks "$CONFIG_DIR"

    local std_out="journal" 
    local std_err="journal" 
    if [[ "$save_logs" == "no" ]]; then
        std_out="null" 
        std_err="null" 
        info "systemd 服务日志将重定向到 /dev/null (只会记录基本的启动/停止信息)。"
    else
        info "systemd 服务日志将由 journald 管理。"
    fi

    local service_content
    service_content=$(cat <<EOF
[Unit]
Description=Shadowsocks-rust Server
Documentation=https://github.com/shadowsocks/shadowsocks-rust
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=shadowsocks
Group=shadowsocks
LimitNOFILE=65536 
ExecStart=${INSTALL_DIR}/ssserver -c ${CONFIG_FILE}
StandardOutput=${std_out}
StandardError=${std_err}
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
)
    
    local temp_service_file
    temp_service_file=$(mktemp 2>/dev/null || mktemp -t 'ssrust_service')
    echo "$service_content" > "$temp_service_file"
    $SUDO_CMD cp "$temp_service_file" "$service_file"
    rm "$temp_service_file"

    $SUDO_CMD chmod 644 "$service_file"
    $SUDO_CMD systemctl daemon-reload
    success "Systemd 服务文件已创建/更新: $service_file"

    info "正在尝试启动服务并设置为开机自启..."
    if $SUDO_CMD systemctl enable "$SERVICE_NAME" && $SUDO_CMD systemctl restart "$SERVICE_NAME"; then 
        success "服务已启动并设置为开机自启。"
        info "使用 'sudo systemctl status $SERVICE_NAME' 查看状态。"
    else
        error "启动服务或设置开机自启失败。请手动执行："
        info "  sudo systemctl enable ${SERVICE_NAME}"
        info "  sudo systemctl restart ${SERVICE_NAME}" 
    fi
    
    if [[ "$INTERACTIVE_MODE" == "yes" ]]; then
        info "你可以使用以下命令管理服务:"
        info "  sudo systemctl stop ${SERVICE_NAME}"
        info "  sudo systemctl status ${SERVICE_NAME}"
        info "  sudo systemctl disable ${SERVICE_NAME} (取消开机自启)"
    fi
}

setup_service_macos() {
    local save_logs="$1" 
    info "正在为 macOS (launchd) 设置服务..."
    mkdir -p "$(dirname "$PLIST_FILE")"

    local std_out_path="${LOG_FILE}"
    local std_err_path="${ERROR_LOG_FILE}"

    if [[ "$save_logs" == "no" ]]; then
        std_out_path="/dev/null"
        std_err_path="/dev/null"
        info "macOS launchd 服务日志将重定向到 /dev/null。"
        rm -f "$LOG_FILE" "$ERROR_LOG_FILE"
    else
        mkdir -p "$(dirname "$LOG_FILE")" 
        info "macOS launchd 服务日志将保存到 ${LOG_FILE} 和 ${ERROR_LOG_FILE}。"
    fi

    local plist_content
    # For macOS, if ssserver arguments differ or cause issues, adjust here.
    # The --log-level arg was problematic on Linux; it might be fine on macOS,
    # or it might also need removal if the ssserver binary is the same version/build.
    # For now, keeping the original args for macOS until a specific issue is reported.
    # If a similar "unexpected argument" error occurs on macOS, remove "--log-level" and "warn" below.
    plist_content=$(cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/ssserver</string>
        <string>-c</string>
        <string>${CONFIG_FILE}</string>
        <string>--log-level</string> 
        <string>warn</string> 
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>${std_out_path}</string>
    <key>StandardErrorPath</key>
    <string>${std_err_path}</string>
    <key>WorkingDirectory</key>
    <string>$(dirname "${CONFIG_FILE}")</string> 
    <key>ProcessType</key> 
    <string>Interactive</string> 
    <key>Nice</key>
    <integer>1</integer>
</dict>
</plist>
EOF
)
    echo "$plist_content" > "$PLIST_FILE"
    chmod 644 "$PLIST_FILE"
    
    success "LaunchAgent Plist 文件已创建/更新: $PLIST_FILE"

    info "正在尝试加载并启动服务 (将在下次登录时自动运行)..."
    launchctl unload -w "$PLIST_FILE" >/dev/null 2>&1 || true 
    sleep 1 
    if launchctl load -w "$PLIST_FILE"; then
        success "服务已加载并设置为随用户登录启动。"
        info "使用 'launchctl list | grep $PLIST_LABEL' 查看状态 (可能需要一点时间才能显示)。"
    else
        error "加载服务失败。请手动执行："
        info "  launchctl load -w ${PLIST_FILE}"
    fi

    if [[ "$INTERACTIVE_MODE" == "yes" ]]; then
        info "你可以使用以下命令管理服务:"
        info "  launchctl unload -w ${PLIST_FILE} (卸载并停止)"
        info "  launchctl kickstart -k gui/$(id -u)/${PLIST_LABEL} (如果需要立即重启)"
        info "日志文件 (如果启用): ${LOG_FILE}, ${ERROR_LOG_FILE}"
    fi
}

manage_service() {
    local action="$1"
    if [[ "$OS_TYPE" == "linux" ]]; then
        if ! $SUDO_CMD systemctl list-units --full -all | grep -qF "${SERVICE_NAME}.service"; then
            if [[ "$action" != "enable" && "$action" != "disable" ]]; then 
                 warn "服务 ${SERVICE_NAME} 似乎未安装或 systemd 未加载。请先运行选项 '4' 或命令 'setup-service'。"
                 # Avoid exiting here if just checking status of a non-existent/unloaded service
                 if [[ "$action" == "status" ]]; then return 0; fi 
            fi
        fi
        case "$action" in
            start) $SUDO_CMD systemctl start "$SERVICE_NAME" && success "服务已启动";;
            stop) $SUDO_CMD systemctl stop "$SERVICE_NAME" && success "服务已停止";;
            restart) $SUDO_CMD systemctl restart "$SERVICE_NAME" && success "服务已重启";;
            status) $SUDO_CMD systemctl status "$SERVICE_NAME" -l --no-pager ;;
            enable) $SUDO_CMD systemctl enable "$SERVICE_NAME" && success "服务已设置为开机自启";;
            disable) $SUDO_CMD systemctl disable "$SERVICE_NAME" && success "服务已取消开机自启";;
            log) 
                info "查看 systemd 日志 (按 q 退出):"
                $SUDO_CMD journalctl -u "$SERVICE_NAME" -f -n 50 --no-pager
                ;;
            *) error "未知操作: $action for Linux" ; return 1;;
        esac
    elif [[ "$OS_TYPE" == "macos" ]]; then
        if [ ! -f "$PLIST_FILE" ] && ! launchctl print "gui/$(id -u)/${PLIST_LABEL}" > /dev/null 2>&1 ; then
            if [[ "$action" != "enable" && "$action" != "disable" ]]; then
                warn "LaunchAgent Plist 文件 ${PLIST_FILE} 不存在且服务未加载。服务可能未设置。请先运行选项 '4' 或命令 'setup-service'。"
                 if [[ "$action" == "status" ]]; then return 0; fi
            fi
        fi
        
        case "$action" in
            start) 
                if [ ! -f "$PLIST_FILE" ]; then error "Plist ${PLIST_FILE} 不存在，无法启动。请先设置服务。"; return 1; fi
                if launchctl print "gui/$(id -u)/${PLIST_LABEL}" > /dev/null 2>&1; then
                    info "服务已加载，尝试 kickstart (重启)..."
                    (launchctl kickstart -k "gui/$(id -u)/${PLIST_LABEL}" || launchctl start "$PLIST_LABEL") && success "服务已启动/重启"
                else
                    info "加载并启动服务..."
                    launchctl load -w "$PLIST_FILE" && success "服务已加载并启动"
                fi
                ;;
            stop) 
                info "卸载并停止服务..."
                (launchctl unload -w "$PLIST_FILE" >/dev/null 2>&1 || true) && success "服务已卸载并停止"
                ;;
            restart)
                if [ ! -f "$PLIST_FILE" ]; then error "Plist ${PLIST_FILE} 不存在，无法重启。请先设置服务。"; return 1; fi
                info "正在重启服务..."
                launchctl unload -w "$PLIST_FILE" >/dev/null 2>&1 || true 
                sleep 1
                launchctl load -w "$PLIST_FILE" && success "服务已重启"
                ;;
            status)
                if launchctl print "gui/$(id -u)/${PLIST_LABEL}" > /dev/null 2>&1; then
                    echo_stdout "${C_GREEN}服务 ${PLIST_LABEL} 已加载。${C_RESET}"
                    launchctl print "gui/$(id -u)/${PLIST_LABEL}"
                    if [ -f "$PLIST_FILE" ] && grep -q "<string>/dev/null</string>" "$PLIST_FILE" 2>/dev/null; then
                        info "日志配置为不保存到文件。"
                    elif [ -f "$LOG_FILE" ] || [ -f "$ERROR_LOG_FILE" ]; then
                        info "日志文件可能位于: ${LOG_FILE}, ${ERROR_LOG_FILE}"
                    fi
                else
                    echo_stdout "${C_YELLOW}服务 ${PLIST_LABEL} 未加载。${C_RESET}"
                fi
                ;;
            enable) 
                if [ ! -f "$PLIST_FILE" ]; then error "Plist ${PLIST_FILE} 不存在，无法启用。请先设置服务。"; return 1; fi
                info "通过 'launchctl load -w ${PLIST_FILE}' 启用并持久化服务。"
                info "服务将在用户下次登录时自动启动。"
                launchctl load -w "$PLIST_FILE" && success "服务已启用并设置为随用户登录启动"
                ;;
            disable)
                info "通过 'launchctl unload -w ${PLIST_FILE}' 禁用并持久化服务。"
                info "服务将不会在用户下次登录时自动启动。"
                (launchctl unload -w "$PLIST_FILE" >/dev/null 2>&1 || true) && success "服务已禁用且不会随用户登录启动"
                ;;
            log) 
                if [ ! -f "$PLIST_FILE" ]; then 
                    if launchctl print "gui/$(id -u)/${PLIST_LABEL}" > /dev/null 2>&1; then
                        warn "Plist ${PLIST_FILE} 不存在，但服务标签已加载。无法确定日志文件位置。"
                    else
                        warn "Plist ${PLIST_FILE} 不存在。服务可能未设置。"
                    fi
                    return 1;
                fi
                if grep -q "<string>/dev/null</string>" "$PLIST_FILE" 2>/dev/null; then
                    info "服务配置为不保存日志到文件 (输出到 /dev/null)。"
                else
                    local files_to_tail=()
                    [[ -f "$LOG_FILE" ]] && files_to_tail+=("$LOG_FILE")
                    [[ -f "$ERROR_LOG_FILE" ]] && files_to_tail+=("$ERROR_LOG_FILE")
                    if [ ${#files_to_tail[@]} -gt 0 ]; then
                        info "查看日志 (按 Ctrl+C 退出):"
                        tail -f "${files_to_tail[@]}"
                    else
                        info "未找到日志文件 (${LOG_FILE}, ${ERROR_LOG_FILE})。服务可能尚未产生输出，或者刚刚清除了日志。"
                    fi
                fi
                ;;
            *) error "未知操作: $action for macOS" ; return 1;;
        esac
    fi
}

uninstall_shadowsocks() {
    local confirmation
    if [[ "$INTERACTIVE_MODE" == "yes" ]]; then
        warn "这将卸载 Shadowsocks-Rust 并删除其配置文件和服务！"
        read -rp "你确定要继续吗? (y/N): " confirmation
        if [[ "$confirmation" != "y" ]] && [[ "$confirmation" != "Y" ]]; then
            info "卸载已取消。"
            return
        fi
    else
        warn "非交互模式下执行卸载。"
    fi


    info "正在停止和禁用服务..."
    if [[ "$OS_TYPE" == "linux" ]]; then
        if $SUDO_CMD systemctl list-units --full -all | grep -qF "${SERVICE_NAME}.service"; then
            $SUDO_CMD systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
            $SUDO_CMD systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
            info "正在删除 systemd 服务文件..."
            $SUDO_CMD rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
            $SUDO_CMD rm -rf "/etc/systemd/system/${SERVICE_NAME}.service.d" 
            $SUDO_CMD systemctl daemon-reload
        else
            info "Systemd 服务 ${SERVICE_NAME} 未找到，跳过服务删除。"
        fi
        
        local deluser_confirm="n"
        if [[ "$INTERACTIVE_MODE" == "yes" ]]; then
            read -rp "是否删除 'shadowsocks' 用户? (y/N): " deluser_confirm
        fi
        if [[ "$deluser_confirm" == "y" ]] || [[ "$deluser_confirm" == "Y" ]]; then
            if id "shadowsocks" &>/dev/null; then
                if $SUDO_CMD userdel shadowsocks; then
                    info "用户 'shadowsocks' 已删除。"
                else
                     warn "删除用户 shadowsocks 失败，可能仍有进程属于该用户或主目录未被 --remove 清理。"
                fi
            else
                info "用户 'shadowsocks' 不存在。"
            fi
        fi

    elif [[ "$OS_TYPE" == "macos" ]]; then
        if [ -f "$PLIST_FILE" ]; then
            launchctl unload -w "$PLIST_FILE" >/dev/null 2>&1 || true 
            if ! grep -q "<string>/dev/null</string>" "$PLIST_FILE" 2>/dev/null; then
                info "正在删除日志文件 (如果存在且未配置为 /dev/null)..."
                rm -f "$LOG_FILE" "$ERROR_LOG_FILE"
            fi
            info "正在删除 launchd plist 文件..."
            rm -f "$PLIST_FILE"
        elif launchctl print "gui/$(id -u)/${PLIST_LABEL}" > /dev/null 2>&1 ; then 
             launchctl unload -w "gui/$(id -u)/${PLIST_LABEL}" >/dev/null 2>&1 || true 
             info "Launchd plist 文件 ${PLIST_FILE} 未找到，但尝试通过标签卸载服务。"
        else
            info "Launchd plist 文件 ${PLIST_FILE} 未找到，服务可能未设置，跳过服务删除。"
        fi
    fi

    info "正在删除可执行文件..."
    for exe in "${SS_EXECUTABLES[@]}"; do
        if [ -f "${INSTALL_DIR}/${exe}" ]; then
            $SUDO_CMD rm -f "${INSTALL_DIR}/${exe}"
        fi
    done

    info "正在删除配置文件目录..."
    if [ -d "$CONFIG_DIR" ]; then
        if [[ "$CONFIG_DIR" == "$HOME"* ]]; then 
            rm -rf "$CONFIG_DIR"
        else 
            $SUDO_CMD rm -rf "$CONFIG_DIR"
        fi
    else
        info "配置文件目录 ${CONFIG_DIR} 未找到。"
    fi

    success "Shadowsocks-Rust 已卸载。"
}


generate_clash_config_from_file() {
    if [ ! -f "$CONFIG_FILE" ]; then
        error "配置文件 ${CONFIG_FILE} 未找到。请先配置 Shadowsocks (选项 2 或 3)。"
        return 1
    fi
    if ! jq -e . "$CONFIG_FILE" >/dev/null 2>&1; then
        error "配置文件 ${CONFIG_FILE} 存在但格式不正确或为空。"
        return 1
    fi

    info "从 ${CONFIG_FILE} 读取配置..."
    local s_port s_pass s_method public_ip
    s_port=$(jq -r .server_port "$CONFIG_FILE")
    s_pass=$(jq -r .password "$CONFIG_FILE")
    s_method=$(jq -r .method "$CONFIG_FILE")

    public_ip=$(_get_public_ip)
    
    local clash_proxy_name_default="SS-$(echo "$public_ip" | tr '.' '_')-${s_port}"
    if [[ "$public_ip" == "YOUR_SERVER_IP" ]]; then
        clash_proxy_name_default="SS-YOUR_SERVER_IP-${s_port}"
    fi

    local clash_proxy_name
    if [[ "$INTERACTIVE_MODE" == "yes" ]]; then
        read -rp "请输入 Clash 中的代理节点名称 (默认为 ${clash_proxy_name_default}): " clash_proxy_name
    fi
    clash_proxy_name=${clash_proxy_name:-$clash_proxy_name_default}

    _generate_full_clash_config "$public_ip" "$s_port" "$s_pass" "$s_method" "$clash_proxy_name"
}

_display_system_info() {
    echo_stdout "\n${C_GREEN}--- 系统信息 ---${C_RESET}"

    echo_stdout "${C_YELLOW}操作系统:${C_RESET}"
    if [[ "$OS_TYPE" == "linux" ]]; then
        if command -v lsb_release &>/dev/null; then
            lsb_release -ds 2>/dev/null | sed 's/^/  /' || \
            ( [ -f /etc/os-release ] && awk -F'=' '/^PRETTY_NAME=/ {gsub(/"/, "", $2); print "  "$2}' /etc/os-release ) || \
            ( [ -f /etc/redhat-release ] && sed 's/^/  /' /etc/redhat-release ) || \
            echo_stdout "  $(uname -srp)"
        elif [ -f /etc/os-release ]; then
            awk -F'=' '/^PRETTY_NAME=/ {gsub(/"/, "", $2); print "  "$2}' /etc/os-release
        elif [ -f /etc/redhat-release ]; then
            sed 's/^/  /' /etc/redhat-release
        else
            echo_stdout "  $(uname -srp)"
        fi
    elif [[ "$OS_TYPE" == "macos" ]]; then
        echo_stdout "  产品名称: $(sw_vers -productName)"
        echo_stdout "  产品版本: $(sw_vers -productVersion)"
        echo_stdout "  构建版本: $(sw_vers -buildVersion)"
    fi
    echo_stdout "  内核版本: $(uname -r)"
    echo_stdout "  架构: $(uname -m)"

    echo_stdout "${C_YELLOW}CPU 信息:${C_RESET}"
    if [[ "$OS_TYPE" == "linux" ]]; then
        if command -v lscpu &>/dev/null; then
            echo_stdout -n "  型号: "
            lscpu | grep "Model name:" | sed -E 's/Model name:[[:space:]]+//'
            echo_stdout -n "  核心数: "
            lscpu | grep "^CPU(s):" | sed -E 's/CPU\(s\):[[:space:]]+//'
            local freq=$(lscpu | grep "CPU max MHz:" | sed -E 's/CPU max MHz:[[:space:]]+//')
            [ -n "$freq" ] && echo_stdout "  最大频率: ${freq} MHz"
        elif [ -f /proc/cpuinfo ]; then
            echo_stdout -n "  型号: "
            grep "model name" /proc/cpuinfo | head -n1 | cut -d: -f2 | xargs
            echo_stdout -n "  核心数: "
            grep -c "^processor" /proc/cpuinfo
        else
            echo_stdout "  无法获取详细 CPU 信息。"
        fi
    elif [[ "$OS_TYPE" == "macos" ]]; then
        echo_stdout "  型号: $(sysctl -n machdep.cpu.brand_string)"
        echo_stdout "  物理核心: $(sysctl -n hw.physicalcpu)"
        echo_stdout "  逻辑核心 (线程): $(sysctl -n hw.logicalcpu)"
    fi

    echo_stdout "${C_YELLOW}内存信息:${C_RESET}"
    if [[ "$OS_TYPE" == "linux" ]]; then
        if command -v free &>/dev/null; then
            free -h | awk '/^Mem:/ {print "  总计: " $2 ", 可用: " $7 ", 已用: " $3} /^Swap:/ {print "  Swap: " $2 ", 已用: " $3 " (空闲: " $4 ")"}'
        elif [ -f /proc/meminfo ]; then
            awk '/MemTotal/ {total=$2/1024/1024; printf "  总计: %.2f GB\n", total}
                 /MemAvailable/ {avail=$2/1024/1024; printf "  可用: %.2f GB\n", avail}
                 /SwapTotal/ {stotal=$2/1024/1024; if(stotal>0) printf "  Swap总计: %.2f GB\n", stotal}
                 /SwapFree/ {sfree=$2/1024/1024; if(stotal>0) printf "  Swap可用: %.2f GB\n", sfree}' /proc/meminfo
        else
            echo_stdout "  无法获取内存信息。"
        fi
    elif [[ "$OS_TYPE" == "macos" ]]; then
        local total_mem_gb=$(sysctl -n hw.memsize | awk '{printf "%.2f", $1/1024/1024/1024}')
        echo_stdout "  总计: ${total_mem_gb} GB"
        top -l 1 -s 0 | awk '/PhysMem/ {print "  概览 (top): " $2 " Total, " $6 " Free, " $10 " Used"}'
    fi

    echo_stdout "${C_YELLOW}存储信息 (根分区 /):${C_RESET}"
    df -h / | awk 'NR>1 {print "  总计: " $2 ", 已用: " $3 " (" $5 "), 可用: " $4}'
    
    echo_stdout "${C_YELLOW}GPU 信息:${C_RESET}"
    local gpu_info_found=0
    if [[ "$OS_TYPE" == "linux" ]]; then
        if command -v nvidia-smi &>/dev/null; then
            echo_stdout "  NVIDIA GPU(s):"
            nvidia-smi -L | sed 's/^/    /'
            gpu_info_found=1
        fi
        if command -v lspci &>/dev/null; then
            local lspci_gpu_info
            lspci_gpu_info=$(lspci -vnn | grep -iA10 'VGA compatible controller\|3D controller\|Display controller' | grep -E 'Device Name:|Subsystem:|Kernel driver in use:|VGA|3D|Display|\[[0-9a-f]{4}:[0-9a-f]{4}\]')
            if [ -n "$lspci_gpu_info" ]; then
                echo_stdout "  通用显卡信息 (lspci):"
                echo "$lspci_gpu_info" | sed 's/^/    /' | sed '/^\s*$/d'
                gpu_info_found=1
            fi
        fi
    elif [[ "$OS_TYPE" == "macos" ]]; then
        local mac_gpu_info
        mac_gpu_info=$(system_profiler SPDisplaysDataType 2>/dev/null | grep -E "Chipset Model:|VRAM \(Total\)|Vendor:|Metal Family:")
        if [ -n "$mac_gpu_info" ]; then
            echo_stdout "  显卡信息 (system_profiler):"
            echo "$mac_gpu_info" | sed -e 's/^[[:space:]]*//' -e 's/^/    /'
            gpu_info_found=1
        fi
    fi
    if [[ "$gpu_info_found" -eq 0 ]]; then
        echo_stdout "  未能自动检测到详细 GPU 信息。您可能需要特定工具 (如 radeontop, intel_gpu_top)。"
    fi
    echo_stdout ""
}


# --- Main Menu ---
main_menu() {
    echo_stdout "\n${C_YELLOW}Shadowsocks-Rust (ssserver) 管理脚本${C_RESET}"
    echo_stdout "-------------------------------------"
    echo_stdout "1. 安装/更新 Shadowsocks-Rust"
    echo_stdout "2. 自动配置 Shadowsocks (覆盖现有配置)"
    echo_stdout "3. 手动配置 Shadowsocks (覆盖现有配置)"
    echo_stdout "4. 设置/更新系统服务 (systemd/launchd)"
    echo_stdout "-------------------------------------"
    echo_stdout " 服务管理 (需要先通过选项4设置服务):"
    echo_stdout "   s) 启动服务          p) 停止服务"
    echo_stdout "   r) 重启服务          t) 查看服务状态"
    echo_stdout "   l) 查看服务日志"
    echo_stdout "   e) 设置开机自启      d) 取消开机自启"
    echo_stdout "-------------------------------------"
    echo_stdout "   i) 显示当前配置信息 (ss://, QR, Clash提示)"
    echo_stdout "   c) 生成完整 Clash 配置文件 (YAML)"
    echo_stdout "   m) 显示系统信息"
    echo_stdout "   u) 卸载 Shadowsocks-Rust"
    echo_stdout "   q) 退出"
    echo_stdout "-------------------------------------"
    read -rp "请选择操作: " choice

    case "$choice" in
        1) download_and_install_ss ;;
        2) configure_shadowsocks_auto ;;
        3) configure_shadowsocks_manual ;;
        4) setup_service ;;
        s|S) manage_service "start" ;;
        p|P) manage_service "stop" ;;
        r|R) manage_service "restart" ;;
        t|T) manage_service "status" ;;
        l|L) manage_service "log" ;;
        e|E) manage_service "enable" ;;
        d|D) manage_service "disable" ;;
        i|I) 
            if [ -f "$CONFIG_FILE" ]; then
                if jq -e . "$CONFIG_FILE" >/dev/null 2>&1; then
                    local s_addr s_port s_pass s_method
                    s_addr=$(jq -r .server "$CONFIG_FILE")
                    s_port=$(jq -r .server_port "$CONFIG_FILE")
                    s_pass=$(jq -r .password "$CONFIG_FILE")
                    s_method=$(jq -r .method "$CONFIG_FILE")
                    _display_config_info "$s_addr" "$s_port" "$s_pass" "$s_method"
                else
                    error "配置文件 ${CONFIG_FILE} 存在但格式不正确或为空。"
                fi
            else
                error "配置文件 ${CONFIG_FILE} 未找到。请先运行配置选项 (2 或 3)。"
            fi
            ;;
        c|C) generate_clash_config_from_file ;;
        m|M) _display_system_info ;;
        u|U) uninstall_shadowsocks ;;
        q|Q) exit 0 ;;
        *) error "无效的选择。" ;;
    esac
}

# --- Script Entry Point ---
main() {
    trap 'echo -e "\n${C_YELLOW}操作被中断。${C_RESET}" >&2; exit 130' INT

    if [[ -n "$1" ]]; then 
        INTERACTIVE_MODE="no"
    else
        INTERACTIVE_MODE="yes"
    fi

    detect_os_arch
    check_sudo 

    check_command "curl"
    check_command "jq"
    check_command "tar"

    # Create config directory for macOS if it's in HOME and doesn't exist, and we are not sudo
    # This helps avoid sudo prompts for initial config dir creation on macOS if not needed.
    if [ "$OS_TYPE" == "macos" ] && [ ! -d "$CONFIG_DIR" ] && [ -z "$SUDO_CMD" ]; then
        if [[ "$CONFIG_DIR" == "$HOME"* ]]; then
             mkdir -p "$CONFIG_DIR"
        fi
    fi

    if [[ "$INTERACTIVE_MODE" == "no" ]]; then 
        case "$1" in
            install) download_and_install_ss ;;
            config-auto) configure_shadowsocks_auto ;;
            config-manual) configure_shadowsocks_manual ;;
            setup-service) setup_service ;;
            start) manage_service "start" ;;
            stop) manage_service "stop" ;;
            restart) manage_service "restart" ;;
            status) manage_service "status" ;;
            logs) manage_service "log" ;;
            enable) manage_service "enable" ;;
            disable) manage_service "disable" ;;
            info) 
                if [ -f "$CONFIG_FILE" ]; then
                     if jq -e . "$CONFIG_FILE" >/dev/null 2>&1; then
                        local s_addr s_port s_pass s_method
                        s_addr=$(jq -r .server "$CONFIG_FILE")
                        s_port=$(jq -r .server_port "$CONFIG_FILE")
                        s_pass=$(jq -r .password "$CONFIG_FILE")
                        s_method=$(jq -r .method "$CONFIG_FILE")
                        _display_config_info "$s_addr" "$s_port" "$s_pass" "$s_method"
                    else
                         error "配置文件 ${CONFIG_FILE} 存在但格式不正确或为空。"
                    fi
                else
                    error "配置文件 ${CONFIG_FILE} 未找到。"
                fi
                ;;
            clash-config) generate_clash_config_from_file ;;
            sysinfo) _display_system_info ;;
            uninstall) uninstall_shadowsocks ;;
            --help|-h|help)
                echo_stdout "用法: $0 [命令]"
                echo_stdout "可用命令:"
                echo_stdout "  install          下载并安装/更新 shadowsocks-rust"
                echo_stdout "  config-auto      自动配置 shadowsocks (ssserver)"
                echo_stdout "  config-manual    手动配置 shadowsocks (ssserver)"
                echo_stdout "  setup-service    设置/更新系统服务 (systemd/launchd)"
                echo_stdout "  start            启动服务"
                echo_stdout "  stop             停止服务"
                echo_stdout "  restart          重启服务"
                echo_stdout "  status           查看服务状态"
                echo_stdout "  logs             查看服务日志"
                echo_stdout "  enable           设置服务开机自启"
                echo_stdout "  disable          取消服务开机自启"
                echo_stdout "  info             显示当前配置信息 (包括Clash生成提示)"
                echo_stdout "  clash-config     从现有配置生成完整Clash YAML文件内容"
                echo_stdout "  sysinfo          显示当前系统硬件和软件信息"
                echo_stdout "  uninstall        卸载 shadowsocks-rust"
                echo_stdout "  (无参数)         显示交互式菜单"
                ;;
            *) error "未知参数: $1. 使用 '$0 --help' 查看帮助。" ;;
        esac
    else 
        while true; do
            main_menu
            read -n 1 -s -r -p "按任意键返回主菜单或按 q 退出..." key_press
            if [[ "$key_press" == "q" ]] || [[ "$key_press" == "Q" ]]; then
                echo_stdout "\n退出脚本。"
                break
            fi
            echo_stdout "" # Newline for readability after key press
        done
    fi
}

# Ensure script is run with bash
if [ -z "$BASH_VERSION" ]; then
    echo -e "${C_RED}[ERROR]${C_RESET} 请使用 bash 运行此脚本: bash $0" >&2
    exit 1
fi

main "$@"
