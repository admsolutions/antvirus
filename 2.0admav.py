# Imports do sistema
import os
import sys
import time
import re
import hashlib
import threading
import datetime
from collections import deque
from urllib.parse import urlparse

# Imports para funcionalidades específicas
import psutil
import win32evtlog
import winreg
import requests
import numpy as np

# Imports para monitoramento de arquivos
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Imports PyQt6
from PyQt6.QtWidgets import (
    QApplication, 
    QMainWindow, 
    QWidget, 
    QVBoxLayout, 
    QHBoxLayout, 
    QPushButton, 
    QLabel, 
    QProgressBar, 
    QTextEdit, 
    QFrame,
    QMessageBox,
    QPlainTextEdit,
    QInputDialog,  # Adicionado
    QLineEdit
)
from PyQt6.QtCore import (
    Qt, 
    QThread, 
    QTimer,
    QObject,
    QRunnable,
    pyqtSignal,
    pyqtSlot,  # Adicionado
    QMetaObject,
    Q_ARG,
    QCoreApplication,
    QFile
)
from PyQt6.QtGui import QFont, QColor

# Import para tema dark
import qdarkstyle
import asyncio
import aiohttp



# Adicione nas constantes no início do arquivo
TRUSTED_PROCESSES = {
    'avp.exe': 'Kaspersky Antivirus',
    'supremo.exe': 'Supremo Remote Desktop',
    'supremohelper.exe': 'Supremo Remote Desktop',
    'anydesk.exe': 'AnyDesk Remote Access',
    'antspy.py': 'ADM Solutions Antivirus',  # Nosso próprio antivírus
    '2.0admav.py': 'ADM Solutions Antivirus',  # Versão 2.0 do nosso antivírus
    'gcapi.dll': 'Dll Anydesk',
    'anydeskexe': 'Anydesk'
    }


BEHAVIOR_PATTERNS = {
    'file_operations': [
        'write', 'delete', 'modify', 'execute',
        'create_file', 'delete_file', 'rename_file'
    ],
    'network_operations': [
        'connect', 'listen', 'send', 'receive',
        'download', 'upload'
    ],
    'system_operations': [
        'registry_modify', 'service_create', 'process_inject',
        'privilege_escalation'
    ]
}

NETWORK_THRESHOLDS = {
    'max_connections_per_process': 20,
    'warning_connections_per_process': 10,
    'max_total_connections': 100,
    'suspicious_traffic_mb': 100  # MB por minuto
}

# Configurações das APIs
HYBRID_API_KEY = "1qf9amgdf7a8ce46hja7urbq9458cbacuww44fuv97d1972dayznqmw96cdcc452"
HYBRID_URL = "https://www.hybrid-analysis.com/api/v2/search/hash"

MALSHARE_API_KEY = "5c7b612cbfa57f5fb2a4c3a7dc8d46b3b1da12890220351e8efc70819e29383c"
MALSHARE_URL = "https://malshare.com/api.php"

# Nas constantes do início do arquivo:
URLSCAN_API_KEY = "d412745c-c579-49b7-9166-d47482b5724b"

SUSPICIOUS_SQL_REGISTRY = [
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server"
]

# Adicione esta lista de exceções no início do arquivo
SYSTEM_WHITELIST = {
    # DLLs legítimas do sistema
    "@shell32.dll,-8506",  # Referência legítima do Windows
    "@shell32.dll,-8508",  # Referência legítima do Windows
    "shell32.dll",         # DLL do sistema
    
    # Comandos legítimos do sistema
    "cmd.exe /s /k pushd",  # Comando legítimo para abrir prompt
    "%SystemRoot%\\system32\\cmd.exe"

    # Caminhos do sistema
    r"C:\Windows\System32",
    r"C:\Windows\explorer.exe",

    # Extensões e configurações padrão
    ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",  # PATHEXT padrão
    
    # Caminhos específicos do registro que são seguros
    "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\ComSpec",
    "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\PATHEXT"
}

SUSPICIOUS_REG_PATHS = {
    # Inicialização do Sistema
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
    
    # Políticas do Sistema
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"SYSTEM\CurrentControlSet\Control\Session Manager",
    
    # Services e Drivers
    r"SYSTEM\CurrentControlSet\Services",
    r"SYSTEM\ControlSet001\Services",
    r"SYSTEM\ControlSet002\Services",
    
    # Extensões de Shell e Handlers
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs",
    
    # Configurações do Internet Explorer
    r"SOFTWARE\Microsoft\Internet Explorer\Toolbar",
    r"SOFTWARE\Microsoft\Internet Explorer\Extensions",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Ext\Stats",
    
    # Associações de Arquivo
    r"SOFTWARE\Classes\*\shell\open\command",
    r"SOFTWARE\Classes\exefile\shell\open\command",
    r"SOFTWARE\Classes\htmlfile\shell\open\command",
    
    # Configurações de Rede
    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
    r"SYSTEM\CurrentControlSet\Services\DNS\Parameters",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList",
    
    # Schedule Tasks
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
    
    # Configurações de Segurança
    r"SYSTEM\CurrentControlSet\Control\SecurityProviders",
    r"SOFTWARE\Microsoft\Security Center",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Security",
    
    # Contexto de Menu
    r"SOFTWARE\Classes\Directory\shell",
    r"SOFTWARE\Classes\Directory\background\shell",
    r"SOFTWARE\Classes\*\shell",
    
    # Startup de Usuário
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    
    # LSA e Autenticação
    r"SYSTEM\CurrentControlSet\Control\Lsa",
    r"SECURITY\Policy\Secrets",
    
    # Configurações do Windows Defender
    r"SOFTWARE\Microsoft\Windows Defender",
    r"SOFTWARE\Policies\Microsoft\Windows Defender",
    
    # AppCompatFlags (usado para persistência)
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags",
    
    # Image File Execution Options (usado para hijacking)
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    
    # COM Objects e CLSID
    r"SOFTWARE\Classes\CLSID",
    r"SOFTWARE\Classes\Wow6432Node\CLSID",
    
    # Terminal Server e RDP
    r"SYSTEM\CurrentControlSet\Control\Terminal Server",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server",
    
    # Winlogon Notify
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
    
    # Winsock e Protocolos
    r"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters",
    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
}

# No início do arquivo, junto com as outras constantes:

# Primeiro definimos o SUSPICIOUS_PATTERNS básico
SUSPICIOUS_PATTERNS = [
    r"powershell\s+-\w+\s+hidden",
    r"cmd\.exe\s+/c",
    r"wget\s+http",
    r"curl\s+http",
    r"\.php\?",
    r"\.jsp\?",
    r"base64",
    r"microsoft-edge:",
    r"shell32\.dll",
    r"\.vbs",
    r"\.ps1",
    r"wscript",
]

# Depois adicionamos os novos padrões
ADDITIONAL_PATTERNS = [
    # Comandos suspeitos
    r"regsvr32",
    r"rundll32",
    r"javascript:",
    r"vbscript:",
    r"scrobj\.dll",
    r"shell\.application",
    r"shell32\.dll",
    r"cmd\.exe",
    
    # Codificação e Ofuscação
    r"frombase64string",
    r"convert\.frombase64string",
    r"encodedcommand",
    r"IEX\(",
    r"Invoke-Expression",
    
    # Downloads e Execução Remota
    r"downloadstring",
    r"downloadfile",
    r"system\.net\.webclient",
    r"net\.webrequest",
    r"start-process",
    r"invoke-item",
    
    # Persistência e Evasão
    r"new-object",
    r"hidden",
    r"-w hidden",
    r"-windowstyle hidden",
    r"bypass",
    r"-ep bypass",
    r"-executionpolicy bypass",
    
    # Comportamentos Maliciosos Comuns
    r"delete.*shadow",  # Tentativas de deletar shadow copies
    r"wevtutil.*clear", # Limpeza de logs
    r"icacls.*\/grant", # Modificação de permissões
    r"attrib.*\+h",     # Ocultar arquivos
    r"netsh.*firewall", # Modificação de firewall
    r"reg.*delete",     # Modificação do registro
    r"sc.*create"       # Criação de serviços
]

# Agora juntamos os dois
SUSPICIOUS_PATTERNS.extend(ADDITIONAL_PATTERNS)

# Adicione nas constantes do início do arquivo:
NETWORK_TOOLS = {
        'nmap.exe': 'Nmap - Scanner de rede',
        'telnet.exe': 'Telnet - Conexão remota insegura',
        'tftpd32.exe': 'TFTP - Transferência de arquivos',
        'wireshark.exe': 'Wireshark - Análise de rede',
        'wmic.exe': 'WMIC - Gerenciamento remoto',
        'bash.exe': 'Bash - Shell Linux',
        'psexec.exe': 'PsExec - Execução remota',
        'certutil.exe': 'CertUtil - Ferramenta de certificados'
    }

# Adicione nas constantes no início do arquivo:
SUSPICIOUS_SQL_COMMANDS = {
    'xp_cmdshell': 'SQL Server Command Shell',
    'sp_oacreate': 'SQL Server Object Creation',
    'xp_regwrite': 'SQL Server Registry Write',
    'xp_instance_regwrite': 'SQL Server Registry Instance Write',
    'sp_addextendedproc': 'SQL Server Extended Procedure Add'
}

# Adicione no início do arquivo, nas constantes:
SUSPICIOUS_COMMANDS = [
    "invoke-webrequest",
    "wget",
    "curl",
    "net user",
    "net localgroup",
    "reg add",
    "reg delete",
    "sc create",
    "sc delete",
    "wevtutil", # Eventing Command Line Utility
    "wecutil",  # Windows Event Collector Utility
    "eventcreate", # Event Creation Utility
    "Get-WinEvent", # PowerShell Event Log cmdlet
    "Get-EventLog",  # PowerShell Event Log cmdlet antigo
    "Invoke-Expression",
    "IEX",
    "Invoke-Command",
    "ScriptBlock",
    "netsh",
    "netstat",
    "nslookup",
    "taskkill",
    "ping",
    "tracert",
    "schtasks",
    "cacls",
    "cscript",
    "wscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "wmic process",
    "tasklist",
    "Get-Process",
    "sc query",
    "sc config",
    "tftp",
    "arp",
    "route",
    "net use",
    "net view",
    "netsh advfirewall",
    "Set-NetFirewallRule",
    "Get-NetFirewallRule",
    "proxycfg",
    "netsh winhttp",
    "net accounts",
    "Get-Localuser",
    "Set-Localuser",
    "msiexec",
    "powershell -encodedcommand",
    "base64",
    "certutil -encode",
    "certutil -decode",
    "klist",
    "nltest",
    "runas",
    "whoami",
    "certreq",
    "dsquery",
    "Get-EventSubscriber",
    "Clear-Eventlog",
    "Remove-Item",
    "sp_configure",
    "xp_cmdshell"
]

# Caminhos e processos
COMMON_PATHS = [
    "C:\\Windows\\System32",
    "C:\\Windows",
    "C:\\Users\\Public",
    "C:\\Program Files",
    "C:\\Program Files (x86)"
]

SUSPICIOUS_PROCESS_NAMES = {"nc.exe", "netcat.exe"}
IGNORED_PROCESSES = {"python.exe", "2.0admav.py"}
# Primeiro, vamos expandir a lista de processos críticos que NUNCA devem ser finalizados:
CRITICAL_PROCESSES = {
    "lsass.exe",          # Segurança do Windows
    "csrss.exe",          # Interface Windows
    "wininit.exe",        # Inicialização Windows
    "winlogon.exe",       # Login Windows
    "services.exe",       # Serviços Windows
    "svchost.exe",        # Host de Serviços
    "explorer.exe",       # Explorer
    "dwm.exe",           # Desktop Window Manager
    "taskmgr.exe",       # Gerenciador de Tarefas
    "sihost.exe",        # Shell Infrastructure Host
    "fontdrvhost.exe",   # Font Driver Host
    "spoolsv.exe",       # Spooler de Impressão
    "smss.exe",          # Session Manager
    "conhost.exe",       # Console Host
    "dllhost.exe",       # COM Surrogate
    "RuntimeBroker.exe", # Runtime Broker
    "SearchIndexer.exe", # Windows Search
    "WmiPrvSE.exe",     # WMI Provider
    "dasHost.exe",      # Device Association
    "System",           # Processo System
    "Registry",         # Registro do Windows
    "Idle"             # Processo Idle
}

# IDs do processo atual
CURRENT_PID = os.getpid()
PARENT_PID = psutil.Process(CURRENT_PID).ppid()

class BehaviorAnalyzer:
    def __init__(self, parent):
        self.parent = parent
        self.valid_pids_cache = set()
        self.last_cache_time = 0  
        self.cache_duration = 300
        self.behavior_history = deque(maxlen=100)
        self.threat_score = 0
        self.is_active = False
        self._stop_requested = False  # Novo flag para controle de parada
        # Sinais para comunicação com a thread principal
        self.parent.behavior_signal = pyqtSignal(str, bool)

    def analyze_behavior(self, process_info):
        if not self.is_active:
            return 0
            
        score = 0
        if process_info.get('file_ops'):
            score += self._analyze_file_operations(process_info['file_ops'])
        if process_info.get('network_ops'):
            score += self._analyze_network_operations(process_info['network_ops'])
        if process_info.get('system_ops'):
            score += self._analyze_system_operations(process_info['system_ops'])
            
        self.behavior_history.append((process_info, score))
        return score

    
    def start_rootkit_detection(self):
        """Inicia a detecção de rootkits em uma thread QThread"""
        try:
            # Criar thread e worker
            self.rootkit_thread = QThread()
            self.rootkit_worker = MonitorWorker(self.parent)
        
            # Mover worker para a thread
            self.rootkit_worker.moveToThread(self.rootkit_thread)
        
            # Conectar sinais
            self.rootkit_worker.log_signal.connect(self.parent.log)
        
            # Iniciar thread
            self.rootkit_thread.start()
        
            self.parent.log("[INFO] Detecção de rootkits iniciada em segundo plano.")
        except Exception as e:
            self.parent.log(f"[ERRO] Falha ao iniciar detecção de rootkits: {str(e)}")

    def _run_rootkit_detection(self):
        """Executa a detecção de rootkits em uma thread separada"""
        try:
            results = self.detect_rootkits()
            if results:
                if results['hidden_processes']:
                    self.parent.update_log_signal.emit(
                        f"[CRÍTICO] Processos ocultos detectados: {len(results['hidden_processes'])}", 
                        True
                    )
                if results['system_hooks']:
                    self.parent.update_log_signal.emit(
                        f"[CRÍTICO] Hooks suspeitos detectados: {len(results['system_hooks'])}", 
                        True
                    )
                if results['kernel_modules']:
                    self.parent.update_log_signal.emit(
                        f"[CRÍTICO] Módulos suspeitos do kernel detectados: {len(results['kernel_modules'])}", 
                        True
                    )
        except Exception as e:
            self.parent.update_log_signal.emit(f"[ERRO] Erro na detecção de rootkits: {str(e)}", True)

    def detect_behavior(self):
        """Detecta comportamentos suspeitos"""
        try:
            if self.parent is not None:
                self.parent.signals.update_text_signal.emit(
                    "[INFO] Detecção de comportamento iniciada",
                    "#06daf8",
                    "log"
                )
            return False
        except Exception as e:
            print(f"Erro ao detectar comportamento: {e}")
            return False
        
    

    def check_kernel_modules(self):
        """Verifica drivers carregados no kernel para rootkits"""
        try:
            if os.name != 'nt':
                self.log("[INFO] Verificação de kernel disponível apenas para Windows")
                return []

            try:
                import wmi
            except ImportError:
                self.log("[ERRO] Módulo WMI não encontrado. Instalando...", True)
                try:
                    import subprocess
                    subprocess.check_call(['pip', 'install', 'wmi'])
                    import wmi
                    self.log("[INFO] Módulo WMI instalado com sucesso")
                except Exception as e:
                    self.log(f"[ERRO] Falha ao instalar WMI: {str(e)}", True)
                    return []

            try:
                import pythoncom
                pythoncom.CoInitialize()
            except ImportError:
                self.log("[ERRO] Módulo pywin32 não encontrado", True)
                return []

            try:
                c = wmi.WMI()
                drivers = c.Win32_SystemDriver()
                suspicious_drivers = []

                for driver in drivers:
                    if not driver.Name or not driver.PathName:
                        continue
                
                    path_lower = driver.PathName.lower()
                    # Verifica drivers em locais suspeitos
                    if any(sus_path in path_lower for sus_path in [
                        'temp', 
                        'appdata', 
                        r'\users\public',
                        'programdata\\temp'
                    ]):
                        suspicious_drivers.append({
                            'name': driver.Name,
                            'path': driver.PathName,
                            'status': driver.State,
                            'start_mode': driver.StartMode
                        })
                        self.log(f"[ALERTA] Driver suspeito detectado: {driver.Name} em {driver.PathName}", True)

                if suspicious_drivers:
                    self.log(f"[ALERTA] {len(suspicious_drivers)} drivers suspeitos detectados", True)
                else:
                    self.log("[INFO] Nenhum driver suspeito encontrado")

                return suspicious_drivers

            except Exception as e:
                self.log(f"[ERRO] Falha ao verificar módulos do kernel: {str(e)}", True)
                return []
            finally:
                try:
                    pythoncom.CoUninitialize()  # Limpa recursos COM
                except:
                    pass

        except Exception as e:
            self.log(f"[ERRO] Erro geral na verificação de kernel: {str(e)}", True)
            return []

    def test_rootkit_detection(self):
        """Testa a detecção de rootkit de forma segura"""
        try:
            self.log("[INFO] Iniciando teste de detecção de rootkit...")
            
            # 1. Teste de processos ocultos
            visible_processes = set(p.pid for p in psutil.process_iter())
            if visible_processes:
                self.log("[INFO] Sistema de detecção de processos funcionando")
            
            # 2. Teste de hooks do sistema
            import winreg
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                   r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 
                                   0, 
                                   winreg.KEY_READ)
                winreg.CloseKey(key)
                self.log("[INFO] Sistema de detecção de hooks funcionando")
            except Exception as e:
                self.log(f"[ERRO] Falha no teste de hooks do sistema: {str(e)}", True)
            
            # 3. Teste de módulos do kernel
            drivers = self.check_kernel_modules()
            if drivers is not None:
                self.log("[INFO] Sistema de detecção de drivers funcionando")
            
            self.log("[INFO] Teste de detecção de rootkit concluído")
            return True
            
        except Exception as e:
            self.log(f"[ERRO] Falha no teste de detecção de rootkit: {str(e)}", True)
            return False

    def check_system_hooks(self):
        """
        Verifica possíveis hooks no sistema Windows.
        Retorna uma lista de hooks detectados e o nível de risco.
        """
        hooks_detected = []
        risk_level = 'Baixo'

        if sys.platform == 'win32':  # Apenas para Windows
            try:
                import winreg
                # Lista de chaves críticas a verificar
                keys_to_check = [
                    (r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "ExceptionPortState"),
                    (r"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9", None)
                ]

                for reg_path, value_name in keys_to_check:
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                            if value_name:
                                value = winreg.QueryValueEx(key, value_name)[0]
                                if value != 1:  # Valor esperado
                                    hooks_detected.append(f"Hook detectado em: {reg_path}, Valor: {value}")
                                    risk_level = 'Alto'
                            else:
                                # Verifica se há muitas entradas suspeitas
                                i = 0
                                while True:
                                    try:
                                        winreg.EnumKey(key, i)
                                        i += 1
                                    except WindowsError:
                                        break
                                if i > 20:  # Número suspeito de entradas
                                    hooks_detected.append(f"Possível hook de rede: {reg_path}, Entradas: {i}")
                                    risk_level = 'Alto'
                    except WindowsError:
                        continue
            except Exception as e:
                self.log(f"[ERRO] Falha ao verificar hooks do sistema: {e}")

        return hooks_detected, risk_level


    def log(self, message, threat=False):
        """Método seguro para logging usando os novos sinais"""
        if self.parent and not self._stop_requested:
            # Criar a mensagem formatada aqui
            timestamp = time.strftime("[%H:%M:%S]")
            log_level = "[CRÍTICO]" if threat else "[INFO]"
            formatted_message = f"{timestamp} {log_level} {message}"
            
            self.parent.signals.update_text_signal.emit(
                formatted_message, 
                "#ff3333" if threat else "#06daf8"
            )

    def detect_behavior(self):
        # Exemplo de uso do log
        self.parent.log("[INFO] Detecção de comportamento iniciada")
        try:
            # Lógica simulada
            self.parent.log("[CRÍTICO] Comportamento suspeito detectado!", threat=True)
        except Exception as e:
            self.parent.log(f"[ERRO] Falha ao detectar comportamento: {e}")

    def detect_rootkits(self):
        """Detecta possíveis rootkits de forma otimizada"""
        try:
            if not hasattr(self, '_last_rootkit_check'):
                self._last_rootkit_check = {'last_check': 0}
                self._kernel_module_cache = {'last_check': 0, 'data': []}

            current_time = time.time()
            cooldown = 1800  # 30 minutos

            # Verifica se já passou o tempo de cooldown
            if current_time - self._last_rootkit_check['last_check'] < cooldown:
                return None

            self.log("[INFO] Iniciando verificação de rootkits...")

            results = {
                'hidden_processes': [],
                'system_hooks': [],
                'kernel_modules': [],
                'risk_level': 'Baixo',
                'detection_time': current_time
            }

            # 1. Verificação de processos ocultos
            try:
                visible_pids = set(proc.pid for proc in psutil.process_iter())
                max_pid = max(visible_pids) if visible_pids else 0

                for pid in range(4, max_pid + 100):  # Começar do PID 4 (primeiros são do sistema)
                    if pid not in visible_pids:
                        try:
                            proc = psutil.Process(pid)
                            # Se conseguir acessar o processo mas ele não está na lista visível
                            results['hidden_processes'].append({
                                'pid': pid,
                                'name': proc.name(),
                                'path': proc.exe()
                            })
                            self.log(f"[ALERTA] Processo oculto detectado - PID: {pid}", True)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue

            except Exception as e:
                self.log(f"[ERRO] Falha ao verificar processos ocultos: {str(e)}", True)

            # 2. Verificação de hooks do sistema
            try:
                import winreg
                suspicious_keys = [
                    r"SYSTEM\CurrentControlSet\Services",
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                ]

                for key_path in suspicious_keys:
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                # Verifica por DLLs ou executáveis em locais suspeitos
                                if isinstance(value, str) and ('temp' in value.lower() or 'appdata' in value.lower()):
                                    results['system_hooks'].append({
                                        'key': key_path,
                                        'name': name,
                                        'value': value
                                    })
                                    self.log(f"[ALERTA] Hook suspeito detectado: {key_path}\\{name}", True)
                                i += 1
                            except WindowsError:
                                break
                        winreg.CloseKey(key)
                    except WindowsError:
                        continue

            except Exception as e:
                self.log(f"[ERRO] Falha ao verificar hooks do sistema: {str(e)}", True)

            # 3. Verificação de módulos do kernel
            try:
                if os.name == 'nt':  # Apenas no Windows
                    import wmi
                    c = wmi.WMI()
                    for driver in c.Win32_SystemDriver():
                        if driver.PathName and ('temp' in driver.PathName.lower() or 
                                              'appdata' in driver.PathName.lower()):
                            results['kernel_modules'].append({
                                'name': driver.Name,
                                'path': driver.PathName,
                                'status': driver.State
                            })
                            self.log(f"[ALERTA] Driver suspeito detectado: {driver.Name}", True)

            except Exception as e:
                self.log(f"[ERRO] Falha ao verificar módulos do kernel: {str(e)}", True)

            # Atualizar nível de risco
            if results['hidden_processes'] or results['kernel_modules']:
                results['risk_level'] = 'Alto'
            elif results['system_hooks']:
                results['risk_level'] = 'Médio'

            # Atualizar timestamp da última verificação
            self._last_rootkit_check['last_check'] = current_time

            # Log final
            if results['risk_level'] != 'Baixo':
                self.log(f"[ALERTA] Detecção de rootkit concluída - Nível de risco: {results['risk_level']}", True)
            else:
                self.log("[INFO] Detecção de rootkit concluída - Nenhuma ameaça encontrada")

            return results

        except Exception as e:
            self.log(f"[ERRO] Erro geral na detecção de rootkits: {str(e)}", True)
            return None


    
    def is_valid_pid(self, pid):
        """
        Verifica se um PID é válido usando o comando `tasklist`, com cache.
        """
        current_time = time.time()
    
        # Atualiza o cache se ele estiver expirado
        if current_time - self.last_cache_time > self.cache_duration:
            self.valid_pids_cache = self._update_pid_cache()
            self.last_cache_time = current_time

        # Verifica se o PID está no cache
        return pid in self.valid_pids_cache

    def _update_pid_cache(self):
        """
        Atualiza o cache de PIDs válidos de forma otimizada.
        """
        try:
            valid_pids = {proc.info['pid'] for proc in psutil.process_iter(['pid'])}
            return valid_pids
        except Exception as e:
            self.log(f"[ERRO] Falha ao atualizar cache de PIDs: {e}")
            return set()
                
    def start_monitor_system_health(self):
        """Inicia o monitoramento de saúde do sistema em uma thread separada."""
        if not hasattr(self, '_health_monitor_thread') or not self._health_monitor_thread.is_alive():
            self._health_monitor_thread = threading.Thread(target=self.monitor_system_health, daemon=True)
            self._health_monitor_thread.start()
            self.parent.log("[INFO] Monitoramento de saúde do sistema iniciado em segundo plano.")
        else:
            self.parent.log("[INFO] O monitoramento de saúde do sistema já está em andamento.")
  

    def monitor_system_health(self):
        """Executa o monitoramento contínuo da saúde do sistema."""
        try:
            self.parent.log("[INFO] Iniciando monitoramento de saúde do sistema.")
            while True:
                # Exemplo de lógica de monitoramento (substitua pela sua implementação real)
                cpu_usage = psutil.cpu_percent(interval=1)
                memory_usage = psutil.virtual_memory().percent

                if cpu_usage > 80:
                    self.parent.log(f"[ALERTA] Uso de CPU alto: {cpu_usage}%")
                if memory_usage > 90:
                    self.parent.log(f"[ALERTA] Uso de memória alto: {memory_usage}%")

                time.sleep(5)  # Intervalo entre verificações
        except Exception as e:
            self.parent.log(f"[ERRO] Erro no monitoramento de saúde do sistema: {e}")


    def detect_ransomware_behavior(self):
        """Detecta comportamentos de ransomware de forma otimizada"""
        # Cache para evitar análises repetidas
        if not hasattr(self, '_last_process_check'):
            self._last_process_check = {}
            
        signs = {
            'suspicious_extensions': False,
            'mass_file_operations': False,
            'suspicious_processes': [],
            'risk_level': 'Baixo'
        }

        # Extensões mais comuns de ransomware (reduzidas para otimização)
        SUSPICIOUS_EXTENSIONS = {
            '.encrypted', '.crypto', '.locky', '.wcry', '.wncry', 
            '.crypt', '.locked', '.cerber', '.zepto', '.thor',
            '.aaa', '.abc', '.xyz', '.zzz', '.micro', '.encrypted',
            '.криптед', '.крипт', '.crinf', '.r5a', '.XRNT', '.XTBL',
            '.crypt', '.R16M01D05', '.pzdc', '.good', '.LOL!', '.OMG!',
            '.RDM', '.RRK', '.encryptedRSA', '.crjoker', '.EnCiPhErEd',
            '.LeChiffre', '.keybtc@inbox_com', '.0x0', '.bleep', '.1999',
            '.vault', '.HA3', '.toxcrypt', '.magic', '.SUPERCRYPT', '.CTBL',
            '.CTB2', '.locky', '.petya', '.cry', '.corona', '.nochance'
        }

        # Processos do sistema para ignorar
        IGNORE_PROCESSES = {
            'avp.exe', 'avpui.exe', '2.0admav.exe', 'python.exe',
            'system', 'svchost.exe', 'services.exe', 'csrss.exe'
        }

        try:
            current_time = time.time()

            # Limita a quantidade de processos analisados por vez
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info.get('name', '').lower()

                    # Ignora processos do sistema e verificações recentes
                    if (proc_name in IGNORE_PROCESSES or 
                        current_time - self._last_process_check.get(proc_name, 0) < 60):
                        continue

                    self._last_ransomware_check[proc_name] = current_time

                    files = proc_info.get('open_files', [])
                    if not files or len(files) < 50:
                        continue                  
                 
                    suspicious_files = []
                    suspicious_count = 0

                    # Verifica apenas os primeiros 100 arquivos
                    for file in files[:100]:
                        if any(file.path.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
                            suspicious_files.append(file.path)
                            signs['suspicious_extensions'] = True
                            if len(suspicious_files) >= 3:
                                break

                    if file_count > 200:
                        signs['mass_file_operations'] = True

                    if suspicious_files or file_count > 200:
                        signs['suspicious_processes'].append({
                            'name': proc_name,
                            'pid': proc_info['pid'],
                            'suspicious_files': suspicious_files[:3],
                            'operation_count': file_count
                        })

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception:
                    continue
                
            # Avalia risco geral
            if signs['suspicious_processes']:
                signs['risk_level'] = (
                    'Alto' if signs['suspicious_extensions'] 
                    else 'Médio' if signs['mass_file_operations'] 
                    else 'Baixo'
                )


            return signs
            
        except Exception as e:
            print(f"Erro na detecção de ransomware: {e}")
            return {
                'suspicious_extensions': False,
                'mass_file_operations': False,
                'suspicious_processes': [],
                'risk_level': 'Erro'
            }              

            

    def _should_analyze_process(self, process_name):
        """Verifica se o processo deve ser analisado"""
        if not process_name:
            return False
        
        # Processos para ignorar
        IGNORE_PROCESSES = {
            'avp.exe', 'avpui.exe', 'kavfs.exe',  # Kaspersky
            '2.0admav.exe', 'python.exe', 'pythonw.exe',  # Nosso antivírus
            'system', 'system idle process', 'registry',  # Sistema
            'svchost.exe', 'services.exe', 'csrss.exe'  # Sistema
        }
    
        return process_name.lower() not in IGNORE_PROCESSES

    def detect_brute_force(self):
        """Detecta tentativas de força bruta de login"""
        try:
            server = 'localhost'
            logtype = 'Security'
            failed_attempts = []
    
            # Abre o log de segurança
            try:
                hand = win32evtlog.OpenEventLog(server, logtype)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            except Exception as e:
                self.log(f"[ERRO] Falha ao abrir log de segurança: {str(e)}", True)
                return None

            try:
                # Define uma janela de tempo (últimos 5 minutos)
                time_window = datetime.datetime.now() - datetime.timedelta(minutes=5)
            
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                for event in events:
                    if event.EventID == 4625:  # ID de falha de login
                        event_time = event.TimeGenerated
                    
                        # Verifica se está dentro da janela de tempo
                        if event_time > time_window:
                            failed_attempts.append({
                                'time': event_time,
                                'user': event.StringInserts[5] if event.StringInserts else 'Unknown',
                                'source': event.StringInserts[19] if event.StringInserts else 'Unknown',
                                'status': event.StringInserts[7] if event.StringInserts else 'Unknown'
                            })
            except Exception as e:
                self.log(f"[ERRO] Falha ao ler eventos de log: {str(e)}", True)
            finally:
                win32evtlog.CloseEventLog(hand)
        
            # Analisa as tentativas encontradas
            analysis_result = self.analyze_login_attempts(failed_attempts)
            if analysis_result:
                for alert in analysis_result:
                    self.log(
                        f"[ALERTA] Possível tentativa de força bruta detectada!\n"
                        f"Usuário: {alert['user']}\n"
                        f"Tentativas: {alert['attempts']}\n"
                        f"Última tentativa: {alert['last_attempt']}\n"
                        f"Origem: {alert['source']}", 
                        True
                    )
        
            return analysis_result
    
        except Exception as e:
            self.log(f"[ERRO] Erro ao detectar força bruta: {str(e)}", True)
            return None
        
    def monitor_file_access(self):
        """Monitora e analisa padrões suspeitos de acesso a arquivos"""
        suspicious_patterns = []
    
        # Diretórios sensíveis para monitoramento especial
        SENSITIVE_DIRS = [
            r"C:\Windows\System32",
            r"C:\Windows\System",
            r"C:\Program Files",
            r"C:\Program Files (x86)",
            os.path.expanduser("~\\Documents"),
            os.path.expanduser("~\\Desktop")
        ]
    
        try:
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    # Ignora processos do sistema
                    if proc.pid <= 4 or proc.name().lower() in CRITICAL_PROCESSES:
                        continue
                    
                    files = proc.open_files()
                    if files:
                        # Conta acessos por diretório
                        access_count = {}
                        suspicious_operations = {
                            'write_ops': 0,
                            'delete_ops': 0,
                            'sensitive_access': []
                        }
                    
                        for f in files:
                            try:
                                dir_path = os.path.dirname(f.path)
                                access_count[dir_path] = access_count.get(dir_path, 0) + 1
                            
                                # Verifica operações de escrita
                                if f.mode == 'w':
                                    suspicious_operations['write_ops'] += 1
                                
                                # Verifica acesso a diretórios sensíveis
                                if any(sensitive in f.path for sensitive in SENSITIVE_DIRS):
                                    suspicious_operations['sensitive_access'].append(f.path)
                                
                            except:
                                continue
                    
                        # Analisa padrões suspeitos
                        for dir_path, count in access_count.items():
                            suspicious_level = 'low'
                            reasons = []
                        
                            # Muitos arquivos sendo acessados
                            if count > 50:
                                suspicious_level = 'medium'
                                reasons.append(f"Alto número de acessos ({count} arquivos)")
                            
                            # Muitas operações de escrita
                            if suspicious_operations['write_ops'] > 20:
                                suspicious_level = 'high'
                                reasons.append(f"Muitas operações de escrita ({suspicious_operations['write_ops']})")
                            
                            # Acesso a arquivos sensíveis
                            if suspicious_operations['sensitive_access']:
                                suspicious_level = 'high'
                                reasons.append("Acesso a diretórios sensíveis")
                        
                            if reasons:  # Se encontrou algo suspeito
                                suspicious_patterns.append({
                                    'process': proc.name(),
                                    'pid': proc.pid,
                                    'directory': dir_path,
                                    'access_count': count,
                                    'write_ops': suspicious_operations['write_ops'],
                                    'sensitive_files': suspicious_operations['sensitive_access'][:5],  # Limita a 5 exemplos
                                    'risk_level': suspicious_level,
                                    'reasons': reasons
                                })
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception as e:
                    print(f"Erro ao monitorar processo: {e}")
                    continue
    
            return suspicious_patterns
        
        except Exception as e:
            print(f"Erro no monitoramento de arquivos: {e}")
            return []

    def analyze_login_attempts(self, failed_attempts):
        """Analisa as tentativas de login falhas para detectar padrões suspeitos"""
        if not failed_attempts:
            return None
        
        try:
            # Agrupa tentativas por usuário
            attempts_by_user = {}
            for attempt in failed_attempts:
                user = attempt['user']
                if user not in attempts_by_user:
                    attempts_by_user[user] = []
                attempts_by_user[user].append(attempt)
    
            suspicious_activity = []
    
            for user, attempts in attempts_by_user.items():
                # Analisa número de tentativas
                num_attempts = len(attempts)
            
                # Define níveis de risco baseado no número de tentativas
                if num_attempts >= 5:
                    # Calcula intervalo de tempo entre primeira e última tentativa
                    first_attempt = min(attempt['time'] for attempt in attempts)
                    last_attempt = max(attempt['time'] for attempt in attempts)
                    time_span = (last_attempt - first_attempt).total_seconds()
                
                    # Se houver muitas tentativas em um curto espaço de tempo
                    if num_attempts >= 10 and time_span < 60:  # 10 tentativas em 1 minuto
                        risk_level = 'crítico'
                    elif num_attempts >= 5 and time_span < 300:  # 5 tentativas em 5 minutos
                        risk_level = 'alto'
                    else:
                        risk_level = 'médio'

                    suspicious_activity.append({
                        'user': user,
                        'attempts': num_attempts,
                        'last_attempt': attempts[-1]['time'],
                        'source': attempts[-1]['source'],
                        'risk_level': risk_level,
                        'time_span': time_span
                    })
                
                    # Log baseado no nível de risco
                    self.log(
                        f"[ALERTA] Detectada possível tentativa de força bruta!\n"
                        f"Usuário: {user}\n"
                        f"Tentativas: {num_attempts}\n"
                        f"Intervalo de tempo: {time_span:.1f} segundos\n"
                        f"Nível de risco: {risk_level.upper()}\n"
                        f"Origem: {attempts[-1]['source']}", 
                        True
                    )

            return suspicious_activity
    
        except Exception as e:
            self.log(f"[ERRO] Falha na análise de tentativas de login: {str(e)}", True)
            return None
    
    def analyze_process_behavior(self):
        if not hasattr(self, '_last_process_alert'):
            self._last_process_alert = {}
            self._process_alert_cooldown = 30

        # Processos do sistema para ignorar completamente
        SYSTEM_IGNORE = {
            'system', 'system idle process', 'registry', 'memory compression',
            'secure system', 'csrss.exe', 'wininit.exe', 'services.exe',
            'lsass.exe', 'svchost.exe'
        }

        # Outros processos confiáveis
        TRUSTED_PROCESSES = {
            'avp.exe', 'avpui.exe', 'kavfs.exe',  # Kaspersky
            '2.0admav.exe', 'python.exe', 'pythonw.exe'  # Nosso antivírus
        }

        current_time = time.time()
        process_patterns = {
            'spawning': [],
            'resource_hogs': [],
            'suspicious_paths': [],
            'high_threads': [],
            'risk_score': 0,
            'risk_level': 'Baixo'
        }

        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 
                                        'num_threads', 'exe']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info.get('name', '').lower()
                    if proc_name == "avp.exe":
                        continue
                
                    # Ignora processos do sistema e confiáveis
                    if (proc_name in SYSTEM_IGNORE or 
                        proc_name in TRUSTED_PROCESSES or
                        current_time - self._last_process_alert.get(proc_name, 0) < self._process_alert_cooldown):
                        continue
                
                    # Verifica CPU/memória apenas para processos não-sistema
                    if proc_info.get('cpu_percent', 0) > 85 or proc_info.get('memory_percent', 0) > 85:
                        process_patterns['resource_hogs'].append({
                            'name': proc_name,
                            'pid': proc_info.get('pid', 0),
                            'cpu': proc_info.get('cpu_percent', 0),
                            'memory': proc_info.get('memory_percent', 0)
                        })
                        self._last_process_alert[proc_name] = current_time
                
                except:
                    continue
            
            process_patterns['resource_hogs'] = process_patterns['resource_hogs'][:3]
            process_patterns['risk_score'] = len(process_patterns['resource_hogs']) * 2
            process_patterns['risk_level'] = (
                'Alto' if process_patterns['risk_score'] > 8 
                else 'Médio' if process_patterns['risk_score'] > 4 
                else 'Baixo'
            )
        
            return process_patterns
         
        except Exception:
            return self._get_default_process_patterns()

        
    def _get_default_process_patterns(self):
        return {
            'spawning': [],
            'resource_hogs': [],
            'suspicious_paths': [],
            'high_threads': [],
            'risk_score': 0,
            'risk_level': 'Erro'
        }

    def get_startup_items(self):
        """Obtém lista de itens da inicialização"""
        startup_items = set()
        try:
            import winreg
            startup_paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            ]
        
            for path in startup_paths:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ)
                    try:
                        i = 0
                        while True:
                            name, _, _ = winreg.EnumValue(key, i)
                            startup_items.add(name)
                            i += 1
                    except WindowsError:
                        pass
                    winreg.CloseKey(key)
                except WindowsError:
                    continue
        except:
            pass
        return startup_items

    def get_scheduled_tasks(self):
        """Obtém lista de tarefas agendadas"""
        import subprocess
        
        tasks = set()
        try:            
            # Executa o comando 'schtasks' para listar tarefas em formato CSV
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'csv'],
                capture_output=True,
                text=True,
                check=True  # Garante que erros no comando serão tratados
            )

            # Divide a saída em linhas e ignora a primeira (cabeçalho)
            lines = result.stdout.splitlines()
            if len(lines) > 1:  # Verifica se há dados além do cabeçalho
                for line in lines[1:]:
                    columns = line.split('","')  # CSV entre aspas
                    if columns and len(columns) > 0:
                        task_name = columns[0].strip('"')  # Remove aspas ao redor
                        tasks.add(task_name)

        except subprocess.CalledProcessError as e:
            # Captura erros na execução do comando 'schtasks'
            self.log(f"[ERRO] Falha ao executar 'schtasks': {e}")
        except Exception as e:
            # Captura qualquer outro erro
            self.log(f"[ERRO] Falha ao processar tarefas agendadas: {e}")

        return tasks

    def get_installed_software(self):
        """Obtém lista de software instalado"""
        software = set()
        try:
            import winreg
            paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ]
        
            for path in paths:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ)
                    for i in range(0, winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey = winreg.OpenKey(key, subkey_name)
                            try:
                                software.add(winreg.QueryValueEx(subkey, "DisplayName")[0])
                            except:
                                pass
                            winreg.CloseKey(subkey)
                        except:
                            continue
                    winreg.CloseKey(key)
                except:
                    continue
        except:
            pass
        return software

    def monitor_system_changes(self):
        """Monitora mudanças no sistema"""
        try:
            current_state = {
                'running_services': set(service.name() for service in psutil.win_service_iter()),
                'startup_items': self.get_startup_items(),
                'scheduled_tasks': self.get_scheduled_tasks(),
                'installed_software': self.get_installed_software()
            }
        
            changes = []
        
            if not hasattr(self, 'last_state'):
                self.last_state = current_state
            else:
                # Verifica novos serviços
                new_services = current_state['running_services'] - self.last_state['running_services']
                if new_services:
                    changes.append({
                        'type': 'service',
                        'message': f"Novos serviços detectados: {', '.join(new_services)}",
                        'items': new_services,
                        'risk_level': 'high'
                    })
            
                # Verifica novos itens de inicialização
                new_startup = current_state['startup_items'] - self.last_state['startup_items']
                if new_startup:
                    changes.append({
                        'type': 'startup',
                        'message': f"Novos itens de inicialização: {', '.join(new_startup)}",
                        'items': new_startup,
                        'risk_level': 'high'
                    })
            
                # Verifica novas tarefas agendadas
                new_tasks = current_state['scheduled_tasks'] - self.last_state['scheduled_tasks']
                if new_tasks:
                    changes.append({
                        'type': 'task',
                        'message': f"Novas tarefas agendadas: {', '.join(new_tasks)}",
                        'items': new_tasks,
                        'risk_level': 'medium'
                    })
            
                # Verifica novo software
                new_software = current_state['installed_software'] - self.last_state['installed_software']
                if new_software:
                    changes.append({
                        'type': 'software',
                        'message': f"Novo software instalado: {', '.join(new_software)}",
                        'items': new_software,
                        'risk_level': 'medium'
                    })
            
                self.last_state = current_state
            
            return changes
        
        except Exception as e:
            print(f"Erro no monitoramento de mudanças: {e}")
            return []

    def monitor_dll_behavior(self):
        """Monitora DLLs carregadas por processos para detectar comportamentos suspeitos"""
        try:
            suspicious_dlls = []
    
            # Lista de DLLs e processos seguros
            SAFE_DLLS = {
                'python3.dll',
                'python311.dll',
                'python312.dll',
                'python313.dll',
                '_ctypes.pyd',
                '_socket.pyd',
                '_ssl.pyd',
                '_queue.pyd',
                '_hashlib.pyd',
                'unicodedata.pyd',
                'select.pyd',
                'python.dll',
                'pythoncom.dll',
                'avp.dll',          # Kaspersky
                'avpui.dll',        # Kaspersky
                'kavfs.dll',        # Kaspersky
                'klsihk.dll',       # Kaspersky
                'kavfsgt.dll',       # Kaspersky
                'gcapi.dll'
            }

            def check_dll_hash(dll_path):
                """Verifica o hash da DLL nas bases de dados de malware"""
                try:
                    # Calcula o hash da DLL
                    with open(dll_path, "rb") as f:
                        dll_hash = hashlib.sha256()
                        while chunk := f.read(8192):
                            dll_hash.update(chunk)
                        file_hash = dll_hash.hexdigest()

                    # Verifica no MalShare
                    malshare_params = {
                        "api_key": MALSHARE_API_KEY,
                        "action": "details",
                        "hash": file_hash
                    }
                    malshare_response = requests.get(MALSHARE_URL, params=malshare_params, timeout=5)
                
                    if malshare_response.status_code == 200 and "ERROR" not in malshare_response.text:
                        self.log(f"[ALERTA] DLL suspeita encontrada no MalShare: {dll_path}", True)
                        return True, "DLL encontrada no MalShare"
                    
                    # Verifica no Hybrid Analysis
                    hybrid_headers = {
                        "api-key": HYBRID_API_KEY,
                        "accept": "application/json"
                    }
                    hybrid_response = requests.post(
                        HYBRID_URL, 
                        headers=hybrid_headers, 
                        json={"hash": file_hash},
                        timeout=5
                    )
                
                    if hybrid_response.status_code == 200:
                        result = hybrid_response.json()
                        if result.get("count", 0) > 0:
                            return True, "DLL encontrada no Hybrid Analysis"
                
                    return False, "DLL não encontrada em bases de malware"
                
                except Exception as e:
                    return None, f"Erro ao verificar DLL: {str(e)}"
        
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    # Ignora processos do sistema
                    if proc.pid <= 4 or proc.name().lower() in CRITICAL_PROCESSES:
                        continue
                        
                    # Ignora nosso próprio processo e Python
                    if proc.name().lower() in {'python.exe', '2.0admav.py', 'pythonw.exe', 'avp.exe'}:                      
                        continue
                        
                    # Verifica DLLs carregadas
                    process = psutil.Process(proc.pid)
                    try:
                        dlls = process.memory_maps()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                    for dll in dlls:
                        try:
                            # Ignora DLLs seguras
                            dll_name = os.path.basename(dll.path).lower()
                            if dll_name in SAFE_DLLS:
                                continue
                            
                            # Lista de locais suspeitos
                            suspicious_locations = [
                                'temp',
                                'downloads',
                                'appdata\\local\\temp',
                                'programdata\\temp',
                                'windows\\temp',
                                'users\\public',
                                'recycle.bin'
                            ]
                        
                            # Ignora DLLs em caminhos seguros
                            safe_paths = {
                                'c:\\windows\\system32',
                                'c:\\windows\\syswow64',
                                'c:\\program files',
                                'c:\\program files (x86)',
                                'c:\\python'
                            }

                            dll_path_lower = dll.path.lower()                        
                            if any(safe_path in dll_path_lower for safe_path in safe_paths):
                                continue
                        
                            if any(sus in dll_path_lower for sus in suspicious_locations):
                                # Verifica a DLL nas bases de malware
                                is_malicious, reason = check_dll_hash(dll.path)
                            
                                risk_level = 'Médio'
                                if is_malicious:
                                    risk_level = 'Crítico'
                                    self.log(f"[ALERTA] DLL maliciosa detectada: {dll.path}", True)
                                elif 'temp' in dll_path_lower:
                                    risk_level = 'Alto'
                                    self.log(f"[ALERTA] DLL em localização suspeita: {dll.path}", True)
                            
                                dll_info = {
                                    'process': proc.name(),
                                    'pid': proc.pid,
                                    'dll_path': dll.path,
                                    'risk_level': risk_level,
                                    'reason': reason if is_malicious else "Local suspeito"
                                }
                                suspicious_dlls.append(dll_info)
                            
                        except Exception as e:
                            self.log(f"[ERRO] Erro ao analisar DLL: {str(e)}", True)
                            continue

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception as e:
                    self.log(f"[ERRO] Erro ao analisar processo: {str(e)}", True)
                    continue
                    
            return suspicious_dlls
            
        except Exception as e:
            self.log(f"[ERRO] Erro no monitoramento de DLLs: {str(e)}", True)
            return []

    def analyze_network(self):
        network_info = []
        total_connections = 0
        suspicious_count = 0
        
        try:
            # Análise por processo
            for proc in psutil.process_iter(['pid', 'name', 'connections']):
                try:
                    connections = proc.connections()
                    if connections:
                        conn_count = len(connections)
                        total_connections += conn_count
                        
                        # Detecta comportamentos suspeitos
                        if conn_count > 10:
                            suspicious_count += 1
                            network_info.append({
                                'process': proc.name(),
                                'pid': proc.pid,
                                'connections': conn_count,
                                'risk_level': 'Alto' if conn_count > 20 else 'Médio'
                            })
                except:
                    continue
                    
            # Análise geral da rede
            net_io = psutil.net_io_counters()
            bytes_sent = net_io.bytes_sent / 1024 / 1024  # Converter para MB
            bytes_recv = net_io.bytes_recv / 1024 / 1024
            
            return {
                'suspicious_processes': network_info,
                'total_connections': total_connections,
                'suspicious_count': suspicious_count,
                'bytes_sent_mb': round(bytes_sent, 2),
                'bytes_recv_mb': round(bytes_recv, 2)
            }
            
        except Exception as e:
            return None    

    def _analyze_file_operations(self, ops):
        score = 0
        suspicious_patterns = {
            'multiple_delete': 5,
            'rapid_create': 3,
            'sensitive_modify': 4
        }
        
        for op in ops:
            if op in BEHAVIOR_PATTERNS['file_operations']:
                score += 1
            if op == 'delete' and len([x for x in ops if x == 'delete']) > 3:
                score += suspicious_patterns['multiple_delete']
                
        return score
    
    def display_system_health(self, health_status):
        """Exibe o status de saúde do sistema na interface"""
        try:
            self.ai_text.delete('1.0', tk.END)
            self.ai_text.insert(tk.END, "=== Status do Sistema ===\n\n")

            # CPU
            cpu_info = health_status.get('cpu', {})
            self.ai_text.insert(tk.END, f"CPU: {cpu_info.get('percent', 0):.1f}%\n")
        
            # Memória
            memory_info = health_status.get('memory', {})
            self.ai_text.insert(tk.END, f"Memória: {memory_info.get('percent', 0):.1f}%\n")
            self.ai_text.insert(tk.END, f"Memória Disponível: {memory_info.get('available', 0):.0f} MB\n")
        
            # Disco
            disk_info = health_status.get('disk', {})
            self.ai_text.insert(tk.END, f"Disco: {disk_info.get('percent', 0):.1f}%\n")

            # Processos com alto consumo de CPU
            high_cpu = cpu_info.get('high_usage_processes', [])
            if high_cpu:
                self.ai_text.insert(tk.END, "\nProcessos com alto uso de CPU:\n")
                for proc in high_cpu:
                    self.ai_text.insert(tk.END, f"- {proc.get('name', 'Unknown')}: {proc.get('cpu_percent', 0):.1f}%\n")

            # Processos com alto consumo de memória
            high_mem = memory_info.get('high_usage_processes', [])
            if high_mem:
                self.ai_text.insert(tk.END, "\nProcessos com alto uso de memória:\n")
                for proc in high_mem:
                    self.ai_text.insert(tk.END, f"- {proc.get('name', 'Unknown')}: {proc.get('memory_percent', 0):.1f}%\n")

            # Nível de risco
            risk_level = health_status.get('risk_level', 'Desconhecido')
            self.ai_text.insert(tk.END, f"\nNível de Risco: {risk_level}")
        
            if risk_level == 'Alto':
                self.ai_text.insert(tk.END, "\n⚠️ ALERTA: Sistema sob estresse!\n")
                if cpu_info.get('percent', 0) > 90:
                    self.ai_text.insert(tk.END, "- CPU em uso crítico\n")
                if memory_info.get('percent', 0) > 90:
                    self.ai_text.insert(tk.END, "- Memória em uso crítico\n")
                if disk_info.get('percent', 0) > 90:
                    self.ai_text.insert(tk.END, "- Disco em uso crítico\n")

        except Exception as e:
            self.log(f"[ERRO] Erro ao exibir status do sistema: {str(e)}")
            self.ai_text.delete('1.0', tk.END)
            self.ai_text.insert(tk.END, "Erro ao exibir status do sistema. Tentando recuperar...")

    
    def monitor_system_health(self):
        try:
            # Cache para evitar alertas repetidos
            if not hasattr(self, '_last_alert_time'):
                self._last_alert_time = {}
                self._process_alert_cooldown = 60  # segundos
        
            current_time = time.time()
            health_status = {
                'cpu': {
                    'percent': psutil.cpu_percent(interval=0.5),
                    'high_usage_processes': []
                },
                'memory': {
                    'percent': psutil.virtual_memory().percent,
                    'available': psutil.virtual_memory().available / (1024 * 1024),
                    'high_usage_processes': []
                },
                'disk': {
                    'percent': 0,
                    'high_io_processes': []
                }
            }

            # Processos com alto consumo (com threshold mais alto)
            for proc in psutil.process_iter(['name', 'cpu_percent', 'memory_percent']):
                try:
                    # Ignora processos já alertados recentemente
                    proc_name = proc.info['name']
                    last_alert = self._last_alert_time.get(proc_name, 0)
                
                    if current_time - last_alert < self._process_alert_cooldown:
                        continue

                    # Só alerta se o consumo for realmente alto
                    if proc.info['cpu_percent'] > 80:
                        health_status['cpu']['high_usage_processes'].append({
                        'name': proc_name,
                        'cpu_percent': proc.info['cpu_percent']
                    })
                    self._last_alert_time[proc_name] = current_time
                    
                    if proc.info.get('memory_percent', 0) > 80:
                        health_status['memory']['high_usage_processes'].append({
                            'name': proc_name,
                            'memory_percent': proc.info['memory_percent']
                        })
                        self._last_alert_time[proc_name] = current_time
                except:
                    continue

            # Limita a quantidade de processos mostrados
            health_status['cpu']['high_usage_processes'] = health_status['cpu']['high_usage_processes'][:3]
            health_status['memory']['high_usage_processes'] = health_status['memory']['high_usage_processes'][:3]

            # Atualiza risco
            health_status['risk_level'] = (
                'Alto' if health_status['cpu']['percent'] > 90 or health_status['memory']['percent'] > 90
                else 'Médio' if health_status['cpu']['percent'] > 75 or health_status['memory']['percent'] > 75
                else 'Baixo'
            )

            return health_status

        except Exception as e:
            print(f"Erro ao monitorar saúde do sistema: {e}")
            return self._get_default_health_status()

    def stop(self):
        """Para o analisador de forma segura"""
        self.is_active = False
        self._stop_requested = True
        self.log("[INFO] Analisador comportamental desativado")

    def _get_default_health_status(self):
        return {
            'cpu': {'percent': 0, 'high_usage_processes': []},
            'memory': {'percent': 0, 'available': 0, 'high_usage_processes': []},
            'disk': {'percent': 0, 'high_io_processes': []},
            'risk_level': 'Erro'
        } 

    def _analyze_network_operations(self, ops):
        score = 0
        suspicious_patterns = {
            'multiple_connections': 4,
            'unusual_ports': 5,
            'data_exfiltration': 6
        }
        
        for op in ops:
            if op in BEHAVIOR_PATTERNS['network_operations']:
                score += 1
                
        return score

    def monitor_ddos(self):
        """Monitora possíveis ataques DDoS"""
        try:
            # Define limiares
            CONNECTION_THRESHOLD = 100  # Número máximo de conexões por processo
            TRAFFIC_THRESHOLD = 1000000  # Bytes por segundo (aproximadamente 1 MB/s)
            TIME_WINDOW = 60  # Janela de tempo em segundos

            # Lista de processos confiáveis/exceções
            TRUSTED_PROCESSES = {
                'system', 
                'svchost.exe', 
                '2.0admav.py', 
                'python.exe',
                'avp.exe',        # Kaspersky
                'avpui.exe',      # Kaspersky UI
                'kavfs.exe',      # Kaspersky
                'kavfsgt.exe',    # Kaspersky
                'kavfsslp.exe'    # Kaspersky
            }

            # Obtém estatísticas de rede atuais
            net_stats = psutil.net_io_counters()
            current_time = time.time()

            # Inicializa contadores se não existirem
            if not hasattr(self, '_last_net_stats'):
                self._last_net_stats = net_stats
                self._last_check_time = current_time
                return

            # Calcula diferenças
            time_diff = current_time - self._last_check_time
            bytes_sent = (net_stats.bytes_sent - self._last_net_stats.bytes_sent) / time_diff
            bytes_recv = (net_stats.bytes_recv - self._last_net_stats.bytes_recv) / time_diff

            suspicious_processes = []

            # Verifica cada processo
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    # Pula processos do sistema e do próprio antivírus
                    proc_name = proc.info['name'].lower()
                    if proc_name in TRUSTED_PROCESSES:
                        continue

                    # Obtém conexões separadamente
                    process = psutil.Process(proc.info['pid'])
                    connections = process.connections()

                    connections = proc.connections()
                    if len(connections) > CONNECTION_THRESHOLD:
                        suspicious_processes.append({
                            'pid': proc.pid,
                            'name': proc.name(),
                            'connections': len(connections),
                            'type': 'high_connections'
                        })
                        self.log(
                            f"[ALERTA] Possível ataque DDoS detectado!\n"
                            f"Processo: {proc.name()} (PID: {proc.pid})\n"
                            f"Conexões: {len(connections)}",
                            True
                        )

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception as e:
                    continue  # Ignora erros específicos de processo

            # Verifica tráfego total
            if bytes_sent > TRAFFIC_THRESHOLD or bytes_recv > TRAFFIC_THRESHOLD:
                self.log(
                    f"[ALERTA] Tráfego de rede suspeito detectado!\n"
                    f"Upload: {bytes_sent/1024:.2f} KB/s\n"
                    f"Download: {bytes_recv/1024:.2f} KB/s",
                    True
                )

                # Se houver processos suspeitos, tenta mitigar
                if suspicious_processes:
                    for proc_info in suspicious_processes:
                        try:
                            proc = psutil.Process(proc_info['pid'])
                            proc.terminate()
                            self.log(
                                f"[AÇÃO] Processo suspeito terminado: {proc_info['name']} (PID: {proc_info['pid']})",
                                True
                            )
                        except:
                            continue

            # Atualiza estatísticas para próxima verificação
            self._last_net_stats = net_stats
            self._last_check_time = current_time

        except Exception as e:
            self.log(f"[ERRO] Falha no monitoramento DDoS: {str(e)}", True)

    def _analyze_system_operations(self, ops):
        score = 0
        critical_patterns = {
            'registry_modify': 5,
            'service_create': 4,
            'process_inject': 6
        }
        
        for op in ops:
            if op in BEHAVIOR_PATTERNS['system_operations']:
                score += 2
                
        return score

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class RansomwareExtensionHandler(FileSystemEventHandler):
    def __init__(self, suspicious_extensions, logger, main_window=None):
        super().__init__()
        self.suspicious_extensions = suspicious_extensions
        self.logger = logger
        self.main_window = main_window
        self._running = True  # Flag para controle

    def stop(self):
        """Para o analisador de forma segura"""
        self.is_active = False
        self._stop_requested = True

    def safe_rename(self, src, dst):
        """Executa renomeação de forma segura"""
        try:
            if os.path.exists(src):
                os.rename(src, dst)
                return True
        except Exception as e:
            self.logger(f"[ERRO] Erro na renomeação segura: {str(e)}", threat=True)
        return False

    def on_moved(self, event):
        """Detecta e reverte mudanças de nome para extensões suspeitas"""
        if not self._running or event.is_directory:
            return

        try:
            dest_path = event.dest_path.lower()
            for ext in self.suspicious_extensions:
                if dest_path.endswith(ext):
                    self.logger(f"[ALERTA] Arquivo renomeado para extensão suspeita: {event.dest_path}", threat=True)
                    
                    # Tenta reverter a renomeação de forma segura
                    if self.safe_rename(event.dest_path, event.src_path):
                        self.logger(f"[AÇÃO] Renomeação revertida: {event.dest_path} -> {event.src_path}", threat=True)
                        
                        # Notifica a interface principal de forma segura
                        if self.main_window and hasattr(self.main_window, 'queue_alert'):
                            self.main_window.queue_alert(
                                "Alerta de Segurança",
                                f"Tentativa de ransomware detectada e bloqueada!\nArquivo: {event.dest_path}"
                            )
                    break
        except Exception as e:
            self.logger(f"[ERRO] Erro no evento de renomeação: {str(e)}", threat=True)

    def on_created(self, event):
        """Detecta e remove arquivos suspeitos recém-criados"""
        if not self._running or event.is_directory:
            return

        try:
            file_path = event.src_path.lower()
            for ext in self.suspicious_extensions:
                if file_path.endswith(ext):
                    self.logger(f"[ALERTA] Arquivo suspeito criado: {event.src_path}", threat=True)
                    
                    try:
                        if os.path.exists(event.src_path):
                            os.remove(event.src_path)
                            self.logger(f"[AÇÃO] Arquivo suspeito removido: {event.src_path}", threat=True)
                            
                            # Notifica a interface principal de forma segura
                            if self.main_window and hasattr(self.main_window, 'queue_alert'):
                                self.main_window.queue_alert(
                                    "Alerta de Segurança",
                                    f"Arquivo suspeito detectado e removido!\nArquivo: {event.src_path}"
                                )
                    except Exception as e:
                        self.logger(f"[ERRO] Falha ao remover arquivo suspeito: {str(e)}", threat=True)
                    break
        except Exception as e:
            self.logger(f"[ERRO] Erro no evento de criação: {str(e)}", threat=True)


class RansomwareProtectionThread(QThread):
    alert_signal = pyqtSignal(str, str)  # (title, message)
    log_signal = pyqtSignal(str, bool)   # (message, is_threat)

    def __init__(self, parent=None):
        self.suspicious_extensions = {
            '.encrypted', '.crypto', '.locky', '.wcry', '.wncry', 
            '.crypt', '.locked', '.cerber', '.zepto', '.thor',
            '.aaa', '.abc', '.xyz', '.zzz', '.micro', '.encrypted',
            '.криптед', '.крипт', '.crinf', '.r5a', '.XRNT', '.XTBL',
            '.crypt', '.R16M01D05', '.pzdc', '.good', '.LOL!', '.OMG!',
            '.RDM', '.RRK', '.encryptedRSA', '.crjoker', '.EnCiPhErEd',
            '.LeChiffre', '.keybtc@inbox_com', '.0x0', '.bleep', '.1999',
            '.vault', '.HA3', '.toxcrypt', '.magic', '.SUPERCRYPT', '.CTBL',
            '.CTB2', '.locky', '.petya', '.cry', '.corona', '.nochance'
        }
    
        super().__init__(parent)
        self.is_running = True        
        self.observer = None
        self.event_handler = None

    def run(self):
        try:
            class SafeHandler(FileSystemEventHandler):
                def __init__(self, thread):
                    super().__init__()
                    self.thread = thread

                def on_moved(self, event):
                    if not event.is_directory:
                        try:
                            dest_path = event.dest_path.lower()
                            for ext in self.thread.suspicious_extensions:
                                if dest_path.endswith(ext):
                                    self.thread.log_signal.emit(
                                        f"[ALERTA] Arquivo renomeado para extensão suspeita: {event.dest_path}",
                                        True
                                    )
                                    
                                    try:
                                        if os.path.exists(event.dest_path):
                                            os.rename(event.dest_path, event.src_path)
                                            self.thread.log_signal.emit(
                                                f"[AÇÃO] Renomeação revertida: {event.dest_path} -> {event.src_path}",
                                                True
                                            )
                                            self.thread.alert_signal.emit(
                                                "Alerta de Segurança",
                                                f"Tentativa de ransomware detectada e bloqueada!\nArquivo: {event.dest_path}"
                                            )
                                    except Exception as e:
                                        self.thread.log_signal.emit(
                                            f"[ERRO] Falha ao reverter renomeação: {str(e)}",
                                            True
                                        )
                                    break
                        except Exception as e:
                            self.thread.log_signal.emit(f"[ERRO] {str(e)}", True)

            path_to_monitor = "C:\\" if os.name == 'nt' else "/"
            self.event_handler = SafeHandler(self)
            self.observer = Observer()
            self.observer.schedule(self.event_handler, path_to_monitor, recursive=True)
            self.observer.start()

            while self.is_running:
                QThread.msleep(1000)  # Verificar a cada segundo

        except Exception as e:
            self.log_signal.emit(f"[ERRO] Erro na thread de proteção: {str(e)}", True)

    def stop(self):
        self.is_running = False
        if self.observer:
            self.observer.stop()
            self.observer.join()

class RegistryScanner:
    def __init__(self, logger):
        self.logger = logger
        self.threats_found = []

    # Modifique a função check_url_with_sucuri:
    def check_url_with_urlscan(self, url):
        try:
            # Remove protocolos e parâmetros para obter apenas o domínio
            url = url.lower()
            url = re.sub(r'https?://', '', url)
            url = url.split('/')[0]  # Pega só o domínio
            url = url.split('?')[0]  # Remove parâmetros query
        
            # URL da API do URLScan.io
            urlscan_search = f"https://urlscan.io/api/v1/search/?q=domain:{url}"
        
            headers = {
                'API-Key': URLSCAN_API_KEY,
                'Content-Type': 'application/json'
            }
        
            response = requests.get(urlscan_search, headers=headers, timeout=10)
        
            if response.status_code == 200:
                data = response.json()
                results = data.get('results', [])
        
                if results:
                    # Pega o resultado mais recente
                    latest = results[0]
        
                    # Verifica por indicadores de malware/phishing
                    verdicts = latest.get('verdicts', {})
                    malicious = verdicts.get('malicious', False)
                
                    if malicious:
                        return True, "URL maliciosa detectada pelo URLScan.io"
                
                    # Verifica score de ameaça
                    threat_score = latest.get('threat', {}).get('score', 0)
                    if threat_score > 50:  # Score alto indica possível ameaça
                        return True, f"URL suspeita (Score de ameaça: {threat_score})"
                
                    return False, "URL verificada e segura"
            
                return None, "URL não encontrada no histórico do URLScan.io"
        
            elif response.status_code == 401:
                return None, "Erro de autenticação com URLScan.io"
            else:
                return None, f"Erro ao verificar URL (Status: {response.status_code})"
            
        except Exception as e:
            return None, f"Erro ao verificar URL: {str(e)}"

    def scan_registry_for_sql(self):
        for path in SUSPICIOUS_SQL_REGISTRY:
            values = self.scan_registry_key(winreg.HKEY_LOCAL_MACHINE, path)
            for name, value, type in values:
                if "xp_cmdshell" in str(value).lower():
                    self.log(f"[ALERTA] Configuração suspeita no registro: {name} = {value}", threat=True)
                    # Opcional: Remover chave suspeita  

    def periodic_disable_xp_cmdshell(self):
        while True:
            self.disable_xp_cmdshell()
            time.sleep(60)  # Verifica a cada 60 segundos       

    def scan_registry_key(self, hive, subkey):
        try:
            key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
            values = []
        
            try:
                i = 0
                while True:
                    name, value, type = winreg.EnumValue(key, i)
                    values.append((name, value, type))
                    i += 1
            except WindowsError:
                pass
        
            winreg.CloseKey(key)
            return values
        
        except WindowsError:
            return []

    # Modifique a função is_suspicious_value para usar a verificação do Sucuri:
    def is_suspicious_value(self, value, key_path=""):
        if key_path in SYSTEM_WHITELIST:
            return False, "Caminho do sistema (whitelist)"

        value = str(value).lower()
    
        # Verificações de whitelist [mantém como está]
        for whitelist_item in SYSTEM_WHITELIST:
            whitelist_item = str(whitelist_item).lower()
            if whitelist_item in value:
                return False, "Valor do sistema (whitelist)"
    
        # Verifica padrões suspeitos [mantém como está]
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                if "cmd.exe" in value and "pushd" in value:
                    return False, "Comando legítimo do sistema"
                return True, f"Padrão suspeito encontrado: {pattern}"
    
        # Verificação de URLs com URLScan.io
        if "http://" in value or "https://" in value or "microsoft-edge:" in value:
            # Primeiro verifica URLs confiáveis do sistema
            if any(trusted in value.lower() for trusted in [
                "windows.com",
                "microsoft.com",
                "msftncsi.com"
            ]):
                return False, "URL confiável do sistema"
            
            # Extrai a URL usando regex
            url_match = re.search(r'https?://([^\s/]+)', value)
            if url_match:
                is_malicious, reason = self.check_url_with_urlscan(url_match.group(1))
                if is_malicious:
                    return True, f"URL maliciosa: {reason}"
                elif is_malicious is False:  # Explicitamente False, não None
                    return False, "URL verificada e segura pelo URLScan.io"
            
            return True, "URL suspeita (não foi possível verificar)"
    
        return False, "Valor seguro"

    def scan(self):
        self.logger("[INFO] Iniciando varredura do registro do Windows...")
        threats = []

        for subkey in SUSPICIOUS_REG_PATHS:
            self.logger(f"[INFO] Verificando: {subkey}")
        
            # Verificar HKLM
            values = self.scan_registry_key(winreg.HKEY_LOCAL_MACHINE, subkey)
            for name, value, type in values:
                is_suspicious, reason = self.is_suspicious_value(value, subkey)
                if is_suspicious:
                    threat = {
                        'location': f"HKLM\\{subkey}",
                        'name': name,
                        'value': value,
                        'reason': reason
                    }
                    threats.append(threat)
                    self.logger(f"[ALERTA] Ameaça encontrada em HKLM\\{subkey}\\{name}")
                    self.logger(f"[INFO] Valor: {value}")
                    self.logger(f"[INFO] Motivo: {reason}")

        return threats


# Adicione a função para desabilitar xp_cmdshell:
def disable_xp_cmdshell(self):
    import pyodbc
    try:
        conn = pyodbc.connect('Driver={SQL Server};Server=localhost;Trusted_Connection=yes;')
        cursor = conn.cursor()
        cursor.execute("sp_configure 'show advanced options', 1;")
        cursor.execute("RECONFIGURE;")
        cursor.execute("sp_configure 'xp_cmdshell', 0;")
        cursor.execute("RECONFIGURE;")
        cursor.execute("sp_configure 'show advanced options', 0;")
        cursor.execute("RECONFIGURE;")
        conn.close()
        self.log("[INFO] xp_cmdshell desabilitado no SQL Server", threat=True)
    except Exception as e:
        self.log(f"[ERRO] Falha ao desabilitar xp_cmdshell: {str(e)}")


def calculate_file_hash(filepath):
    try:
        with open(filepath, "rb") as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(8192):
                file_hash.update(chunk)
            return file_hash.hexdigest()
    except Exception as e:
        return None

from watchdog.events import FileSystemEventHandler
import os

class AntivirusWatchdog(FileSystemEventHandler):
    def __init__(self, suspicious_extensions, logger):
        """
        Inicializa o Watchdog com extensões suspeitas.
        """
        self.suspicious_extensions = suspicious_extensions
        self.logger = logger

    def on_moved(self, event):
        """
        Detecta mudanças de nome de arquivos para extensões suspeitas e reverte.
        """
        if not event.is_directory:
            source_path = event.src_path.lower()
            dest_path = event.dest_path.lower()

            # Verifica se a nova extensão é suspeita
            for ext in self.suspicious_extensions:
                if dest_path.endswith(ext):
                    self.logger(f"[ALERTA] Tentativa de renomear arquivo para extensão suspeita: {source_path} -> {dest_path}", threat=True)
                    
                    # Reverte a renomeação
                    try:
                        os.rename(dest_path, source_path)
                        self.logger(f"[AÇÃO] Renomeação revertida: {dest_path} -> {source_path}", threat=True)
                    except Exception as e:
                        self.logger(f"[ERRO] Falha ao reverter renomeação: {str(e)}")
                    
                    # Opcional: alerta ao usuário
                    messagebox.showerror(
                        "Alerta de Segurança",
                        f"Tentativa de renomear arquivo para extensão suspeita detectada e bloqueada:\n"
                        f"{source_path} -> {dest_path}"
                    )
                    return

class DLLMonitorWorker(QObject):
    dll_alert_signal = pyqtSignal(dict)  # Para enviar resultados
    log_signal = pyqtSignal(str, bool)   # Para logging

    def __init__(self):
        super().__init__()
        self.is_running = True
        self.last_check_time = 0
        self.check_interval = 30  # Intervalo em segundos

    def run(self):
        """Executa o monitoramento de DLLs em thread separada"""
        while self.is_running:
            try:
                current_time = time.time()
                
                # Verifica se já passou o intervalo
                if current_time - self.last_check_time < self.check_interval:
                    QThread.msleep(1000)
                    continue

                self.last_check_time = current_time
                self.check_dlls()
                
                # Pausa entre verificações
                QThread.msleep(1000)

            except Exception as e:
                self.log_signal.emit(f"[ERRO] Erro no monitoramento de DLLs: {str(e)}", True)
                QThread.msleep(5000)

    def check_dlls(self):
        """Verifica DLLs carregadas"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if not self.is_running:
                    break

                try:
                    # Pula processos do sistema
                    if proc.info['name'].lower() in CRITICAL_PROCESSES:
                        continue

                    process = psutil.Process(proc.info['pid'])
                    maps = process.memory_maps()

                    for m in maps:
                        path = m.path.lower()
                        
                        # Verifica locais suspeitos
                        if ('temp' in path or 'appdata' in path):
                            dll_info = {
                                'process': proc.info['name'],
                                'pid': proc.info['pid'],
                                'dll_path': m.path,
                                'risk_level': 'Médio'
                            }
                            self.dll_alert_signal.emit(dll_info)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception:
                    continue

        except Exception as e:
            self.log_signal.emit(f"[ERRO] Falha na verificação de DLLs: {str(e)}", True)

class SignalManager(QObject):
    update_text_signal = pyqtSignal(str, str)  # (message, color)
    update_health_signal = pyqtSignal(dict)

class AntivirusGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # Configurações da janela principal
        self.setWindowTitle("ADM SOLUTIONS SECURITY")
        self.setMinimumSize(1000, 700)

        # Flags de controle
        self.is_shutting_down = False
        self.scanning = False
        self.pause = False
        self.ai_running = False
        self.realtime_protection = True
        
        # Configurações de proteção em tempo real
        self.realtime_configs = {
            'block_powershell': True,
            'block_network_tools': True,
            'block_suspicious_commands': True,
            'monitor_registry': True,
            'monitor_system_files': True,
            'monitor_network': True
        }
        
        # Configurações de segurança
        self.admin_password = "admin"
        
        # Listas e coleções
        self.threats_found = []
        self.pending_updates = []
        self.alert_queue = []

        # Criar gerenciador de sinais
        self.signals = SignalManager()
        
        # Criar elementos básicos da UI
        self.status_label = QLabel("PROTEGIDO")
        self.status_label.setFont(QFont('Segoe UI', 12, QFont.Weight.Bold))
        self.status_label.setStyleSheet("color: #03f8e6; padding: 5px 15px;")
        
        # Configurar interface principal
        self.setup_ui()
        
        # Conectar sinais
        self.signals.update_text_signal.connect(self.safe_update_text)
        self.signals.update_health_signal.connect(self.display_system_health)
        
        # Inicializar módulo de IA
        self.ai_module = BehaviorAnalyzer(self)

        # Inicializar timers
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.process_pending_updates)
        self.update_timer.start(100)
        
        self.alert_timer = QTimer(self)
        self.alert_timer.timeout.connect(self.process_alerts)
        self.alert_timer.start(100)

        # Iniciar proteções básicas
        self.setup_watchdog()
        
        # Usar QTimer para iniciar threads de proteção após a interface estar pronta
        QTimer.singleShot(1000, self.start_protection_threads)

        # Adicionar timer para monitoramento de força bruta
        self.start_brute_force_monitoring()

        # Iniciar monitoramento DDoS
        self.start_ddos_monitoring()
        
        # Bloquear xp cmd
        self.block_xp_cmdshell_registry()

        # Adicionar proteção contra fechamento
        self.setWindowFlags(
            self.windowFlags() | 
            Qt.WindowType.WindowStaysOnTopHint
        )
        
        # Inicializar thread de proteção
        self.start_process_protection()

        # Inicializar memória
        self.start_memory_protection()

       
    def start_process_protection(self):
        """Inicia thread de proteção contra fechamento forçado"""
        self.protection_thread = QThread()
        self.protection_worker = ProcessProtectionWorker()
        self.protection_worker.moveToThread(self.protection_thread)
        
        # Conectar sinais
        self.protection_worker.alert_signal.connect(self.show_protection_alert)
        self.protection_thread.started.connect(self.protection_worker.run)
        
        # Iniciar thread
        self.protection_thread.start()
        self.log("[INFO] Proteção contra fechamento iniciada")

    def start_protection_threads(self):
        """Inicia as threads de proteção de forma segura"""
        try:
            # Thread de proteção contra ransomware
            self.ransomware_thread = RansomwareProtectionThread()
            self.ransomware_thread.alert_signal.connect(self.show_alert)
            self.ransomware_thread.log_signal.connect(self.log)
            self.ransomware_thread.start()
            
            # Thread de proteção em tempo real
            self.realtime_thread = RealtimeProtectionThread()
            self.realtime_thread.alert_signal.connect(self.show_alert)
            self.realtime_thread.log_signal.connect(self.log)
            self.realtime_thread.start()
            
            self.log("[INFO] Threads de proteção iniciadas com sucesso")
            
        except Exception as e:
            self.log(f"[ERRO] Falha ao iniciar threads de proteção: {str(e)}", True)

    def initialize_threads(self):
        """Inicializa as threads de proteção"""
        try:
            # Thread de proteção em tempo real
            self.realtime_thread = RealtimeProtectionThread(None)  # Note o None aqui
            self.realtime_thread.alert_signal.connect(self.show_alert)
            self.realtime_thread.log_signal.connect(self.log)
            self.realtime_thread.start()

            # Thread de proteção contra ransomware
            self.ransomware_thread = RansomwareProtectionThread(None)  # Note o None aqui
            self.ransomware_thread.alert_signal.connect(self.show_alert)
            self.ransomware_thread.log_signal.connect(self.log)
            self.ransomware_thread.start()

            self.threads_initialized = True
            self.log("[INFO] Threads de proteção inicializadas com sucesso")
            
        except Exception as e:
            self.log(f"[ERRO] Falha ao inicializar threads: {str(e)}", True)

    def test_rootkit_system(self):
        if self.ai_module:
            return self.ai_module.test_rootkit_detection()
        return False
    
    def start_memory_protection(self):
        """Inicia a proteção de memória"""
        try:
            # Criar thread e worker
            self.memory_thread = QThread()
            self.memory_worker = MemoryProtectionWorker()
        
            # Mover worker para a thread
            self.memory_worker.moveToThread(self.memory_thread)
        
            # Conectar sinais
            self.memory_worker.alert_signal.connect(self.show_memory_alert)
            self.memory_worker.log_signal.connect(self.log)
        
            # Conectar início da thread
            self.memory_thread.started.connect(self.memory_worker.run)
        
            # Iniciar thread
            self.memory_thread.start()
        
            self.log("[INFO] Proteção de memória iniciada")
        
        except Exception as e:
            self.log(f"[ERRO] Falha ao iniciar proteção de memória: {str(e)}", True)

    @pyqtSlot(str, str)
    def show_memory_alert(self, title, message):
        """Mostra alerta de memória"""
        QMessageBox.warning(self, title, message)


    def start_ddos_monitoring(self):
        """Inicia o monitoramento de DDoS"""
        try:
            self.ddos_timer = QTimer(self)
            self.ddos_timer.timeout.connect(self.check_ddos)
            self.ddos_timer.start(1000)  # Verifica a cada segundo
            self.log("[INFO] Monitoramento DDoS iniciado")
        except Exception as e:
            self.log(f"[ERRO] Falha ao iniciar monitoramento DDoS: {str(e)}", True)

    
    def check_ddos(self):
        """Callback para verificar DDoS"""
        try:
            if self.ai_module and hasattr(self.ai_module, 'monitor_ddos'):
                self.ai_module.monitor_ddos()
        except Exception as e:
            self.log(f"[ERRO] Falha ao verificar DDoS: {str(e)}", True)

    def initialize_timers(self):
        """Inicializa os timers do sistema"""
        # Timer para atualizações pendentes
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.process_pending_updates)
        self.update_timer.start(100)
        
        # Timer para alertas
        self.alert_timer = QTimer()
        self.alert_timer.timeout.connect(self.process_alerts)
        self.alert_timer.start(100)

    def initialize_components(self):
        """Inicializa componentes básicos"""
        # Módulo de IA
        self.ai_module = BehaviorAnalyzer(self)
        
        # Inicializar threads como None
        self.realtime_thread = None
        self.ransomware_thread = None
        self.protection_thread = None

    def block_xp_cmdshell_registry(self):
        """Bloqueia xp_cmdshell através do registro do Windows"""
        try:
            self.log("[INFO] Iniciando bloqueio de xp_cmdshell...")
        
            import winreg
        
            # Chaves do registro para SQL Server
            sql_keys = [
                r"SOFTWARE\Microsoft\Microsoft SQL Server",
                r"SOFTWARE\Wow6432Node\Microsoft\Microsoft SQL Server"  # Para sistemas 64-bit
            ]
        
            # Valores a serem modificados/bloqueados
            block_values = {
                "xp_cmdshell": 0,
                "show advanced options": 0,
                "cmdshell": 0
            }
        
            blocked = False
        
            for key_path in sql_keys:
                try:
                    # Tenta abrir a chave do SQL Server
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, 
                                        winreg.KEY_ALL_ACCESS)
                
                    # Procura por instâncias do SQL Server
                    i = 0
                    while True:
                        try:
                            instance_name = winreg.EnumKey(key, i)
                            instance_path = f"{key_path}\\{instance_name}\\MSSQLServer\\SuperSocketNetLib"
                        
                            try:
                                instance_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                                            instance_path, 0, 
                                                            winreg.KEY_ALL_ACCESS)
                            
                                # Define os valores de bloqueio 
                                for value_name, value_data in block_values.items():
                                    try:
                                        winreg.SetValueEx(instance_key, value_name, 0, 
                                                        winreg.REG_DWORD, value_data)
                                        blocked = True
                                        self.log(f"[INFO] Valor {value_name} bloqueado para instância {instance_name}")
                                    except Exception as e:
                                        self.log(f"[ERRO] Não foi possível definir {value_name}: {str(e)}", True)
                            
                                winreg.CloseKey(instance_key)
                            
                            except Exception as e:
                                self.log(f"[ERRO] Não foi possível acessar instância {instance_name}: {str(e)}", True)
                        
                            i += 1
                        
                        except WindowsError:
                            break
                        
                    winreg.CloseKey(key)
                
                except Exception as e:
                    self.log(f"[ERRO] Não foi possível acessar chave {key_path}: {str(e)}", True)
        
            if blocked:
                self.log("[INFO] Bloqueio de xp_cmdshell concluído com sucesso")
                QMessageBox.information(
                    self,
                    "Proteção SQL Server",
                    "Bloqueio de xp_cmdshell realizado com sucesso!"
                )
            else:
                self.log("[AVISO] Nenhuma instância do SQL Server encontrada ou bloqueada", True)
                QMessageBox.warning(
                    self,
                    "Proteção SQL Server",
                    "Nenhuma instância do SQL Server foi encontrada ou não foi possível realizar o bloqueio."
                )
            
        except Exception as e:
            self.log(f"[ERRO] Falha ao bloquear xp_cmdshell: {str(e)}", True)
            QMessageBox.critical(
                self,
                "Erro",
                f"Falha ao bloquear xp_cmdshell: {str(e)}"
            )

    def initialize_protection_systems(self):
        """Inicializa todos os sistemas de proteção"""
        try:
            # Proteção contra Ransomware
            self.ransomware_thread = RansomwareProtectionThread(None)
            self.ransomware_thread.alert_signal.connect(self.show_alert)
            self.ransomware_thread.log_signal.connect(self.log)
            self.ransomware_thread.start()

            # Proteção em Tempo Real
            self.realtime_thread = RealtimeProtectionThread(None)
            self.realtime_thread.alert_signal.connect(self.show_alert)
            self.realtime_thread.log_signal.connect(self.log)
            self.realtime_thread.start()

            # Proteção de Processo
            self.protection_thread = QThread()
            self.protection_thread.run = self.protect_process
            self.protection_thread.start()

            # Iniciar proteção em tempo real e watchdog
            self.start_realtime_protection()
            self.setup_watchdog()

            self.threads_initialized = True
            self.log("[INFO] Sistemas de proteção inicializados com sucesso")
            
        except Exception as e:
            self.log(f"[ERRO] Falha ao inicializar sistemas de proteção: {str(e)}", True)

    @pyqtSlot(str, str)
    def safe_update_text(self, text, color):
        """Atualiza o texto de forma segura na thread principal"""
        try:
            if hasattr(self, 'log_text'):
                # Adiciona nova linha ao texto recebido
                formatted_text = f"{text}\n"
            
                # Usar insertPlainText para QPlainTextEdit
                self.log_text.moveCursor(self.log_text.textCursor().End)
                self.log_text.insertPlainText(formatted_text)
            
                # Scroll para o final
                scrollbar = self.log_text.verticalScrollBar()
                scrollbar.setValue(scrollbar.maximum())
            
                # Se for mensagem crítica (vermelha), atualizar log de ameaças
                if color == "#ff3333" and hasattr(self, 'threat_text'):
                    self.threats_found.append(formatted_text)
                    self.threat_text.clear()
                    self.threat_text.insertPlainText("=== RESUMO DE AMEAÇAS ===\n\n")
                    for threat in self.threats_found:
                        self.threat_text.insertPlainText(threat)
                
        except Exception as e:
            print(f"Erro ao atualizar texto: {e}")

    def process_pending_updates(self):
        """Processa atualizações pendentes na thread principal"""
        try:
            while self.pending_updates:
                text, color = self.pending_updates.pop(0)
                
                if hasattr(self, 'log_text'):
                    # Inserir no log principal
                    cursor = self.log_text.textCursor()
                    cursor.movePosition(cursor.End)
                    self.log_text.insertPlainText(text)
                    self.log_text.centerCursor()
                    
                    # Se for mensagem crítica, atualizar log de ameaças
                    if color == "#ff3333" and hasattr(self, 'threat_text'):
                        self.threats_found.append(text)
                        # Atualizar log de ameaças
                        self.threat_text.clear()
                        self.threat_text.insertPlainText("=== RESUMO DE AMEAÇAS ===\n\n")
                        for threat in self.threats_found:
                            self.threat_text.insertPlainText(threat)
                
        except Exception as e:
            print(f"Erro ao processar atualizações: {e}")

    def update_threat_log(self):
        """Atualiza o log de ameaças"""
        try:
            if hasattr(self, 'threat_text'):
                self.threat_text.clear()
                self.threat_text.insertPlainText("=== RESUMO DE AMEAÇAS ===\n\n")
                for threat in self.threats_found:
                    self.threat_text.insertPlainText(threat + "\n")
                
                # Scroll para o final
                scrollbar = self.threat_text.verticalScrollBar()
                scrollbar.setValue(scrollbar.maximum())
        except Exception as e:
            print(f"Erro ao atualizar log de ameaças: {e}")

    def log(self, message, threat=False):
        """Método para logging"""
        try:
            timestamp = time.strftime("[%H:%M:%S]")
            log_level = "[CRÍTICO]" if threat else "[INFO]"
            formatted_message = f"{timestamp} {log_level} {message}"
            
            # Log no console
            print(formatted_message)
            
            # Definir cor
            color = "#ff3333" if threat else "#06daf8"
            
            # Emitir sinal para log
            self.signals.update_text_signal.emit(formatted_message, color, "log")
            
            # Se for ameaça, atualizar também o log de ameaças
            if threat:
                self.threats_found.append(formatted_message)
                self.signals.update_text_signal.emit(formatted_message, "#ff3333", "threat")
                
        except Exception as e:
            print(f"Erro no log: {e}")

    def start_brute_force_monitoring(self):
        """Inicia o monitoramento de força bruta"""
        try:
            self.brute_force_timer = QTimer(self)
            self.brute_force_timer.timeout.connect(self.check_brute_force)
            self.brute_force_timer.start(30000)  # Verifica a cada 30 segundos
            self.log("[INFO] Monitoramento de força bruta iniciado")
        except Exception as e:
            self.log(f"[ERRO] Falha ao iniciar monitoramento de força bruta: {str(e)}", True)

    def check_brute_force(self):
        """Callback para verificar força bruta"""
        try:
            if self.ai_module and hasattr(self.ai_module, 'detect_brute_force'):
                results = self.ai_module.detect_brute_force()
                if results:
                    # Se detectou atividade crítica, mostra alerta visual
                    critical_activities = [act for act in results if act['risk_level'] == 'crítico']
                    if critical_activities:
                        QMessageBox.warning(
                            self,
                            "Alerta de Segurança",
                            "Detectada possível tentativa de força bruta!\n"
                            "Verifique o log de ameaças para mais detalhes."
                        )
        except Exception as e:
            self.log(f"[ERRO] Falha ao verificar força bruta: {str(e)}", True)

    def detect_behavior(self):
        """Detecta comportamentos suspeitos de forma segura"""
        try:
            QMetaObject.invokeMethod(
                self,
                "safe_update_text",
                Qt.ConnectionType.QueuedConnection,
                Q_ARG(str, "[INFO] Detecção de comportamento iniciada"),
                Q_ARG(str, "#06daf8")
            )
            
            # Sua lógica de detecção aqui
            
            if suspicious_behavior_detected:
                QMetaObject.invokeMethod(
                    self,
                    "safe_update_text",
                    Qt.ConnectionType.QueuedConnection,
                    Q_ARG(str, "[CRÍTICO] Comportamento suspeito detectado!"),
                    Q_ARG(str, "#ff3333")
                )
                
        except Exception as e:
            print(f"Erro na detecção de comportamento: {e}")

           
    
    def display_system_health(self, health_status):
        """Exibe o status de saúde do sistema na interface"""
        try:
            self.ai_text.clear()
            self.ai_text.insertHtml("<h3 style='color: #06daf8'>Status do Sistema</h3><br>")

            # CPU
            cpu_info = health_status.get('cpu', {})
            cpu_usage = cpu_info.get('percent', 0)
            cpu_color = "#ff3333" if cpu_usage > 90 else "#ffaa00" if cpu_usage > 70 else "#03f8e6"
            self.ai_text.insertHtml(
                f"<p>CPU: <span style='color: {cpu_color}'>{cpu_usage:.1f}%</span></p>"
            )
        
            # Memória
            memory_info = health_status.get('memory', {})
            mem_usage = memory_info.get('percent', 0)
            mem_color = "#ff3333" if mem_usage > 90 else "#ffaa00" if mem_usage > 70 else "#03f8e6"
            self.ai_text.insertHtml(
                f"<p>Memória: <span style='color: {mem_color}'>{mem_usage:.1f}%</span><br>"
                f"Memória Disponível: {memory_info.get('available', 0):.0f} MB</p>"
            )

            # Processos com alto consumo
            high_cpu = cpu_info.get('high_usage_processes', [])
            if high_cpu:
                self.ai_text.insertHtml("<p><b>Processos com alto uso de CPU:</b></p>")
                for proc in high_cpu:
                    self.ai_text.insertHtml(
                        f"<p style='margin-left: 20px'>• {proc.get('name', 'Unknown')}: "
                        f"<span style='color: #ff3333'>{proc.get('cpu_percent', 0):.1f}%</span></p>"
                    )

            # Nível de risco
            risk_level = health_status.get('risk_level', 'Desconhecido')
            risk_color = {
                'Alto': '#ff3333',
                'Médio': '#ffaa00',
                'Baixo': '#03f8e6'
            }.get(risk_level, '#ffffff')
            
            self.ai_text.insertHtml(
                f"<p><br><b>Nível de Risco: </b>"
                f"<span style='color: {risk_color}'>{risk_level}</span></p>"
            )

            if risk_level == 'Alto':
                self.ai_text.insertHtml(
                    "<p style='color: #ff3333'><br>⚠️ ALERTA: Sistema sob estresse!<br>"
                    "• Recursos do sistema em estado crítico<br>"
                    "• Recomenda-se ação imediata</p>"
                )

        except Exception as e:
            self.log(f"[ERRO] Erro ao exibir status do sistema: {str(e)}")
            self.ai_text.clear()
            self.ai_text.insertHtml(
                "<p style='color: #ff3333'>Erro ao exibir status do sistema. "
                "Tentando recuperar...</p>"
            )


    def log_from_thread(self, message, threat=False):
        """Método seguro para logging a partir de threads"""
        try:
            timestamp = time.strftime("[%H:%M:%S]")
            log_level = "[CRÍTICO]" if threat else "[INFO]"
            formatted_message = f"{timestamp} {log_level} {message}\n"
            
            # Log no console
            print(formatted_message)
            
            # Log na interface de forma segura
            if hasattr(self, 'log_text') and self.log_text is not None:
                self.log_text.moveCursor(self.log_text.textCursor().End)
                if threat:
                    self.log_text.insertHtml(f'<span style="color: #ff3333">{formatted_message}</span>')
                else:
                    self.log_text.insertHtml(f'<span style="color: #06daf8">{formatted_message}</span>')
                
                # Atualiza log de ameaças se necessário
                if threat:
                    self.threats_found.append(formatted_message)
                    QTimer.singleShot(0, self.update_threat_log)
                    
        except Exception as e:
            print(f"Erro ao registrar log: {e}")

    def log(self, message, threat=False):
        """Wrapper para log que usa sinais"""
        self.signals.update_log_signal.emit(message, threat)

    def handle_behavior_signal(self, message, is_threat):
        """Manipula sinais de comportamento"""
        self.log(message, is_threat)

    @pyqtSlot(str)
    def update_ai_text(self, text):
        """Atualiza o texto da IA de forma segura"""
        if hasattr(self, 'ai_text'):
            self.ai_text.clear()
            self.ai_text.insertHtml(text)

   
    @pyqtSlot(dict)
    def display_process_analysis(self, analysis):
        """Exibe a análise de processos"""
        try:
            if hasattr(self, 'ai_text'):
                self.ai_text.clear()
                self.ai_text.insertHtml("<h3 style='color: #06daf8'>Análise de Processos</h3><br>")
                # ... resto do código de exibição da análise ...
        except Exception as e:
            self.log(f"[ERRO] Erro ao exibir análise de processos: {str(e)}")

    def update_threat_log(self):
        """Atualiza o log de ameaças"""
        if hasattr(self, 'threat_text'):
            self.threat_text.clear()
            if self.threats_found:
                self.threat_text.insertPlainText("=== RESUMO DE AMEAÇAS ===\n\n")
                for threat in self.threats_found:
                    self.threat_text.insertPlainText(threat)
            else:
                self.threat_text.insertPlainText("Nenhuma ameaça encontrada")


    def update_ai_text(self, text):
        """Atualiza o texto da IA de forma segura"""
        if hasattr(self, 'ai_text') and self.ai_text is not None:
            self.ai_text.clear()
            self.ai_text.insertHtml(text)

    def run_ai_monitoring(self):
        """Executa o monitoramento da IA"""
        while self.ai_running:
            try:
                # Monitoramento de saúde do sistema
                health_status = self.ai_module.monitor_system_health()
                if health_status:
                    # Emitir sinal ao invés de chamar diretamente
                    self.update_system_health_signal.emit(health_status)

                # Análise de processos
                process_analysis = self.ai_module.analyze_process_behavior()
                if process_analysis:
                    # Emitir sinal ao invés de chamar diretamente
                    self.update_process_analysis_signal.emit(process_analysis)

                # Detecção de comportamentos suspeitos
                if self.ai_module.detect_behavior():
                    self.update_log_signal.emit(
                        "Comportamento suspeito detectado!",
                        True
                    )

                QThread.msleep(5000)  # 5 segundos de pausa

            except Exception as e:
                self.update_log_signal.emit(f"[ERRO] Erro no monitoramento da IA: {str(e)}", False)
                QThread.msleep(1000)

    @pyqtSlot()
    def on_ai_thread_finished(self):
        """Callback para quando a thread da IA termina"""
        try:
            print("Thread da IA finalizada")  # Debug
            if self.ai_running:
                self.safe_update_text("[ALERTA] Thread da IA finalizada inesperadamente", "#ff3333")
                self.ai_running = False
                self.ai_button.setText("🤖 IA: Desativada")
                
                # Limpar recursos
                if hasattr(self, 'ai_worker'):
                    self.ai_worker.deleteLater()
                if hasattr(self, 'ai_thread'):
                    self.ai_thread.deleteLater()
                    
        except Exception as e:
            print(f"Erro no callback de finalização da thread: {e}")
            self.safe_update_text(f"[ERRO] Falha no callback de finalização: {str(e)}", "#ff3333")

    @pyqtSlot(dict)
    def display_system_health(self, health_status):
        """Exibe o status de saúde do sistema"""
        try:
            # Formatar o texto do status
            text = "<h3 style='color: #06daf8'>Status do Sistema</h3><br>"
            
            # CPU
            cpu_info = health_status.get('cpu', {})
            cpu_usage = cpu_info.get('percent', 0)
            cpu_color = "#ff3333" if cpu_usage > 90 else "#ffaa00" if cpu_usage > 70 else "#03f8e6"
            text += f"<p>CPU: <span style='color: {cpu_color}'>{cpu_usage:.1f}%</span></p>"
            
            # Memória
            memory_info = health_status.get('memory', {})
            mem_usage = memory_info.get('percent', 0)
            mem_color = "#ff3333" if mem_usage > 90 else "#ffaa00" if mem_usage > 70 else "#03f8e6"
            text += f"<p>Memória: <span style='color: {mem_color}'>{mem_usage:.1f}%</span></p>"
            
            # Atualizar texto da IA
            self.signals.update_text_signal.emit(text, "#06daf8", "ai")
            
        except Exception as e:
            print(f"Erro ao exibir status do sistema: {e}")
       
    
    def display_process_analysis(self, process_analysis):
        """Exibe a análise de processos na interface"""
        try:
            self.ai_text.insertHtml("<br><h3 style='color: #06daf8'>Análise de Processos</h3>")
            
            risk_level = process_analysis.get('risk_level', 'Desconhecido')
            risk_color = {
                'Alto': '#ff3333',
                'Médio': '#ffaa00',
                'Baixo': '#03f8e6'
            }.get(risk_level, '#ffffff')
            
            self.ai_text.insertHtml(
                f"<p>Nível de Risco: <span style='color: {risk_color}'>{risk_level}</span></p>"
            )

            # Processos com alto consumo
            if process_analysis.get('resource_hogs'):
                self.ai_text.insertHtml("<p><b>Processos com Alto Consumo:</b></p>")
                for proc in process_analysis['resource_hogs']:
                    self.ai_text.insertHtml(
                        f"<p style='margin-left: 20px'>• {proc['name']} (PID: {proc.get('pid', 'N/A')})<br>"
                        f"CPU: {proc.get('cpu', 0):.1f}% | Memória: {proc.get('memory', 0):.1f}%</p>"
                    )

            # Processos suspeitos
            if process_analysis.get('suspicious_paths'):
                self.ai_text.insertHtml("<p><b>Processos em Locais Suspeitos:</b></p>")
                for proc in process_analysis['suspicious_paths']:
                    self.ai_text.insertHtml(
                        f"<p style='margin-left: 20px'>• {proc['name']} (PID: {proc.get('pid', 'N/A')})<br>"
                        f"Caminho: {proc.get('path', 'N/A')}</p>"
                    )
                    
                    # Pergunta se deseja finalizar
                    reply = QMessageBox.question(
                        self,
                        "Processo Suspeito",
                        f"Processo {proc['name']} está executando de um local suspeito:\n"
                        f"{proc.get('path', 'N/A')}\n\nDeseja finalizar este processo?",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                    )
                    
                    if reply == QMessageBox.StandardButton.Yes:
                        try:
                            psutil.Process(proc['pid']).terminate()
                            self.log(f"[INFO] Processo {proc['name']} finalizado")
                        except:
                            self.log(f"[ERRO] Não foi possível finalizar {proc['name']}")

        except Exception as e:
            self.log(f"[ERRO] Erro ao exibir análise de processos: {str(e)}")
            self.ai_text.insertHtml(
                "<p style='color: #ff3333'>Erro ao exibir análise de processos. "
                "Tentando recuperar...</p>"
            )

    def start_threads(self):
        """Inicia todas as threads de monitoramento"""
        try:
            # Thread de monitoramento do sistema
            health_thread = threading.Thread(
                target=self.ai_module.monitor_system_health,
                daemon=True
            )
            health_thread.start()
            self.threads.append(health_thread)

            # Thread de detecção de rootkits
            rootkit_thread = threading.Thread(
                target=self.ai_module.start_rootkit_detection,
                daemon=True
            )
            rootkit_thread.start()
            self.threads.append(rootkit_thread)

            # Thread de monitoramento de arquivos
            file_thread = threading.Thread(
                target=self.ai_module.monitor_file_access,
                daemon=True
            )
            file_thread.start()
            self.threads.append(file_thread)

            # Thread de análise de comportamento
            behavior_thread = threading.Thread(
                target=self.ai_module.detect_behavior,
                daemon=True
            )
            behavior_thread.start()
            self.threads.append(behavior_thread)

            self.log("[INFO] Threads de monitoramento iniciadas")
        
        except Exception as e:
            self.log(f"[ERRO] Falha ao iniciar threads: {str(e)}")

    def queue_alert(self, title, message):
        """Adiciona um alerta à fila de forma thread-safe"""
        self.alert_queue.append((title, message))

    def process_alerts(self):
        """Processa alertas pendentes na thread principal"""
        try:
            while self.alert_queue:
                title, message = self.alert_queue.pop(0)
                QMessageBox.critical(self, title, message)
        except Exception as e:
            print(f"Erro ao processar alertas: {e}")

    def update_interface(self):
        """Atualiza os elementos visuais da interface"""
        try:
            # Atualiza status da proteção
            protection_status = "PROTEGIDO" if self.realtime_protection else "DESPROTEGIDO"
            status_color = "#03f8e6" if self.realtime_protection else "#ff3333"
            self.status_label.setStyleSheet(f"color: {status_color};")
            self.status_label.setText(protection_status)

            # Atualiza botões
            self.ai_button.setText("🤖 IA: Ativada" if self.ai_running else "🤖 IA: Desativada")
            self.pause_button.setEnabled(self.scanning)
            
        except Exception as e:
            self.log(f"[ERRO] Erro ao atualizar interface: {str(e)}")

    def show_alert(self, title, message, level="info"):
        """Exibe alertas na interface"""
        icon = {
            "info": QMessageBox.Icon.Information,
            "warning": QMessageBox.Icon.Warning,
            "error": QMessageBox.Icon.Critical
        }.get(level, QMessageBox.Icon.Information)
        
        QMessageBox.information(self, title, message, icon)

    def start_realtime_protection(self):
        """Inicia a proteção em tempo real"""
        self.realtime_thread = QThread()
        self.realtime_thread.run = self.realtime_monitor
        self.realtime_thread.start()
        self.log("[INFO] Proteção em tempo real iniciada")

    def _check_process_security(self, proc):
        """Verifica a segurança de um processo específico"""
        try:
            proc_info = proc.as_dict(attrs=['pid', 'name', 'exe', 'cmdline'])
            proc_name = proc_info['name'].lower() if proc_info.get('name') else ''
            cmdline = " ".join(proc_info.get('cmdline', []) or []).lower()

            # Verificações de segurança
            if self.realtime_configs.get('block_powershell', True) and "powershell" in (proc_name + cmdline):
                self.log(f"[ALERTA] Tentativa de execução do PowerShell bloqueada: {proc_name}", threat=True)
                proc.terminate()
                return

            # Verificação de ferramentas de rede
            if self.realtime_configs.get('block_network_tools', True):
                for tool, desc in NETWORK_TOOLS.items():
                    if tool.lower() in (proc_name + cmdline):
                        self.log(f"[ALERTA] Ferramenta de rede bloqueada: {desc}", threat=True)
                        proc.terminate()
                        return

            # Verificação de comandos suspeitos
            if self.realtime_configs.get('block_suspicious_commands', True):
                for cmd in SUSPICIOUS_COMMANDS:
                    if cmd.lower() in cmdline:
                        self.log(f"[ALERTA] Comando suspeito bloqueado: {cmd}", threat=True)
                        proc.terminate()
                        return

        except Exception as e:
            self.log(f"[ERRO] Erro na verificação de segurança: {str(e)}")

    def update_realtime_config(self, config_name, value):
        """Atualiza uma configuração de proteção em tempo real"""
        try:
            if config_name in self.realtime_configs:
                old_value = self.realtime_configs[config_name]
                self.realtime_configs[config_name] = bool(value)
                self.log(f"[INFO] Configuração '{config_name}' atualizada: {old_value} -> {value}")
            else:
                self.log(f"[ERRO] Configuração '{config_name}' não encontrada")
        except Exception as e:
            self.log(f"[ERRO] Falha ao atualizar configuração: {str(e)}")

    
        
    @pyqtSlot(str)
    def show_ransomware_alert(self, file_path):
        """Exibe alerta de ransomware de forma segura"""
        try:
            QMessageBox.critical(
                self,
                "Alerta de Segurança",
                f"Tentativa de ransomware detectada!\nArquivo: {file_path}\nAção bloqueada."
            )
        except Exception as e:
            self.log(f"[ERRO] Falha ao exibir alerta de ransomware: {str(e)}", True)

    


    def protect_process(self):
        """Protege o processo do antivírus contra finalização"""
        while True:
            try:
                current_process = psutil.Process(os.getpid())
                
                for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                    try:
                        if proc.pid == current_process.pid:
                            continue

                        # Monitora tentativas de finalização
                        if any([
                            "taskkill" in str(proc.cmdline()).lower(),
                            "taskmgr.exe" in proc.name().lower(),
                            "processhacker.exe" in proc.name().lower(),
                            proc.name().lower() in ["taskkill.exe", "ntsd.exe", "procexp.exe"]
                        ]):
                            cmdline = " ".join(proc.cmdline()).lower()
                            if str(current_process.pid) in cmdline or self._is_targeting_us(proc):
                                if not self.check_password():
                                    proc.terminate()
                                    self.log("[ALERTA] Tentativa de finalização bloqueada!", threat=True)
                                    QMessageBox.warning(self, "Proteção", 
                                        "Tentativa de finalização não autorizada bloqueada")
                                else:
                                    self.cleanup()
                                    self.close()
                                    return

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                QThread.msleep(100)
                
            except Exception as e:
                self.log(f"[ERRO] Erro na proteção: {str(e)}")
                QThread.msleep(1000)

    def realtime_monitor(self):
        """Monitor em tempo real de processos e atividades"""
        checked_processes = set()
        
        while True:
            try:
                active_processes = [
                    proc for proc in psutil.process_iter(attrs=["pid", "name", "exe", "cmdline"]) 
                    if proc.info["pid"] not in checked_processes
                ]

                for proc in active_processes:
                    try:
                        if not all(key in proc.info for key in ["pid", "name"]):
                            continue
                        
                        proc_name = proc.info["name"].lower()
                        proc_pid = proc.info["pid"]
                        
                        # Verifica processos e executa ações de proteção
                        self._check_process_security(proc)
                        
                        checked_processes.add(proc_pid)
                        
                        # Limita o tamanho do cache
                        if len(checked_processes) > 1000:
                            checked_processes = set(list(checked_processes)[-500:])
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                    except Exception as e:
                        self.log(f"[ERRO] Erro ao verificar processo: {str(e)}")
                
                QThread.msleep(100)
                
            except Exception as e:
                self.log(f"[ERRO] Erro no monitoramento: {str(e)}")
                QThread.msleep(1000)

    
    def _check_process_security(self, proc):
        """Verifica a segurança de um processo específico"""
        try:
            proc_name = proc.name().lower() if proc else ''
            cmdline = ' '.join(proc.cmdline()) if proc else ''
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return
        except Exception:
            return

            # Pular processos do sistema
            if proc_name in CRITICAL_PROCESSES:
                return

             # Verificações de segurança
            try:
                # PowerShell
                if self.realtime_configs['block_powershell']:
                    if "powershell" in proc_name or "powershell" in cmdline:
                        self.log(f"[ALERTA] Tentativa de execução do PowerShell bloqueada: {proc_name}", threat=True)
                        try:
                            proc.terminate()
                        except:
                            pass
                        return

                # Ferramentas de rede
                if self.realtime_configs['block_network_tools']:
                    for tool, desc in NETWORK_TOOLS.items():
                        if tool.lower() in proc_name or tool.lower() in cmdline:
                            self.log(f"[ALERTA] Ferramenta de rede bloqueada: {desc}", threat=True)
                            try:
                                proc.terminate()
                            except:
                                pass
                            return
                        
                # Comandos suspeitos
                if self.realtime_configs['block_suspicious_commands']:
                    for cmd in SUSPICIOUS_COMMANDS:
                        if cmd.lower() in cmdline:
                            self.log(f"[ALERTA] Comando suspeito bloqueado: {cmd}", threat=True)
                            try:
                                proc.terminate()
                            except:
                                pass
                            return
                        
            except Exception as e:
                self.log(f"[ERRO] Erro ao verificar processo {proc_name}: {str(e)}")

        except Exception as e:
            self.log(f"[ERRO] Erro na verificação de segurança: {str(e)}")

    def delayed_start(self):
        """Inicializa componentes após a interface estar pronta"""
        try:
            # Configurar senha inicial se não existir
            if not hasattr(self, 'admin_password'):
                self.setup_initial_password()
            
            # Iniciar monitoramento da IA
            if self.ai_running:
                self.start_ai_monitoring()
            
            # Log inicial
            self.log("[INFO] Sistema iniciado e pronto para uso")
            self.log("[INFO] Proteção em tempo real ativa")
        
            # Atualizar interface
            self.update_interface()
        
        except Exception as e:
            self.log(f"[ERRO] Falha na inicialização: {str(e)}")

    def closeEvent(self, event):
        """Intercepta tentativa de fechar a janela"""
        try:
            if not hasattr(self, 'is_authorized_close') or not self.is_authorized_close:
                reply = QMessageBox.question(
                    self,
                    'Confirmação',
                    'Para fechar o antivírus, é necessário senha de administrador. Deseja continuar?',
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )

                if reply == QMessageBox.StandardButton.Yes:
                    password, ok = QInputDialog.getText(
                        self, 
                        'Autenticação',
                        'Digite a senha de administrador:',
                        QLineEdit.EchoMode.Password
                    )
                
                    if ok and password == self.admin_password:
                        self.is_authorized_close = True
                        self.cleanup()
                        event.accept()
                    else:
                        self.log("[ALERTA] Tentativa de fechamento não autorizada bloqueada", True)
                        event.ignore()
                else:
                    event.ignore()
            else:
                event.accept()
            
        except Exception as e:
            self.log(f"[ERRO] Erro ao processar tentativa de fechamento: {str(e)}", True)
            event.ignore()

    @pyqtSlot()
    def show_protection_alert(self):
        """Mostra alerta quando há tentativa de fechamento forçado"""
        QMessageBox.warning(
            self,
            "Proteção",
            "Tentativa de finalização não autorizada detectada e bloqueada!"
        )

    def _is_targeting_us(self, proc):
        """Verifica se um processo está tentando finalizar o antivírus"""
        try:
            handles = proc.open_files()
            return any(str(os.getpid()) in str(handle) for handle in handles)
        except:
            return False

    def _format_message(self, message, level="info"):
        """Formata mensagens para exibição com cores HTML"""
        colors = {
            "info": "#06daf8",
            "warning": "#ffaa00",
            "error": "#ff3333",
            "success": "#03f8e6"
        }
        return f"<span style='color: {colors.get(level, colors['info'])}'>{message}</span>"

    def _handle_monitoring_error(self, error):
        """Trata erros de monitoramento"""
        self.log(f"[ERRO] Erro no monitoramento: {str(error)}")
        
        self.ai_text.clear()
        self.ai_text.insertHtml(
            "<h3 style='color: #ff3333'>ERRO DE MONITORAMENTO</h3>"
            f"<p>{str(error)}</p>"
            "<p>O monitoramento tentará continuar na próxima verificação.</p>"
        )

    def analyze_network(self):
        """Analisa conexões de rede ativas"""
        try:
            self.ai_text.clear()
            self.ai_text.insertHtml("<h3 style='color: #06daf8'>Análise de Rede</h3>")
            
            connections = 0
            suspicious_count = 0
            network_data = {
                'suspicious_processes': [],
                'high_traffic': []
            }
            
            # Análise por processo
            for proc in psutil.process_iter(['pid', 'name', 'connections']):
                try:
                    proc_connections = proc.connections()
                    if proc_connections:
                        conn_count = len(proc_connections)
                        connections += conn_count
                        
                        if conn_count > NETWORK_THRESHOLDS['warning_connections_per_process']:
                            suspicious_count += 1
                            network_data['suspicious_processes'].append({
                                'name': proc.name(),
                                'pid': proc.pid,
                                'connections': conn_count,
                                'risk_level': 'Alto' if conn_count > NETWORK_THRESHOLDS['max_connections_per_process'] else 'Médio'
                            })
                            
                            # Exibe processos suspeitos
                            risk_color = '#ff3333' if conn_count > NETWORK_THRESHOLDS['max_connections_per_process'] else '#ffaa00'
                            self.ai_text.insertHtml(
                                f"<p style='color: {risk_color}'>Processo com muitas conexões:<br>"
                                f"• {proc.name()} (PID: {proc.pid})<br>"
                                f"• Conexões ativas: {conn_count}</p>"
                            )
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            # Análise de tráfego
            net_io = psutil.net_io_counters()
            bytes_sent = net_io.bytes_sent / (1024 * 1024)  # MB
            bytes_recv = net_io.bytes_recv / (1024 * 1024)  # MB
            
            self.ai_text.insertHtml(
                f"<p><b>Estatísticas de Rede:</b><br>"
                f"• Total de conexões: {connections}<br>"
                f"• Processos suspeitos: {suspicious_count}<br>"
                f"• Dados enviados: {bytes_sent:.2f} MB<br>"
                f"• Dados recebidos: {bytes_recv:.2f} MB</p>"
            )
            
            # Avalia risco geral
            risk_level = 'Baixo'
            if suspicious_count > 3 or connections > NETWORK_THRESHOLDS['max_total_connections']:
                risk_level = 'Alto'
            elif suspicious_count > 1 or bytes_sent > NETWORK_THRESHOLDS['suspicious_traffic_mb']:
                risk_level = 'Médio'
                
            risk_color = {'Alto': '#ff3333', 'Médio': '#ffaa00', 'Baixo': '#03f8e6'}[risk_level]
            self.ai_text.insertHtml(
                f"<p><b>Nível de Risco: </b>"
                f"<span style='color: {risk_color}'>{risk_level}</span></p>"
            )
            
            return network_data
            
        except Exception as e:
            self.log(f"[ERRO] Erro na análise de rede: {str(e)}")
            return None

    async def scan_files(self):
        """Verifica arquivos suspeitos com interface visual"""
        try:
            total_files = 0
            scanned_files = 0
            threats_found = 0
        
            # Primeira passagem para contar arquivos
            for path in COMMON_PATHS:
                for _, _, files in os.walk(path):
                    total_files += len([f for f in files if f.endswith((".exe", ".dll", ".bin"))])
        
            self.progress_bar.setValue(0)
        
            # Segunda passagem para verificação
            for path in COMMON_PATHS:
                try:
                    for root, _, files in os.walk(path):
                        for file in files:
                            if self.pause:
                                self.status_label.setText("Varredura pausada")
                                continue
                            
                            if not self.scanning:
                                return
                            
                            if file.endswith((".exe", ".dll", ".bin")):
                                file_path = os.path.join(root, file)
                                self.status_label.setText(f"Verificando: {file_path}")
                            
                                # Calcula hash e verifica
                                file_hash = self.calculate_file_hash(file_path)
                                if file_hash:
                                    is_threat = await self.check_hash(file_hash, file_path)
                                    if is_threat:
                                        threats_found += 1
                                    
                                scanned_files += 1
                                progress = int((scanned_files / total_files) * 100)
                                self.progress_bar.setValue(progress)
                            
                                # Pequena pausa para não sobrecarregar
                                await asyncio.sleep(0.01)  # Versão assíncrona do sleep
                            
                except Exception as e:
                    self.log(f"[ERRO] Erro ao verificar diretório {path}: {str(e)}")
                    continue
                
            self.status_label.setText(
                f"Varredura concluída. {threats_found} ameaças encontradas."
            )  
            self.progress_bar.setValue(100)
        
        except Exception as e:
            self.log(f"[ERRO] Erro na varredura de arquivos: {str(e)}")
            self.status_label.setText("Erro na varredura")

    def calculate_file_hash(self, filepath):
        """Calcula o hash SHA-256 de um arquivo"""
        try:
            with open(filepath, "rb") as f:
                file_hash = hashlib.sha256()
                while chunk := f.read(8192):
                    file_hash.update(chunk)
                return file_hash.hexdigest()
        except Exception as e:
            self.log(f"[ERRO] Erro ao calcular hash do arquivo {filepath}: {str(e)}")
            return None

    @pyqtSlot(str, str)
    def show_alert(self, title, message):
        """Exibe alertas de forma segura na thread principal"""
        try:
            QMessageBox.critical(self, title, message)
        except Exception as e:
            self.log(f"[ERRO] Falha ao exibir alerta: {str(e)}", True)

    
    
    @pyqtSlot(str, str)
    def show_alert_dialog(self, title, message):
        """Exibe diálogo de alerta na thread principal"""
        try:
            QMessageBox.critical(self, title, message)
        except Exception as e:
            self.log(f"[ERRO] Falha ao exibir alerta: {str(e)}", True)

    def setup_watchdog(self):
        """Configura o monitoramento de arquivos"""
        try:
            path_to_monitor = "C:\\" if os.name == 'nt' else "/"
            
            # Configurar extensões suspeitas
            suspicious_extensions = {
                '.encrypted', '.crypto', '.locky', '.wcry', '.wncry', 
            '.crypt', '.locked', '.cerber', '.zepto', '.thor',
            '.aaa', '.abc', '.xyz', '.zzz', '.micro', '.encrypted',
            '.криптед', '.крипт', '.crinf', '.r5a', '.XRNT', '.XTBL',
            '.crypt', '.R16M01D05', '.pzdc', '.good', '.LOL!', '.OMG!',
            '.RDM', '.RRK', '.encryptedRSA', '.crjoker', '.EnCiPhErEd',
            '.LeChiffre', '.keybtc@inbox_com', '.0x0', '.bleep', '.1999',
            '.vault', '.HA3', '.toxcrypt', '.magic', '.SUPERCRYPT', '.CTBL',
            '.CTB2', '.locky', '.petya', '.cry', '.corona', '.nochance'
            }

            self.event_handler = RansomwareExtensionHandler(
                suspicious_extensions,
                self.log,
                self
            )
            
            self.observer = Observer()
            self.observer.schedule(
                self.event_handler,
                path=path_to_monitor,
                recursive=True
            )
            self.observer.start()
            self.log("[INFO] Sistema de proteção WatchDog iniciado")
            
        except Exception as e:
            self.log(f"[ERRO] Falha ao iniciar WatchDog: {str(e)}")

    def analyze_process_behavior(self, process):
        """Analisa o comportamento de um processo"""
        try:
            score = 0
            behaviors = []
            
            # Analisa operações de arquivo
            file_ops = self._get_file_operations(process)
            if file_ops:
                file_score = self._analyze_file_operations(file_ops)
                score += file_score
                if file_score > 3:
                    behaviors.append(f"Operações suspeitas em arquivos: {', '.join(file_ops)}")
            
            # Analisa operações de rede
            network_ops = self._get_network_operations(process)
            if network_ops:
                network_score = self._analyze_network_operations(network_ops)
                score += network_score
                if network_score > 3:
                    behaviors.append(f"Operações suspeitas de rede: {', '.join(network_ops)}")
            
            # Analisa operações do sistema
            system_ops = self._get_system_operations(process)
            if system_ops:
                system_score = self._analyze_system_operations(system_ops)
                score += system_score
                if system_score > 3:
                    behaviors.append(f"Operações suspeitas do sistema: {', '.join(system_ops)}")
            
            # Determina nível de risco
            risk_level = (
                'Alto' if score > 8
                else 'Médio' if score > 4
                else 'Baixo'
            )
            
            return {
                'score': score,
                'risk_level': risk_level,
                'behaviors': behaviors,
                'process_name': process.name(),
                'pid': process.pid
            }
            
        except Exception as e:
            self.log(f"[ERRO] Erro ao analisar comportamento: {str(e)}")
            return None

    def _get_file_operations(self, process):
        """Obtém operações de arquivo do processo"""
        operations = set()
        try:
            for file in process.open_files():
                if file.mode == 'w':
                    operations.add('write')
                elif file.mode == 'r':
                    operations.add('read')
                
                file_path = file.path.lower()
                if any(sens_dir in file_path for sens_dir in SENSITIVE_DIRS):
                    operations.add('sensitive_access')
                    
        except:
            pass
        return operations

    def _get_network_operations(self, process):
        """Obtém operações de rede do processo"""
        operations = set()
        try:
            for conn in process.connections():
                if conn.status == 'LISTEN':
                    operations.add('listen')
                elif conn.status == 'ESTABLISHED':
                    operations.add('connect')
                    
                # Verifica portas suspeitas
                if conn.laddr.port in SUSPICIOUS_PORTS:
                    operations.add('suspicious_port')
                    
        except:
            pass
        return operations

    def _get_system_operations(self, process):
        """Obtém operações do sistema do processo"""
        operations = set()
        try:
            cmdline = " ".join(process.cmdline())
            
            if any(pattern in cmdline.lower() for pattern in SUSPICIOUS_PATTERNS):
                operations.add('suspicious_command')
                
            if "reg" in cmdline:
                operations.add('registry_modify')
                
            if "sc" in cmdline:
                operations.add('service_create')
                
        except:
            pass
        return operations

    def setup_ui(self):
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
    
        # Layout principal
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)  # Define o layout no widget central
    
        # Header
        header_widget = QWidget()
        header_layout = QHBoxLayout()
        header_widget.setLayout(header_layout)  # Define o layout no widget do header
    
        title = QLabel("ADM Solutions Security")
        title.setFont(QFont('Segoe UI', 28, QFont.Weight.Bold))
        title.setStyleSheet("color: #06daf8;")
        header_layout.addWidget(title)
        header_layout.addWidget(self.status_label, alignment=Qt.AlignmentFlag.AlignRight)
    
        main_layout.addWidget(header_widget)
    
        # Status e Progresso (NOVO)
        status_frame = QFrame()
        status_layout = QHBoxLayout(status_frame)

        # Status Label
        self.status_label = QLabel("Sistema protegido e monitorado")
        self.status_label.setStyleSheet("color: #06daf8;")
        status_layout.addWidget(self.status_label)

        # Botões
        button_widget = QWidget()
        button_layout = QHBoxLayout()
        button_widget.setLayout(button_layout)  # Define o layout no widget dos botões

        # Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #16213e;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #00b6ef;
            }
        """)
        status_layout.addWidget(self.progress_bar)
        main_layout.addWidget(status_frame)

    
        self.scan_button = QPushButton("🔍 VARREDURA COMPLETA")
        self.pause_button = QPushButton("⏸️ PAUSAR")
        self.clear_button = QPushButton("🗑️ LIMPAR LOGS")
        self.ai_button = QPushButton("🤖 IA DEFENDER")
        self.test_rootkit_button = QPushButton("🛡️ TESTAR ROOTKIT")
    
        for button in [self.scan_button, self.pause_button, self.clear_button, self.ai_button, self.test_rootkit_button]:
            button.setStyleSheet("""
                QPushButton {
                    background-color: #1e2936;
                    color: white;
                    padding: 10px 20px;
                    border-radius: 5px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #2e3946;
                }
            """)
            button_layout.addWidget(button)

        # Conectar o novo botão
        self.test_rootkit_button.clicked.connect(self.run_rootkit_test)
    
        main_layout.addWidget(button_widget)
    
        # Painéis de log e análise
        panels_widget = QWidget()
        panels_layout = QHBoxLayout()
        panels_widget.setLayout(panels_layout)  # Define o layout no widget dos painéis
    
        # Painel de IA
        ai_frame = QFrame()
        ai_frame.setStyleSheet("background-color: #16213e; border-radius: 10px;")
        ai_layout = QVBoxLayout()
        ai_frame.setLayout(ai_layout)  # Define o layout no frame
    
        ai_title = QLabel("💡 ANÁLISE DO SISTEMA")
        ai_title.setStyleSheet("color: #00b6ef; font-weight: bold;")
        ai_layout.addWidget(ai_title)
    
        self.ai_text = QPlainTextEdit()
        self.ai_text.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1a1a2e;
                color: #09f9fd;
                border: none;
                font-family: Consolas;
            }
        """)
        ai_layout.addWidget(self.ai_text)
        panels_layout.addWidget(ai_frame)
    
        # Painel de Logs
        log_frame = QFrame()
        log_frame.setStyleSheet("background-color: #16213e; border-radius: 10px;")
        log_layout = QVBoxLayout()
        log_frame.setLayout(log_layout)  # Define o layout no frame
    
        log_title = QLabel("📊 MONITORAMENTO")
        log_title.setStyleSheet("color: #00b6ef; font-weight: bold;")
        log_layout.addWidget(log_title)
    
        self.log_text = QPlainTextEdit()
        self.log_text.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1a1a2e;
                color: #06daf8;
                border: none;
                font-family: Consolas;
            }
        """)
        log_layout.addWidget(self.log_text)
        panels_layout.addWidget(log_frame)
    
        main_layout.addWidget(panels_widget)
    
        # Painel de ameaças
        threat_frame = QFrame()
        threat_frame.setStyleSheet("background-color: #16213e; border-radius: 10px;")
        threat_layout = QVBoxLayout()
        threat_frame.setLayout(threat_layout)  # Define o layout no frame
    
        threat_title = QLabel("⚠️ CENTRO DE AMEAÇAS")
        threat_title.setStyleSheet("color: #00b6ef; font-weight: bold;")
        threat_layout.addWidget(threat_title)
    
        self.threat_text = QPlainTextEdit()
        self.threat_text.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1a1a2e;
                color: #ff3333;
                border: none;
                font-family: Consolas;
            }
        """)
        threat_layout.addWidget(self.threat_text)
        main_layout.addWidget(threat_frame)
    
        # Conectar os botões
        self.scan_button.clicked.connect(self.start_scan)
        self.pause_button.clicked.connect(self.toggle_pause)
        self.clear_button.clicked.connect(self.clear_log)
        self.ai_button.clicked.connect(self.toggle_ai)

    def log(self, message, threat=False):
        """Registra mensagens no log com formatação adequada"""
        timestamp = time.strftime("[%H:%M:%S]")
        log_level = "[CRÍTICO]" if threat else "[INFO]"
        formatted_message = f"{timestamp} {log_level} {message}\n"
        
        # Log no console
        print(formatted_message)
        
        # Log na interface
        text_widget = self.log_text
        text_widget.moveCursor(text_widget.textCursor().End)
        
        # Aplica cor baseada no tipo de mensagem
        if threat:
            color = QColor("#ff3333")  # Vermelho para ameaças
        else:
            color = QColor("#06daf8")  # Azul para info
            
        cursor = text_widget.textCursor()
        format = cursor.charFormat()
        format.setForeground(color)
        cursor.mergeCharFormat(format)
        
        text_widget.insertPlainText(formatted_message)
        text_widget.ensureCursorVisible()
        
        # Atualiza log de ameaças se necessário
        if threat:
            self.threats_found.append(formatted_message)
            self.update_threat_log()


    def clear_log(self):
        """Limpa todos os logs"""
        self.log_text.clear()
        self.threat_text.clear()
        self.ai_text.clear()
        self.threats_found = []
        self.log("[INFO] Logs limpos com sucesso")

    def check_password(self):
        """Verifica a senha de administrador"""
        from PyQt6.QtWidgets import QInputDialog, QLineEdit, QMessageBox
        
        password, ok = QInputDialog.getText(
            self, 
            'Segurança',
            'Digite a senha de administrador:',
            QLineEdit.EchoMode.Password
        )
        
        if not ok or not password:
            return False
            
        is_valid = password == self.admin_password
        
        if not is_valid:
            QMessageBox.critical(self, "Erro", "Senha incorreta. O antivírus não pode ser finalizado.")
            self.log("[ALERTA] Tentativa de finalização do antivírus bloqueada!", threat=True)
            return False
            
        return True

    def setup_initial_password(self):
        """Configura a senha inicial do administrador"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLineEdit, QPushButton, QLabel, QMessageBox
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Configuração Inicial")
        dialog.setFixedSize(400, 200)
        
        layout = QVBoxLayout()
        
        # Título
        title = QLabel("Configuração de Senha do Administrador")
        title.setFont(QFont('Segoe UI', 12, QFont.Weight.Bold))
        layout.addWidget(title)
        
        # Campos de senha
        password_label = QLabel("Digite uma senha para proteger o antivírus:")
        layout.addWidget(password_label)
        
        password_input = QLineEdit()
        password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(password_input)
        
        confirm_label = QLabel("Confirme a senha:")
        layout.addWidget(confirm_label)
        
        confirm_input = QLineEdit()
        confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(confirm_input)
        
        # Botão de confirmação
        def validate_and_save():
            password = password_input.text()
            confirm = confirm_input.text()
            
            if not password:
                QMessageBox.critical(dialog, "Erro", "A senha não pode estar vazia!")
                return
                
            if password != confirm:
                QMessageBox.critical(dialog, "Erro", "As senhas não correspondem!")
                return
                
            self.admin_password = password
            dialog.accept()
            
        confirm_button = QPushButton("Confirmar")
        confirm_button.clicked.connect(validate_and_save)
        layout.addWidget(confirm_button)
        
        dialog.setLayout(layout)
        dialog.exec()

    def run_rootkit_test(self):
        """Executa o teste de rootkit e mostra o resultado"""
        try:
            self.log("[INFO] Iniciando teste do sistema de detecção de rootkit...")
            result = self.test_rootkit_system()
        
            if result:
                self.log("[INFO] Sistema de detecção de rootkit funcionando corretamente")
                QMessageBox.information(
                    self,
                    "Teste de Rootkit",
                    "Sistema de detecção de rootkit está funcionando corretamente!"
                )
            else:
                self.log("[ERRO] Falha no teste do sistema de detecção de rootkit", True)
                QMessageBox.warning(
                    self,
                    "Teste de Rootkit",
                    "Falha no teste do sistema de detecção de rootkit.\nVerifique os logs para mais detalhes."
                )
            
        except Exception as e:
            self.log(f"[ERRO] Erro ao executar teste de rootkit: {str(e)}", True)
            QMessageBox.critical(
                self,
                "Erro",
                f"Erro ao executar teste de rootkit: {str(e)}"
            )

    def update_status(self, message):
        """Atualiza a mensagem de status"""
        self.status_label.setText(message)

    def update_progress(self, value):
        """Atualiza a barra de progresso"""
        self.progress_bar.setValue(value)
        
    def toggle_pause(self):
        """Alterna entre pausar/continuar a varredura"""
        if hasattr(self, 'scan_worker'):
            self.scan_worker.is_paused = not self.scan_worker.is_paused
            self.pause_button.setText("▶️ Continuar" if self.scan_worker.is_paused else "⏸️ PAUSAR")
            status = "Varredura pausada" if self.scan_worker.is_paused else "Varredura em andamento"
            self.status_label.setText(status)

    def on_scan_finished(self):
        """Callback quando a varredura termina"""
        self.scan_button.setEnabled(True)
        self.pause_button.setEnabled(False)
        self.pause_button.setText("⏸️ PAUSAR")

    def toggle_ai(self):
        """Alterna a ativação da IA"""
        try:
            print("Iniciando toggle_ai")  # Debug
            self.ai_running = not self.ai_running
            
            if self.ai_running:
                try:
                    print("Criando worker e thread")  # Debug
                    # Criar worker sem parent
                    self.ai_worker = MonitorWorker()
                    
                    # Criar thread
                    self.ai_thread = QThread()
                    
                    print("Configurando worker")  # Debug
                    # Configurar worker
                    self.ai_worker.set_antivirus(self)
                    
                    print("Movendo worker para thread")  # Debug
                    # Mover worker para a thread
                    self.ai_worker.moveToThread(self.ai_thread)
                    
                    print("Conectando sinais")  # Debug
                    # Conectar sinais
                    try:
                        self.ai_worker.update_text_signal.connect(self.safe_update_text)
                    except Exception as signal_error:
                        print(f"Erro ao conectar sinais: {signal_error}")
                        self.log(f"[ERRO] Falha ao conectar sinais: {signal_error}", True)
                    
                    print("Conectando método run")  # Debug
                    # Conectar o método run à thread
                    self.ai_thread.started.connect(self.ai_worker.run)
                    
                    # Conectar sinais de finalização
                    self.ai_thread.finished.connect(self.on_ai_thread_finished)
                    
                    print("Iniciando thread")  # Debug
                    # Iniciar thread
                    self.ai_thread.start()
                    
                    self.safe_update_text("Sistema de IA ativado", "#06daf8")
                    print("IA ativada com sucesso")  # Debug
                    
                except Exception as e:
                    print(f"Erro durante ativação da IA: {e}")  # Debug
                    self.safe_update_text(f"[ERRO] Falha durante ativação da IA: {str(e)}", "#ff3333")
                    self.ai_running = False  # Reverter estado
                    return
                    
            else:
                try:
                    print("Desativando IA")  # Debug
                    # Parar BehaviorAnalyzer primeiro
                    if hasattr(self, 'ai_module'):
                        self.ai_module.stop()
                
                    # Parar worker e thread
                    if hasattr(self, 'ai_worker'):
                        self.ai_worker.is_running = False
                    if hasattr(self, 'ai_thread'):
                        self.ai_thread.quit()
                        self.ai_thread.wait(1000)  # Espera até 1 segundo
                
                    self.safe_update_text("Sistema de IA desativado", "#06daf8")
                    print("IA desativada com sucesso")  # Debug
                
                except Exception as e:
                    print(f"Erro durante desativação da IA: {e}")  # Debug
                    self.safe_update_text(f"[ERRO] Falha durante desativação da IA: {str(e)}", "#ff3333")
        
            self.ai_button.setText("🤖 IA: Ativada" if self.ai_running else "🤖 IA: Desativada")
        
        except Exception as e:
            print(f"Erro geral em toggle_ai: {e}")  # Debug
            self.safe_update_text(f"[ERRO] Falha ao alternar IA: {str(e)}", "#ff3333")
            
            

    def stop_threads(self):
        """Para todas as threads de monitoramento"""
        try:
            # Marca threads para parar
            self.ai_running = False
            self.ai_module.is_active = False
        
            # Aguarda threads terminarem
            for thread in self.threads:
                if thread.is_alive():
                    thread.join(timeout=1.0)
                
            # Limpa lista de threads
            self.threads.clear()
        
            self.log("[INFO] Threads de monitoramento finalizadas")
        
        except Exception as e:
            self.log(f"[ERRO] Falha ao parar threads: {str(e)}")
 
    def start_scan(self):
        """Inicia a varredura completa"""
        try:
            if hasattr(self, 'scan_thread') and self.scan_thread.isRunning():
                return

            # Desabilita botão de scan
            self.scan_button.setEnabled(False)
            self.pause_button.setEnabled(True)
            self.progress_bar.setValue(0)

            # Criar thread e worker
            self.scan_thread = QThread()
            self.scan_worker = ScanWorker()

            # Mover worker para a thread
            self.scan_worker.moveToThread(self.scan_thread)

            # Conectar sinais
            self.scan_worker.progress_signal.connect(self.progress_bar.setValue)
            self.scan_worker.status_signal.connect(self.status_label.setText)
            self.scan_worker.log_signal.connect(self.log)
            self.scan_worker.finished_signal.connect(self.on_scan_finished)

            # Conectar início da thread
            self.scan_thread.started.connect(self.scan_worker.run)

            # Iniciar thread
            self.scan_thread.start()

        except Exception as e:
            self.log(f"[ERRO] Falha ao iniciar varredura: {str(e)}", True)
            self.scan_button.setEnabled(True)
            self.pause_button.setEnabled(False)

    
    def start_ai_monitoring(self):
        """Inicia o monitoramento da IA"""
        if hasattr(self, 'ai_worker') and self.ai_worker.isRunning():
            return

        self.ai_worker = AIMonitorWorker(self)
        
        # Conectar sinais
        self.ai_worker.status_updated.connect(self.display_system_health)
        self.ai_worker.alert_triggered.connect(self.handle_ai_alert)
        self.ai_worker.log_message.connect(self.log)

        # Iniciar worker
        self.ai_worker.start()

    def handle_ai_alert(self, message, details):
        """Trata alertas da IA"""
        from PyQt6.QtWidgets import QMessageBox
        
        self.log(f"[IA ALERTA] {message}", True)
        
        reply = QMessageBox.warning(
            self,
            "Alerta de Segurança",
            f"{message}\n\nDeseja ver mais detalhes?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            QMessageBox.information(self, "Detalhes", details)

    def run_ai_monitoring(self):
        """Executa o monitoramento da IA"""
        while self.ai_running:
            try:
                # Monitoramento de saúde do sistema
                health_status = self.ai_module.monitor_system_health()
                if health_status:
                    self.display_system_health(health_status)

                # Análise de processos
                process_analysis = self.ai_module.analyze_process_behavior()
                if process_analysis:
                    self.display_process_analysis(process_analysis)

                # Análise de rede
                network_analysis = self.ai_module.analyze_network()
                if network_analysis:
                    suspicious_count = len(network_analysis.get('suspicious_processes', []))
                    if suspicious_count > 0:
                        self.log(f"[ALERTA] Detectados {suspicious_count} processos com comportamento de rede suspeito", threat=True)

                # Detecção de ransomware
                ransomware_signs = self.ai_module.detect_ransomware_behavior()
                if ransomware_signs.get('risk_level') != 'Baixo':
                    self.log("[ALERTA] Comportamento similar a ransomware detectado!", threat=True)

                # Pausa entre verificações
                QThread.msleep(5000)  # 5 segundos

            except Exception as e:
                self.log(f"[ERRO] Erro no monitoramento da IA: {str(e)}")
                QThread.msleep(1000)  # Pausa mais curta em caso de erro

    def cleanup(self):
        """Limpa recursos antes de fechar"""
        try:
            # Para timers primeiro
            if hasattr(self, 'alert_timer'):
                self.alert_timer.stop()
            if hasattr(self, 'update_timer'):
                self.update_timer.stop()

            # Para BehaviorAnalyzer
            if hasattr(self, 'ai_module'):
                self.ai_module.stop()

            # Para thread de varredura
            if hasattr(self, 'scan_worker'):
                self.scan_worker.stop()
            if hasattr(self, 'scan_thread'):
                self.scan_thread.quit()
                self.scan_thread.wait(1000)

            # Para thread de memória
            if hasattr(self, 'memory_worker'):
                self.memory_worker.is_running = False
            if hasattr(self, 'memory_thread'):
                self.memory_thread.quit()
                self.memory_thread.wait(1000)
            
            # Para threads
            if hasattr(self, 'protection_worker'):
                self.protection_worker.stop()
            if hasattr(self, 'protection_thread'):
                self.protection_thread.quit()
                self.protection_thread.wait(1000)

            # Para o timer de força bruta
            if hasattr(self, 'brute_force_timer'):
                self.brute_force_timer.stop()

            # Para o timer de DDoS
            if hasattr(self, 'ddos_timer'):
                self.ddos_timer.stop()

            # Para o timer de DLLs
            if hasattr(self, 'dll_timer'):
                self.dll_timer.stop()

            # Para threads de forma segura
            if hasattr(self, 'ai_worker'):
                self.ai_worker.is_running = False
            if hasattr(self, 'ai_thread'):
                self.ai_thread.quit()
                self.ai_thread.wait(1000)

            # Limpa filas
            if hasattr(self, 'alert_queue'):
                self.alert_queue.clear()
            if hasattr(self, 'pending_updates'):
                self.pending_updates.clear()

        except Exception as e:
            print(f"Erro ao limpar recursos: {e}")
    

# Primeiro as classes trabalhadoras (Workers)
class ScanWorker(QObject):
    progress_signal = pyqtSignal(int)
    status_signal = pyqtSignal(str)
    log_signal = pyqtSignal(str, bool)
    finished_signal = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.is_running = True
        self.is_paused = False

    def run(self):
        """Executa a varredura completa"""
        try:
            self.log_signal.emit("[INFO] Iniciando varredura completa...", False)
            total_files = 0
            scanned_files = 0

            # Diretórios para varredura
            scan_dirs = [
                os.environ['SYSTEMROOT'],
                os.environ['PROGRAMFILES'],
                os.environ.get('PROGRAMFILES(X86)', ''),
                os.path.expanduser('~\\Documents'),
                os.path.expanduser('~\\Downloads')
            ]

            # Primeira passagem para contar arquivos
            self.status_signal.emit("Contando arquivos...")
            for directory in scan_dirs:
                if os.path.exists(directory):
                    for _, _, files in os.walk(directory):
                        total_files += len(files)

            # Segunda passagem para verificação
            for directory in scan_dirs:
                if not os.path.exists(directory):
                    continue

                for root, _, files in os.walk(directory):
                    for file in files:
                        while self.is_paused:
                            if not self.is_running:
                                return
                            QThread.msleep(500)

                        if not self.is_running:
                            return

                        try:
                            file_path = os.path.join(root, file)
                            self.status_signal.emit(f"Verificando: {file_path}")

                            # Verifica extensão
                            if file.lower().endswith(('.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1')):
                                self.scan_file(file_path)

                            scanned_files += 1
                            progress = int((scanned_files / total_files) * 100)
                            self.progress_signal.emit(progress)

                        except Exception as e:
                            self.log_signal.emit(f"[ERRO] Falha ao verificar arquivo {file}: {str(e)}", True)

                        # Pequena pausa para não sobrecarregar
                        QThread.msleep(1)

            self.status_signal.emit("Varredura concluída!")
            self.log_signal.emit("[INFO] Varredura completa finalizada", False)
            self.finished_signal.emit()

        except Exception as e:
            self.log_signal.emit(f"[ERRO] Erro durante a varredura: {str(e)}", True)
            self.finished_signal.emit()

    def scan_file(self, file_path):
        """Verifica um arquivo específico"""
        try:
            # Calcula hash do arquivo
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256()
                while chunk := f.read(8192):
                    file_hash.update(chunk)
                hash_value = file_hash.hexdigest()

            # Verifica tamanho
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                self.log_signal.emit(f"[ALERTA] Arquivo vazio encontrado: {file_path}", True)
                return

            # Verifica permissões suspeitas
            if os.access(file_path, os.X_OK) and 'temp' in file_path.lower():
                self.log_signal.emit(f"[ALERTA] Executável em local temporário: {file_path}", True)

            # Outras verificações podem ser adicionadas aqui

        except Exception as e:
            self.log_signal.emit(f"[ERRO] Erro ao verificar arquivo {file_path}: {str(e)}", True)

    def stop(self):
        """Para a varredura"""
        self.is_running = False

    def pause(self):
        """Pausa a varredura"""
        self.is_paused = True

    def resume(self):
        """Retoma a varredura"""
        self.is_paused = False

class AIMonitorWorker(QThread):
    status_updated = pyqtSignal(dict)
    alert_triggered = pyqtSignal(str, str)  # mensagem, nível
    log_message = pyqtSignal(str, bool)

    def __init__(self, antivirus):
        super().__init__()
        self.antivirus = antivirus
        self.is_running = True

    def run(self):
        while self.is_running:
            try:
                # Monitoramento de saúde do sistema
                health_status = self.antivirus.ai_module.monitor_system_health()
                if health_status:
                    self.status_updated.emit(health_status)

                # Análise de processos
                process_analysis = self.antivirus.ai_module.analyze_process_behavior()
                if process_analysis and process_analysis.get('risk_score', 0) > 0:
                    self.alert_triggered.emit(
                        "Comportamento suspeito detectado",
                        str(process_analysis)
                    )

                # Resto das suas análises de IA aqui...

                QThread.msleep(5000)  # Pausa de 5 segundos entre verificações

            except Exception as e:
                self.log_message.emit(f"[ERRO] Erro no monitoramento: {str(e)}", True)
                QThread.msleep(1000)  # Pausa em caso de erro


    def start_scan(self):
        """Inicia a varredura completa"""
        if hasattr(self, 'scan_worker') and self.scan_worker.isRunning():
            return

        self.scan_button.setEnabled(False)
        self.pause_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.pause = False

        # Criar e configurar o worker
        self.scan_worker = ScanWorker(self)
        
        # Conectar sinais
        self.scan_worker.progress_updated.connect(self.progress_bar.setValue)
        self.scan_worker.status_updated.connect(self.update_status)
        self.scan_worker.log_message.connect(self.log)
        self.scan_worker.scan_finished.connect(self.on_scan_finished)

        # Iniciar worker
        self.scan_worker.start()

    def on_scan_finished(self):
        """Callback quando a varredura termina"""
        self.scan_button.setEnabled(True)
        self.pause_button.setEnabled(False)
        self.scanning = False

    def start_ai_monitoring(self):
        """Inicia o monitoramento da IA"""
        if hasattr(self, 'ai_worker') and self.ai_worker.isRunning():
            return

        self.ai_worker = AIMonitorWorker(self)
        
        # Conectar sinais
        self.ai_worker.status_updated.connect(self.display_system_health)
        self.ai_worker.alert_triggered.connect(self.handle_ai_alert)
        self.ai_worker.log_message.connect(self.log)

        # Iniciar worker
        self.ai_worker.start()

    def handle_ai_alert(self, message, details):
        """Trata alertas da IA"""
        from PyQt6.QtWidgets import QMessageBox
        
        self.log(f"[IA ALERTA] {message}", True)
        
        reply = QMessageBox.warning(
            self,
            "Alerta de Segurança",
            f"{message}\n\nDeseja ver mais detalhes?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            QMessageBox.information(self, "Detalhes", details)

    def cleanup(self):
        """Limpa recursos antes de fechar"""
        try:
            # Parar workers
            if hasattr(self, 'scan_worker'):
                self.scan_worker.is_running = False
                self.scan_worker.wait()
                
            if hasattr(self, 'ai_worker'):
                self.ai_worker.is_running = False
                self.ai_worker.wait()

            # Parar observer do watchdog
            if hasattr(self, 'observer'):
                self.observer.stop()
                self.observer.join()

        except Exception as e:
            print(f"Erro ao limpar recursos: {e}")

class MonitorWorker(QObject):
    update_text_signal = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.is_running = True
        self.antivirus = None
        print("MonitorWorker inicializado")  # Debug

    def set_antivirus(self, antivirus):
        print("Definindo referência do antivírus")  # Debug
        self.antivirus = antivirus

    def run(self):
        print("Iniciando run do MonitorWorker")  # Debug
        while self.is_running:
            try:
                if self.antivirus is None:
                    print("Antivírus não definido")  # Debug
                    QThread.msleep(1000)
                    continue

                # Monitoramento de saúde do sistema
                health_status = self.antivirus.ai_module.monitor_system_health()
                if health_status:
                    cpu_info = health_status.get('cpu', {})
                    memory_info = health_status.get('memory', {})
                    
                    cpu_usage = cpu_info.get('percent', 0)
                    mem_usage = memory_info.get('percent', 0)
                    
                    status_text = f"Status do Sistema - CPU: {cpu_usage:.1f}% | Memória: {mem_usage:.1f}%"
                    self.update_text_signal.emit(status_text, "#06daf8")

                # Pequena pausa para não sobrecarregar
                QThread.msleep(500000)

            except Exception as e:
                print(f"Erro no run do MonitorWorker: {e}")  # Debug
                self.update_text_signal.emit(
                    f"Erro no monitoramento: {str(e)}",
                    "#ff3333"
                )
                QThread.msleep(1000)
        
        print("MonitorWorker finalizado")  # Debug

class RealtimeProtectionThread(QThread):
    alert_signal = pyqtSignal(str, str)
    log_signal = pyqtSignal(str, bool)

    def __init__(self):
        super().__init__()
        self.is_running = True
        
        # Lista de processos permitidos (whitelist)
        self.allowed_processes = {
            'python.exe',
            'pythonw.exe',
            '2.0admav.py',
            'python3.exe',
            'python3.11.exe',
            'python3.12.exe',
            'python3.13.exe',
            'antspy.py',
            'antivirus.exe',
            'qt5core.dll',
            'qt6core.dll'
        }
        
        # Lista de processos críticos do sistema que nunca devem ser finalizados
        self.critical_processes = {
            'explorer.exe',
            'svchost.exe',
            'lsass.exe',
            'csrss.exe',
            'winlogon.exe',
            'services.exe',
            'smss.exe',
            'wininit.exe',
            'system'
        }
        
        # Lista de processos bloqueados
        self.blocked_processes = {
            'powershell.exe': 'PowerShell',
            'cmd.exe': 'Prompt de Comando',
            'psexec.exe': 'PSExec',
            'wmic.exe': 'WMIC',
            'regsvr32.exe': 'RegSvr32',
            'netsh.exe': 'NetSH',
            'mshta.exe': 'MSHTA',
            'certutil.exe': 'CertUtil',
            'bitsadmin.exe': 'BitsAdmin',
            'rundll32.exe': 'RunDLL32'
        }

    def terminate_process(self, pid, name):
        """Termina um processo específico com verificações de segurança"""
        try:
            # Verifica se o PID existe
            if not psutil.pid_exists(pid):
                return False

            process = psutil.Process(pid)
            proc_name = process.name().lower()

            # Verifica se não é um processo crítico ou do próprio antivírus
            if (proc_name in self.critical_processes or 
                proc_name in self.allowed_processes or 
                pid == os.getpid() or  # PID do próprio antivírus
                pid == os.getppid()):  # PID do processo pai
                return False

            # Tenta terminar o processo
            process.terminate()
            self.log_signal.emit(f"[PROTEÇÃO] Processo bloqueado e finalizado: {name}", True)
            self.alert_signal.emit(
                "Proteção em Tempo Real",
                f"Processo bloqueado por segurança: {name}\nEste processo representa um risco potencial."
            )
            return True

        except psutil.NoSuchProcess:
            return False
        except psutil.AccessDenied:
            self.log_signal.emit(f"[AVISO] Acesso negado ao tentar finalizar {name}", True)
            return False
        except Exception as e:
            self.log_signal.emit(f"[ERRO] Falha ao terminar processo {name}: {str(e)}", True)
            return False

    def run(self):
        while self.is_running:
            try:
                # Obtém lista de processos ativos
                current_processes = list(psutil.process_iter(['pid', 'name', 'username', 'cmdline']))
                
                for proc in current_processes:
                    try:
                        if not self.is_running:
                            break

                        proc_info = proc.info
                        proc_name = proc_info['name'].lower()
                        
                        # Ignora processos permitidos e críticos
                        if (proc_name in self.allowed_processes or 
                            proc_name in self.critical_processes):
                            continue
                            
                        # Verifica processos bloqueados
                        if proc_name in self.blocked_processes:
                            self.terminate_process(proc_info['pid'], self.blocked_processes[proc_name])

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                    except Exception as e:
                        self.log_signal.emit(f"[ERRO] Erro ao processar {proc_name}: {str(e)}", True)
                
                # Pausa entre verificações
                QThread.msleep(100)
                
            except Exception as e:
                self.log_signal.emit(f"[ERRO] Erro na proteção em tempo real: {str(e)}", True)
                QThread.msleep(1000)
            
            # Garante que a thread continua rodando mesmo com erros
            if self.is_running:
                QThread.msleep(100)

    def stop(self):
        """Para a thread de forma segura"""
        self.is_running = False

class ProcessProtectionWorker(QObject):
    alert_signal = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.is_running = True

    def run(self):
        """Monitora tentativas de finalização do processo de forma mais suave"""
        while self.is_running:
            try:
                current_process = psutil.Process(os.getpid())
                
                # Monitora processos de forma mais seletiva
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        if proc.pid == current_process.pid:
                            continue

                        # Verifica apenas processos específicos
                        if proc.name().lower() in ['taskkill.exe', 'taskmgr.exe']:
                            cmdline = " ".join(proc.cmdline()).lower()
                            
                            # Verifica apenas se está mirando nosso processo
                            if str(current_process.pid) in cmdline:
                                self.alert_signal.emit()
                                # Em vez de terminar o processo, apenas emite o alerta

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                    except Exception:
                        continue

                QThread.msleep(500)  # Pausa maior para reduzir uso de CPU

            except Exception:
                QThread.msleep(1000)

    def stop(self):
        self.is_running = False

def main():
    try:
        app = QApplication(sys.argv)
        app.setStyleSheet(qdarkstyle.load_stylesheet())
        
        # Configurar loop de eventos para Windows
        if sys.platform.startswith('win'):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        # Criar novo loop de eventos
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        window = AntivirusGUI()
        window.show()
        
        # Executar a aplicação
        sys.exit(app.exec())
        
    except Exception as e:
        print(f"Erro na inicialização: {e}")
        sys.exit(1)
    finally:
        # Fechar o loop de eventos se estiver aberto
        if loop and not loop.is_closed():
            loop.close()

class MemoryProtectionWorker(QObject):
    alert_signal = pyqtSignal(str, str)
    log_signal = pyqtSignal(str, bool)

    def __init__(self):
        super().__init__()
        self.is_running = True
        self.check_interval = 5
        
        # Lista de processos críticos para monitorar
        self.critical_processes = {
            'lsass.exe',
            'winlogon.exe',
            'csrss.exe'
        }

        # Caminhos seguros/normais que devem ser ignorados
        self.safe_paths = [
            'notifications',
            'wpndatabase',
            'cache',
            'cookies',
            'indexdb',
            'webcache',
            'iconcache',
            'windows.storage',
            'windows.data',
            'microsoft\\windows\\explorer',
            'microsoft\\windows\\notifications',
            'microsoft\\windows\\cache'
        ]

        # Extensões seguras para ignorar
        self.safe_extensions = {
            '.db', '.db-shm', '.db-wal',  # Arquivos de banco de dados
            '.dat', '.log', '.tmp',        # Arquivos temporários comuns
            '.cache', '.ico', '.png'       # Arquivos de cache e ícones
        }

    def is_safe_path(self, path):
        """Verifica se é um caminho seguro"""
        path_lower = path.lower()
        
        # Verifica extensões seguras
        if any(path_lower.endswith(ext) for ext in self.safe_extensions):
            return True
            
        # Verifica caminhos seguros
        if any(safe_path in path_lower for safe_path in self.safe_paths):
            return True
            
        return False

    def run(self):
        """Executa o monitoramento de memória"""
        last_check = {}
        last_alert = {}  # Para evitar alertas repetidos
        alert_cooldown = 300  # 5 minutos entre alertas do mesmo processo
        
        while self.is_running:
            try:
                current_time = time.time()
                
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        proc_name = proc.info['name'].lower()
                        proc_pid = proc.info['pid']
                        
                        # Verifica apenas processos críticos
                        if proc_name not in self.critical_processes:
                            continue
                            
                        # Respeita o intervalo de verificação
                        if current_time - last_check.get(proc_pid, 0) < self.check_interval:
                            continue
                            
                        last_check[proc_pid] = current_time
                        
                        # Verifica memória do processo
                        process = psutil.Process(proc_pid)
                        memory_info = process.memory_info()
                        
                        # Verifica uso excessivo de memória (ajustado para 1GB)
                        if memory_info.private > 1024 * 1024 * 1024:  # 1GB
                            if current_time - last_alert.get(f"mem_{proc_pid}", 0) > alert_cooldown:
                                self.log_signal.emit(
                                    f"[ALERTA] Alto uso de memória em {proc_name} "
                                    f"(PID: {proc_pid}) - {memory_info.private / (1024*1024*1024):.2f} GB",
                                    True
                                )
                                last_alert[f"mem_{proc_pid}"] = current_time
                        
                        # Verifica regiões de memória suspeitas
                        try:
                            maps = process.memory_maps()
                            for m in maps:
                                if not self.is_safe_path(m.path):
                                    map_key = f"{proc_pid}_{m.path}"
                                    if current_time - last_alert.get(map_key, 0) > alert_cooldown:
                                        self.log_signal.emit(
                                            f"[ALERTA] Região de memória suspeita em {proc_name} "
                                            f"(PID: {proc_pid})",
                                            True
                                        )
                                        last_alert[map_key] = current_time
                        except:
                            continue
                                
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                    except Exception as e:
                        if "não existe" not in str(e).lower():
                            self.log_signal.emit(f"[ERRO] Erro ao verificar processo: {str(e)}", True)
                
                QThread.msleep(2000)  # Aumentado o intervalo para 2 segundos
                
            except Exception as e:
                self.log_signal.emit(f"[ERRO] Erro no monitor de memória: {str(e)}", True)
                QThread.msleep(5000)

    def stop(self):
        """Para o monitoramento"""
        self.is_running = False

if __name__ == "__main__":
    main()