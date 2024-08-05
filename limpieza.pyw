import os
import shutil
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import platform
import subprocess
import math
import logging
import hashlib

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Determinar el sistema operativo
IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    import winreg

def get_size(start_path='.'):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(start_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            try:
                total_size += os.path.getsize(fp)
            except OSError:
                pass
    return total_size

def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"

def clean_temp_files():
    def clean():
        temp_folders = get_temp_folders()
        total_space_freed = 0
        for folder in temp_folders:
            if folder and os.path.exists(folder):
                space_before = get_size(folder)
                delete_folder_contents(folder)
                space_after = get_size(folder)
                total_space_freed += (space_before - space_after)
        
        # Limpiar archivos temporales de Windows
        if IS_WINDOWS:
            clean_windows_temp_files()
        
        update_status(f"Limpieza de archivos temporales completada. Espacio liberado: {convert_size(total_space_freed)}")

    threading.Thread(target=clean).start()

def get_temp_folders():
    if IS_WINDOWS:
        return [
            os.environ.get('TEMP'),
            os.environ.get('TMP'),
            r'C:\Windows\Temp',
            os.path.join(os.environ.get('LOCALAPPDATA'), 'Temp')
        ]
    else:
        return [
            '/tmp',
            os.path.expanduser('~/.cache'),
        ]

def delete_folder_contents(folder):
    for root, dirs, files in os.walk(folder, topdown=False):
        for name in files:
            try:
                os.remove(os.path.join(root, name))
            except OSError:
                logging.warning(f"No se pudo eliminar el archivo: {os.path.join(root, name)}")
        for name in dirs:
            try:
                os.rmdir(os.path.join(root, name))
            except OSError:
                logging.warning(f"No se pudo eliminar el directorio: {os.path.join(root, name)}")

def clean_windows_temp_files():
    temp_files = [
        '*.tmp', '*.temp', '*.log', '~*.*',
        'prefetch\\*.*', 'Recent\\*.*',
        'Temporary Internet Files\\*.*'
    ]
    for pattern in temp_files:
        try:
            subprocess.run(f'del /s /q /f "{os.path.join(os.environ["SystemRoot"], pattern)}"', shell=True)
        except subprocess.SubprocessError:
            logging.warning(f"Error al eliminar archivos con patrón: {pattern}")

def empty_recycle_bin():
    def empty():
        if IS_WINDOWS:
            try:
                subprocess.run(['powershell.exe', '-Command', 'Clear-RecycleBin', '-Force', '-ErrorAction', 'SilentlyContinue'], check=True)
                update_status("Papelera de reciclaje vaciada.")
            except subprocess.CalledProcessError as e:
                update_status(f"Error al vaciar la papelera: {str(e)}")
        else:
            trash_dir = os.path.expanduser('~/.local/share/Trash/files')
            space_freed = empty_directory(trash_dir)
            update_status(f"Papelera vaciada. Espacio liberado: {convert_size(space_freed)}")

    threading.Thread(target=empty).start()

def empty_directory(directory):
    space_freed = 0
    if os.path.exists(directory):
        for root, dirs, files in os.walk(directory, topdown=False):
            for name in files:
                try:
                    file_path = os.path.join(root, name)
                    size = os.path.getsize(file_path)
                    os.remove(file_path)
                    space_freed += size
                except OSError as e:
                    logging.warning(f"No se pudo eliminar el archivo: {file_path}. Error: {e}")
            for name in dirs:
                try:
                    os.rmdir(os.path.join(root, name))
                except OSError as e:
                    logging.warning(f"No se pudo eliminar el directorio: {os.path.join(root, name)}. Error: {e}")
    return space_freed

def clean_downloads_folder():
    if tk.messagebox.askyesno("Confirmación", "¿Estás seguro de que quieres vaciar la carpeta de descargas?"):
        downloads_folder = os.path.expanduser('~/Downloads')
        space_freed = empty_directory(downloads_folder)
        update_status(f"Carpeta de descargas limpiada. Espacio liberado: {convert_size(space_freed)}")

def clean_browser_data():
    def clean():
        space_freed = 0
        if IS_WINDOWS:
            # Limpiar caché de Chrome
            chrome_cache_path = os.path.expanduser('~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache')
            space_freed += empty_directory(chrome_cache_path)

            # Limpiar caché de Firefox
            firefox_path = os.path.expanduser('~\\AppData\\Local\\Mozilla\\Firefox\\Profiles')
            for profile in os.listdir(firefox_path):
                profile_cache_path = os.path.join(firefox_path, profile, 'cache2')
                space_freed += empty_directory(profile_cache_path)

            # Limpiar caché de Edge
            edge_cache_path = os.path.expanduser('~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Media Cache')
            space_freed += empty_directory(edge_cache_path)

            # Limpiar caché de Opera
            opera_cache_path = os.path.expanduser('~\\AppData\\Roaming\\Opera Software\\Opera Stable\\Cache')
            space_freed += empty_directory(opera_cache_path)

            # Limpiar caché de Brave
            brave_cache_path = os.path.expanduser('~\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Cache')
            space_freed += empty_directory(brave_cache_path)

        else:
            # Limpiar caché de Chrome en Linux
            chrome_cache_path = os.path.expanduser('~/.cache/google-chrome')
            space_freed += empty_directory(chrome_cache_path)

            # Limpiar caché de Firefox en Linux
            firefox_cache_path = os.path.expanduser('~/.cache/mozilla/firefox')
            space_freed += empty_directory(firefox_cache_path)

            # Limpiar caché de Opera en Linux
            opera_cache_path = os.path.expanduser('~/.config/opera/cache')
            space_freed += empty_directory(opera_cache_path)

            # Limpiar caché de Brave en Linux
            brave_cache_path = os.path.expanduser('~/.cache/brave/Default/Cache')
            space_freed += empty_directory(brave_cache_path)

        update_status(f"Caché de navegadores limpiado. Espacio liberado: {convert_size(space_freed)}")

    threading.Thread(target=clean).start()

def clean_system_logs():
    def clean():
        if IS_WINDOWS:
            try:
                subprocess.run('wevtutil el | Foreach-Object {wevtutil cl "$_"}', shell=True)
                update_status("Registros del sistema limpiados.")
            except subprocess.SubprocessError:
                update_status("Error al limpiar los registros del sistema.")
        else:
            try:
                subprocess.run('sudo journalctl --vacuum-time=1d', shell=True)
                update_status("Registros del sistema limpiados.")
            except subprocess.SubprocessError:
                update_status("Error al limpiar los registros del sistema.")

    threading.Thread(target=clean).start()

def optimize_system():
    def optimize():
        if IS_WINDOWS:
            windows_optimize()
        else:
            linux_optimize()

    threading.Thread(target=optimize).start()

def windows_optimize():
    try:
        # Optimizar inicio de Windows
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_ALL_ACCESS)
        count = 0
        while True:
            try:
                name, value, type = winreg.EnumValue(key, 0)
                winreg.DeleteValue(key, name)
                count += 1
            except WindowsError:
                break
        winreg.CloseKey(key)
        update_status(f"Se han eliminado {count} elementos del inicio de Windows.")
        
        
        # Ejecutar limpieza de disco
        subprocess.run(['cleanmgr', '/sagerun:1'], check=True)
        update_status("Limpieza de disco completada.")

    except Exception as e:
        update_status(f"Error durante la optimización: {str(e)}")


def get_linux_distro():
    with open("/etc/os-release") as f:
        lines = f.readlines()
    distro_info = {}
    for line in lines:
        key, value = line.rstrip().split("=")
        distro_info[key] = value.strip('"')
    return distro_info.get("ID", "").lower()
def linux_optimize():
    distro_id = get_linux_distro()
    print(distro_id)
    commands = []

    if 'ubuntu' in distro_id or 'debian' in distro_id:
        commands = [
            "sudo apt-get clean",
            "sudo apt-get autoremove -y",
            "sudo apt-get autoclean",
            "sudo journalctl --vacuum-size=50M",
            "sudo apt-get -y remove --purge $(dpkg -l | awk '/^rc/ { print $2 }')",
            "sudo apt-get -y remove --purge $(dpkg -l | awk '/^ii linux-(image|headers)-[^ ]+/{print $2}' | grep -v $(uname -r | sed 's/-generic//'))",
            "sudo update-grub"
        ]
    elif 'arch' in distro_id or 'manjaro' in distro_id:
        commands = [
            "sudo pacman -Scc --noconfirm",
            "sudo pacman -Rns $(pacman -Qdtq) --noconfirm",
            "sudo journalctl --vacuum-size=50M",
            "sudo pacman -R $(pacman -Qq | grep '^linux' | grep -v $(uname -r)) --noconfirm",
            "sudo grub-mkconfig -o /boot/grub/grub.cfg"

        ]
    elif 'fedora' in distro_id:
        commands = [
            "sudo dnf clean all",
            "sudo dnf autoremove -y",
            "sudo journalctl --vacuum-size=50M",
            "sudo dnf remove $(dnf repoquery --installonly --latest-limit=-1 -q) -y",
            "sudo grub2-mkconfig -o /boot/grub2/grub.cfg"
        ]
    elif 'opensuse' in distro_id:
        commands = [
            "sudo zypper clean --all",
            "sudo zypper rm $(zypper packages --unneeded | awk 'NR>3 {print $3}')",
            "sudo journalctl --vacuum-size=50M",
            "sudo zypper rm $(rpm -q --queryformat '%{NAME}\n' $(rpm -q -a | grep '^kernel-') | grep -v $(uname -r))",
            "sudo grub2-mkconfig -o /boot/grub2/grub.cfg"
        ]
    else:
        print("Unsupported Linux distribution.")
        return

    for cmd in commands:
        try:
            subprocess.run(cmd, shell=True, check=True)
            update_status(f"Comando ejecutado: {cmd}")
        except subprocess.CalledProcessError:
            update_status(f"Error al ejecutar: {cmd}")
    

    update_status("Optimización del sistema completada.")

def analyze_disk_space():
    def analyze():
        root_dir = "C:\\" if IS_WINDOWS else "/"
        total, used, free = shutil.disk_usage(root_dir)
        update_status(f"Espacio total: {convert_size(total)}\n"
                      f"Espacio usado: {convert_size(used)}\n"
                      f"Espacio libre: {convert_size(free)}")

    threading.Thread(target=analyze).start()

def find_duplicate_files():
    def find_duplicates():
        directory = filedialog.askdirectory(title="Seleccione el directorio para buscar duplicados")
        if not directory:
            return

        update_status("Buscando archivos duplicados...")
        duplicates = {}
        for dirpath, dirnames, filenames in os.walk(directory):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                try:
                    file_hash = hash_file(filepath)
                    if file_hash in duplicates:
                        duplicates[file_hash].append(filepath)
                    else:
                        duplicates[file_hash] = [filepath]
                except IOError:
                    continue

        duplicate_files = [files for files in duplicates.values() if len(files) > 1]
        
        if duplicate_files:
            report = "Archivos duplicados encontrados:\n\n"
            for files in duplicate_files:
                report += f"Tamaño: {convert_size(os.path.getsize(files[0]))}\n"
                for file in files:
                    report += f"- {file}\n"
                report += "\n"
            
            show_report(report)
        else:
            update_status("No se encontraron archivos duplicados.")

    threading.Thread(target=find_duplicates).start()

def hash_file(filepath):
    BUF_SIZE = 65536
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()

def show_report(report):
    report_window = tk.Toplevel(root)
    report_window.title("Reporte de Archivos Duplicados")
    report_window.geometry("600x400")

    report_text = tk.Text(report_window, wrap=tk.WORD)
    report_text.pack(expand=True, fill=tk.BOTH)
    report_text.insert(tk.END, report)

    scrollbar = ttk.Scrollbar(report_text, orient="vertical", command=report_text.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    report_text.config(yscrollcommand=scrollbar.set)

def update_status(message):
    status_text.config(state=tk.NORMAL)
    status_text.insert(tk.END, message + "\n")
    status_text.see(tk.END)
    status_text.config(state=tk.DISABLED)
    logging.info(message)

# Crear la interfaz gráfica
root = tk.Tk()
root.title("Optimizador de Sistema Avanzado")
root.geometry("600x550")

style = ttk.Style()
style.theme_use("clam")

main_frame = ttk.Frame(root, padding="10")
main_frame.pack(fill=tk.BOTH, expand=True)

# Crear pestañas
notebook = ttk.Notebook(main_frame)
notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Pestaña de limpieza
cleaning_tab = ttk.Frame(notebook)
notebook.add(cleaning_tab, text="Limpieza")

ttk.Button(cleaning_tab, text="Limpiar archivos temporales", command=clean_temp_files).pack(pady=5, padx=10, fill=tk.X)
ttk.Button(cleaning_tab, text="Vaciar papelera", command=empty_recycle_bin).pack(pady=5, padx=10, fill=tk.X)
ttk.Button(cleaning_tab, text="Limpiar carpeta de descargas", command=clean_downloads_folder).pack(pady=5, padx=10, fill=tk.X)
ttk.Button(cleaning_tab, text="Limpiar caché de navegadores", command=clean_browser_data).pack(pady=5, padx=10, fill=tk.X)
ttk.Button(cleaning_tab, text="Limpiar registros del sistema", command=clean_system_logs).pack(pady=5, padx=10, fill=tk.X)

# Pestaña de optimización
optimization_tab = ttk.Frame(notebook)
notebook.add(optimization_tab, text="Optimización")

ttk.Button(optimization_tab, text="Optimizar sistema", command=optimize_system).pack(pady=5, padx=10, fill=tk.X)
ttk.Button(optimization_tab, text="Analizar espacio en disco", command=analyze_disk_space).pack(pady=5, padx=10, fill=tk.X)

# Pestaña de duplicados
duplicates_tab = ttk.Frame(notebook)
notebook.add(duplicates_tab, text="Duplicados")

ttk.Button(duplicates_tab, text="Buscar duplicados", command=find_duplicate_files).pack(pady=5, padx=10, fill=tk.X)

# Área de estado
status_frame = ttk.LabelFrame(main_frame, text="Estado", padding="10")
status_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

status_text = tk.Text(status_frame, height=10, wrap=tk.WORD, state=tk.DISABLED)
status_text.pack(fill=tk.BOTH, expand=True)

scrollbar = ttk.Scrollbar(status_frame, orient="vertical", command=status_text.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
status_text.config(yscrollcommand=scrollbar.set)

root.mainloop()
