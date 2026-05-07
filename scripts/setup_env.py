"""
Setup script to download required binaries for SiteMap Guard v3:
- nuclei (ProjectDiscovery)
- httpx (ProjectDiscovery)
- ffuf
- obscura
"""
import os
import sys
import urllib.request
import zipfile
import tarfile
from pathlib import Path

# Static URLs for binaries (cross-platform handling could be expanded, simplified here for Windows/Linux x64)
# For a production script, we'd dynamically fetch the latest release from GitHub API.
# Here we'll hardcode some recent versions for simplicity.

BINARIES = {
 "win32": {
 "nuclei": "https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_windows_amd64.zip",
 "httpx": "https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_windows_amd64.zip",
 "ffuf": "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_windows_amd64.zip",
 "obscura": "https://github.com/h4ckf0r0day/obscura/releases/download/v0.1.1/obscura-x86_64-windows.zip"
 },
 "linux": {
 "nuclei": "https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip",
 "httpx": "https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_amd64.zip",
 "ffuf": "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz",
 "obscura": "https://github.com/h4ckf0r0day/obscura/releases/download/v0.1.1/obscura-x86_64-linux.tar.gz"
 }
}

def get_urls():
 if sys.platform == "win32":
 return BINARIES["win32"]
 else:
 return BINARIES["linux"] # Fallback to linux amd64 for now

def main():
 root_dir = Path(__file__).parent.parent
 bin_dir = root_dir / "bin"
 bin_dir.mkdir(exist_ok=True)
 
 urls = get_urls()
 
 for tool_name, url in urls.items():
 filename = url.split("/")[-1]
 archive_path = bin_dir / filename
 
 print(f"Downloading {tool_name} from {url}...")
 try:
 urllib.request.urlretrieve(url, archive_path)
 
 print(f"Extracting {filename}...")
 if filename.endswith(".zip"):
 with zipfile.ZipFile(archive_path, "r") as zip_ref:
 # Extract only the executable file
 for file_info in zip_ref.infolist():
 if file_info.filename.endswith(".exe") or file_info.filename == tool_name or "obscura" in file_info.filename:
 zip_ref.extract(file_info, bin_dir)
 elif filename.endswith(".tar.gz"):
 with tarfile.open(archive_path, "r:gz") as tar_ref:
 for member in tar_ref.getmembers():
 if member.name.endswith(".exe") or member.name == tool_name or "obscura" in member.name:
 tar_ref.extract(member, bin_dir)
 
 # Clean up archive
 archive_path.unlink()
 
 # Make executable on Unix
 if sys.platform != "win32":
 tool_bin = bin_dir / tool_name
 if tool_bin.exists():
 os.chmod(tool_bin, 0o755)
 
 print(f"Successfully installed {tool_name}!\n")
 
 except Exception as e:
 print(f"Failed to install {tool_name}: {e}")

if __name__ == "__main__":
 main()