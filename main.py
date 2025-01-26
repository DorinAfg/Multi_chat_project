import subprocess

#'start' and 'cmd' open windows of CMD
#'/K' to keep it open
for i in range(2):
    subprocess.Popen(['start', 'cmd', '/K', 'python', 'Client.py'], shell=True)
