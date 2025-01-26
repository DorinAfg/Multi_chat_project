import subprocess

for i in range(2):
    subprocess.Popen(['start', 'cmd', '/K', 'python', 'Client.py'], shell=True)
