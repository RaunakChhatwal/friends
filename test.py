import subprocess as sp
import tempfile
import os
import time
import sys
from pathlib import Path

temp_dir = Path(tempfile.mkdtemp())
print(f'Test folder: {temp_dir}')
database_url = f'sqlite://{temp_dir}/data.db?mode=rwc'
sp.run(['sea-orm-cli', 'migrate', 'up', '-d', 'migration/', '-u', database_url], check=True)

env = dict(os.environ)
env.update({
    'JWT_SECRET': 'mcdonalds',
    'LOG_DIR': temp_dir,
    'DATABASE_URL': database_url,
    'PORT': '8000'
})

server = sp.Popen(['cargo', 'run', '--bin', 'server'], env=env)

try:
    while not (temp_dir/'logs').exists():
        time.sleep(0.1)

    with open(temp_dir/'logs') as logs:
        while 'Starting server...' not in logs.read():
            continue

    sp.run(['cargo', 'test'] + sys.argv[1:], env=env)

    server.terminate()
    server.wait()
except KeyboardInterrupt:
    server.terminate()