"""Local noVNC UI -> pinned owner SSH exec channel -> guest localhost WayVNC."""
from pathlib import Path
import contextlib,json,os,secrets,select,shlex,signal,socket,socketserver,subprocess,sys,threading,time,urllib.parse
import paramiko
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
PRIVATE=ROOT/'work/j81-internal-install/private-live'
STATE=HERE/'private-live'
BRIDGE='''import os,select,socket
s=socket.create_connection(('127.0.0.1',5900),5)
s.settimeout(None)
while True:
 ready,_,_=select.select([0,s],[],[],30)
 for source in ready:
  if source==0:
   data=os.read(0,65536)
   if not data:raise SystemExit
   s.sendall(data)
  else:
   data=s.recv(65536)
   if not data:raise SystemExit
   while data:
    n=os.write(1,data);data=data[n:]
'''
class Relay(socketserver.BaseRequestHandler):
 def handle(self):
  transport=None
  try:
   sock=socket.create_connection(('10.71.0.1',2222),8)
   if sock.getsockname()[0]!='10.71.0.2':raise RuntimeError('USB owner link required')
   transport=paramiko.Transport(sock);transport.start_client(timeout=10)
   pin=json.loads((PRIVATE/'native-install-run/owner-ssh-hostkey.json').read_text())
   key=transport.get_remote_server_key()
   if (key.get_name(),key.get_base64())!=(pin['type'],pin['base64']):raise RuntimeError('Owner SSH identity changed')
   transport.auth_publickey('tablet',paramiko.Ed25519Key.from_private_key_file(str(PRIVATE/'native-root-package/owner_ed25519')))
   channel=transport.open_session(timeout=10);channel.exec_command(shlex.join(['python3','-u','-c',BRIDGE]))
   while True:
    ready,_,_=select.select([self.request,channel],[],[],30)
    for source in ready:
     data=source.recv(65536)
     if not data:return
     (channel if source is self.request else self.request).sendall(data)
  except Exception as error:
   with (STATE/'relay-errors.log').open('a') as f:f.write(type(error).__name__+': '+str(error)+'\n')
  finally:
   if transport:transport.close()
class Server(socketserver.ThreadingTCPServer):
 daemon_threads=True
 allow_reuse_address=False

def main():
 os.umask(0o077);STATE.mkdir(mode=0o700,exist_ok=True)
 if not (HERE/'noVNC/vnc.html').is_file():raise RuntimeError('Pinned local noVNC checkout missing')
 token=secrets.token_urlsafe(32)
 with Server(('127.0.0.1',0),Relay) as relay:
  port=relay.server_address[1]
  tokenfile=STATE/'tokens';tokenfile.write_text(token+': 127.0.0.1:'+str(port)+'\n')
  threading.Thread(target=relay.serve_forever,daemon=True).start()
  with (STATE/'websockify.log').open('w') as log:
   child=subprocess.Popen([sys.executable,'-m','websockify','--web',str(HERE/'noVNC'),'--token-plugin','TokenFile','--token-source',str(tokenfile),'127.0.0.1:6081'],stdout=log,stderr=subprocess.STDOUT)
   def stop(*args):raise KeyboardInterrupt
   signal.signal(signal.SIGTERM,stop)
   try:
    for _ in range(100):
     if child.poll() is not None:raise RuntimeError('Local WebSocket server stopped; inspect its private log')
     try:
      with socket.create_connection(('127.0.0.1',6081),0.2):break
     except OSError:time.sleep(0.1)
    else:raise RuntimeError('Local WebSocket server did not start')
    query=urllib.parse.urlencode({'autoconnect':'true','resize':'scale','reconnect':'true','reconnect_delay':'1000','path':'websockify?token='+token})
    (STATE/'control-url.txt').write_text('http://127.0.0.1:6081/vnc.html?'+query+'\n')
    (STATE/'service.json').write_text(json.dumps({'pid':os.getpid(),'websocket_pid':child.pid,'listen':'127.0.0.1:6081','transport':'pinned USB owner SSH exec','guest':'127.0.0.1:5900'})+'\n')
    print('READY: private local J81 desktop control',flush=True)
    child.wait()
   except KeyboardInterrupt:pass
   finally:
    if child.poll() is None:child.terminate()
    with contextlib.suppress(subprocess.TimeoutExpired):child.wait(timeout=5)
    relay.shutdown()
if __name__=='__main__':main()
