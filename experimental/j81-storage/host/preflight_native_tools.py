"""Run released ARM64 installer tools on J81; writes only under guest /run."""
from pathlib import Path
import hashlib, http.server, json, secrets, shlex, socket, threading
from orchard_cli.apple.usb import devices
from orchard_cli.serial import SerialPort

TASK = Path(__file__).resolve().parent
PRIVATE = TASK / 'private-live'
RELEASE = '7.3.0-rc1-orchard-j81-storage-ro-v2mod'

def main():
    expected = json.loads((PRIVATE / 'selected-device.json').read_text())
    def target():
        found = [d for d in devices() if d['location'] == expected['location']
                 and d.get('product') in ('Orchard j81_storage_ro', 'Orchard j81-storage-ro')
                 and d.get('serial_port')]
        if len(found) != 1:
            raise RuntimeError('Selected diagnostic USB endpoint is unavailable')
        return found[0]
    manifest = json.loads((TASK / 'native-install-tools/manifest.json').read_text())
    payload = (TASK / 'native-install-tools/tools.tar.gz').read_bytes()
    if hashlib.sha256(payload).hexdigest() != manifest['tar_sha256']:
        raise RuntimeError('Native tools archive changed')
    with socket.create_connection(('10.71.0.1', 8080), timeout=5) as sock:
        if sock.getsockname()[0] != '10.71.0.2':
            raise RuntimeError('Expected dedicated USB network source address')
    token = secrets.token_hex(16)
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            if self.client_address[0] != '10.71.0.1' or self.path != '/' + token:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Type', 'application/gzip')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
    server = http.server.HTTPServer(('10.71.0.2', 0), Handler)
    server.timeout = 10
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    report = {'writes_to_internal_storage': False, 'passed': False}
    ram = '/run/j81-native-tools-preflight-' + secrets.token_hex(5)
    def cleanup_command(path):
        target = path + '/root/dev/null'
        return ('if awk -v target=' + shlex.quote(target) +
                ' \'$2 == target {found=1} END {exit !found}\' /proc/mounts; '
                'then umount ' + shlex.quote(target) + ' || exit 1; fi; rm -rf ' + shlex.quote(path))
    try:
        with SerialPort(target()['serial_port'], target) as port:
            def run(command, timeout=25):
                rc, data = port.run(command, timeout=timeout)
                if rc:
                    raise RuntimeError('Guest preflight failed: ' + data[-1500:])
                return data
            identity = run('uname -r; tr "\\000" "\\n" < /proc/device-tree/compatible; '
                           'awk \'$2 == "/run" {print $3}\' /proc/mounts; '
                           'cat /sys/module/asp/parameters/write_first_lba; '
                           'cat /sys/module/asp/parameters/write_lba_count')
            lines = identity.splitlines()
            if (not lines or lines[0] != RELEASE or 'apple,j81' not in lines
                    or 'apple,t7001' not in lines or 'tmpfs' not in lines
                    or lines[-2:] != ['15624738', '1']):
                raise RuntimeError('Board, kernel, RAM mount or immutable one-block gate changed')
            run('umask 077; mkdir ' + shlex.quote(ram))
            try:
                print('Verified J81 identity and unchanged one-block gate; transferring tools over USB.', flush=True)
                url = 'http://10.71.0.2:' + str(server.server_port) + '/' + token
                run('timeout 120 wget -q -O ' + ram + '/tools.tar.gz ' + shlex.quote(url), timeout=130)
                if run('sha256sum ' + ram + '/tools.tar.gz').split()[0] != manifest['tar_sha256']:
                    raise RuntimeError('Guest archive hash mismatch')
                run('mkdir ' + ram + '/root; tar -xzf ' + ram + '/tools.tar.gz -C ' + ram + '/root', timeout=45)
                # A minimal native runtime still needs its own null device and
                # mount table. Only a regular RAM fixture is formatted below.
                # /run is nodev: creating a character node there is insufficient.
                run('mkdir -p ' + ram + '/root/dev; touch ' + ram + '/root/dev/null; '
                    'mount -o bind /dev/null ' + ram + '/root/dev/null; '
                    'cp /proc/mounts ' + ram + '/root/etc/mtab')
                prefix = 'chroot ' + ram + '/root /usr/bin/'
                versions = {}
                for name, arg in [('mke2fs', '-V'), ('e2fsck', '-V'), ('bsdtar', '--version'),
                                  ('zstd', '--version'), ('sfdisk', '--version'), ('blkid', '--version')]:
                    versions[name] = run(prefix + name + ' ' + arg).strip()
                report['tool_versions'] = versions
                print('All six released ARM64 tools execute natively; checking a RAM file filesystem.', flush=True)
                run('dd if=/dev/zero of=' + ram + '/root/fixture.img bs=1048576 count=64 2>/dev/null', timeout=30)
                report['ram_mke2fs'] = run(prefix + 'mke2fs -q -t ext4 -F -E nodiscard,lazy_itable_init=0,lazy_journal_init=0 /fixture.img', timeout=60).strip()
                report['ram_e2fsck'] = run(prefix + 'e2fsck -fn /fixture.img', timeout=60).strip()
                if 'ERROR:' in report['ram_e2fsck'] or 'Pass 5:' not in report['ram_e2fsck']:
                    raise RuntimeError('Native filesystem check did not complete cleanly')
                loader = ram + '/root/lib/ld-linux-aarch64.so.1 --library-path ' + ram + '/root/usr/lib '
                table = json.loads(run(loader + ram + '/root/usr/bin/sfdisk --json /dev/asp0n1'))['partitiontable']
                (PRIVATE / 'native-tools-partition-table.json').write_text(json.dumps(table, indent=2) + '\n')
                parts = table['partitions']
                if table['label'] != 'gpt' or len(parts) != 1 or parts[0]['type'].lower() != '7c3457ef-0000-11aa-aa11-00306543ecac':
                    raise RuntimeError('Original APFS layout changed')
                report['original_apfs_layout_read_only_check'] = True
            finally:
                run(cleanup_command(ram), timeout=30)
                report['ram_files_cleaned'] = True
            report['passed'] = True
    finally:
        server.shutdown()
        server.server_close()
        (TASK / 'native-install-tools/device-preflight.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
