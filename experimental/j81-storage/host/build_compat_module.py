"""Build only the range-gated ASP module for the already-qualified ro-v2 kernel."""
from pathlib import Path
import hashlib,json,os,re,subprocess
root=Path.cwd();task=root/'work/j81-internal-install';base=root/'work/orchard-integration/linux-build/j81-module-compat';old=root/'work/orchard-integration/linux-build/j81-storage-candidate'
assert (base/'output/.config').read_bytes()==(old/'output/.config').read_bytes()
assert (task/'kernel-ro-v2mod/kernel.release').read_text().strip()=='7.3.0-rc1-orchard-j81-storage-ro-v2mod'
args=['/opt/homebrew/bin/podman','run','--rm','--network','none','--userns','keep-id','-v',str(base/'source')+':/src:ro','-v',str(base/'output')+':/out:rw','localhost/orchard-hardware-kernel-toolchain:bookworm','bash','-euc','export KBUILD_BUILD_USER=orchard KBUILD_BUILD_HOST=builder KBUILD_BUILD_VERSION=1 KBUILD_BUILD_TIMESTAMP=2026-10-22T00:00:00Z; make -C /src O=/out -j4 LLVM=-19 ARCH=arm64 LOCALVERSION=-orchard-j81-storage-ro-v2mod drivers/block/asp.ko; llvm-nm-19 -u /out/drivers/block/asp.ko > /out/asp-undefined-symbols.txt']
with (task/'module-compat-build.log').open('w') as f:subprocess.run(args,check=True,stdout=f,stderr=subprocess.STDOUT)
module=base/'output/drivers/block/asp.ko';orig=task/'kernel-ro-v2mod/lib/modules/7.3.0-rc1-orchard-j81-storage-ro-v2mod/kernel/drivers/block/asp.ko'
def info(path,key):return re.findall(key.encode()+rb'=([^\0]+)',path.read_bytes())
for key in ['vermagic','depends','alias']:
 assert sorted(info(module,key))==sorted(info(orig,key)),key
symbols={line.split()[1] for line in (old/'output/Module.symvers').read_text().splitlines()}
undefined=[line.split()[-1] for line in (base/'output/asp-undefined-symbols.txt').read_text().splitlines() if line.strip()]
assert set(undefined)<=symbols,sorted(set(undefined)-symbols)
report={'kernel_release':'7.3.0-rc1-orchard-j81-storage-ro-v2mod','module_sha256':hashlib.sha256(module.read_bytes()).hexdigest(),'module_bytes':module.stat().st_size,'vermagic_matches_baseline':True,'dependencies_match_baseline':True,'aliases_match_baseline':True,'undefined_symbols_all_in_baseline_exports':True,'undefined_symbol_count':len(undefined),'base_kernel_config_unchanged':True,'kernel_image_rebuilt_or_replaced':False,'hardware_tested':False,'write_qualification':False}
(task/'MODULE-COMPAT-BUILD-VERIFIED.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)
