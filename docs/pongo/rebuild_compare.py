#!/usr/bin/env python3
"""Rebuild a pinned Pongo source with/without QUIET_BOOT. No device access."""
import argparse,hashlib,json,os,shutil,subprocess
from pathlib import Path

COMMIT='bb492b004265ce91123caa23b8bc04b2eff6d2b7'
NEWLIB='f9ea5054de8fb51dff6f6d3c2e7cdd4aa89744b8'
EXPECTED={'quiet':'c6aa270ba22d40036487b027d5bb9b67955c35def61ceb65cff2b358dd40d80b','normal':'90086685c73a066a05b736cc1908308ba2cda2a5283cdfebc1f7d9b62d41234d'}
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--source',required=True,type=Path);ap.add_argument('--output',required=True,type=Path);ap.add_argument('--developer-dir',type=Path);a=ap.parse_args()
 src=a.source.resolve();out=a.output.resolve();here=Path(__file__).resolve().parent
 if subprocess.check_output(['git','-C',str(src),'rev-parse','HEAD'],text=True).strip()!=COMMIT:raise ValueError('Wrong Pongo commit')
 if subprocess.check_output(['git','-C',str(src/'newlib'),'rev-parse','HEAD'],text=True).strip()!=NEWLIB:raise ValueError('Wrong newlib commit')
 subprocess.run(['git','-C',str(src),'apply','--reverse','--check',str(here/'pongo.patch')],check=True)
 provenance=json.loads((here/'source-provenance.json').read_text())
 for name,sha in provenance['source_files'].items():
  if digest(src/name)!=sha:raise ValueError('Unexpected source content: '+name)
 changed=set(subprocess.check_output(['git','-C',str(src),'diff','--name-only'],text=True).splitlines())
 if changed!={'src/drivers/framebuffer/fb.c','src/kernel/entry.c'}:raise ValueError('Only the published quiet patch may modify source')
 if out.exists():raise ValueError('Choose a new output directory')
 out.mkdir(parents=True)
 env=dict(os.environ)
 if a.developer_dir:env['DEVELOPER_DIR']=str(a.developer_dir.resolve())
 compiler=subprocess.check_output(['xcrun','-sdk','iphoneos','clang','--version'],env=env,text=True).splitlines()[0]
 sdk=subprocess.check_output(['xcrun','-sdk','iphoneos','--show-sdk-version'],env=env,text=True).strip()
 receipt={'source_commit':COMMIT,'newlib_commit':NEWLIB,'compiler':compiler,'sdk_version':sdk,'source_diff_held_fixed':True,'forced_target_rebuild':True,'hardware_tested_by_this_script':False,'runs':[]}
 for variant in ['quiet-1','normal-1','quiet-2']:
  quiet=variant.startswith('quiet')
  # Make does not treat changed CFLAGS as a dependency. -W forces the final
  # source target each round without deleting the pinned newlib build cache.
  with (out/(variant+'.log')).open('w') as log:subprocess.run(['make','-C',str(src),'-j4','-W','src/drivers/framebuffer/fb.c','PONGO_CFLAGS='+('-DQUIET_BOOT' if quiet else ''),'build/Pongo.bin'],env=env,check=True,stdout=log,stderr=subprocess.STDOUT)
  for name in ['Pongo','Pongo.bin']:shutil.copy2(src/'build'/name,out/(variant+'-'+name))
  binary=out/(variant+'-Pongo.bin');sha=digest(binary)
  receipt['runs'].append({'variant':variant,'quiet_define':quiet,'bytes':binary.stat().st_size,'sha256':sha,'matches_recorded_build':sha==EXPECTED['quiet' if quiet else 'normal']})
  (out/'rebuild-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
 if receipt['runs'][0]['sha256']!=receipt['runs'][2]['sha256']:raise RuntimeError('Quiet repeat was not reproducible')
 print('Rebuilds complete. See the receipt; this does not establish hardware boot success.')
if __name__=='__main__':main()
