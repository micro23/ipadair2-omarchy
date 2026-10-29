"""Preconditions for one bounded read from the J81 user-data namespace."""
import re

RELEASE='7.3.0-rc1-orchard-j81-storage-ro-v1'
CRASH=re.compile(rb'Kernel panic|Oops:|WARNING: CPU|\bBUG:|Unable to handle|Call Trace:|WRITE_UNLOCK',re.I)
class InspectionStop(RuntimeError):pass

def validate_read_target(release,namespaces,log):
    if release != RELEASE:raise InspectionStop('Wrong storage-inspection kernel')
    names=[r['name'] for r in namespaces]
    expected={'asp0n'+str(i) for i in range(1,11)}
    if len(names)!=10 or set(names)!=expected:raise InspectionStop('Expected exactly the ten ASP namespaces')
    if any(r['ro']!=1 for r in namespaces):raise InspectionStop('An ASP namespace is writable')
    if CRASH.search(log):raise InspectionStop('Kernel stop condition in storage log')
    user=next(r for r in namespaces if r['name']=='asp0n1')
    if user['logical_block_size']!=4096 or user['bytes']<4096:raise InspectionStop('Unexpected USERAREA geometry')
    return 'asp0n1'
