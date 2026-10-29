#include <assert.h>
#include <limits.h>
#include "j81_asp_write_range.h"
int main(void) {
 const unsigned long long cap=15625000;
 assert(!j81_asp_write_range_allowed(cap,0,0,0,1));
 assert(!j81_asp_write_range_allowed(cap,100,1,100,0));
 assert(j81_asp_write_range_allowed(cap,100,1,100,1));
 assert(!j81_asp_write_range_allowed(cap,100,1,99,1));
 assert(!j81_asp_write_range_allowed(cap,100,1,101,1));
 assert(!j81_asp_write_range_allowed(cap,100,1,100,2));
 assert(j81_asp_write_range_allowed(cap,6,cap-12,6,cap-12));
 assert(!j81_asp_write_range_allowed(cap,6,cap-12,5,1));
 assert(!j81_asp_write_range_allowed(cap,6,cap-12,cap-6,1));
 assert(!j81_asp_write_range_allowed(cap,cap+1,1,cap+1,1));
 assert(!j81_asp_write_range_allowed(cap,cap,1,cap,1));
 assert(!j81_asp_write_range_allowed(cap,ULLONG_MAX,2,ULLONG_MAX,1));
 assert(!j81_asp_write_range_allowed(cap,1,ULLONG_MAX,1,1));
 assert(!j81_asp_write_range_allowed(cap,0,cap,ULLONG_MAX,1));
 assert(j81_asp_write_range_allowed(ULLONG_MAX,ULLONG_MAX-1,1,ULLONG_MAX-1,1));
 assert(!j81_asp_write_range_allowed(ULLONG_MAX,ULLONG_MAX-1,1,ULLONG_MAX,1));
 return 0;
}
