#include <linux/kref.h>
struct foo { struct kref ref; };
void foo_kref_get(struct foo *foo) { kref_get(&foo->ref); }
void foo_kref_put(struct foo *foo) { kref_put(&foo->ref, foo_destroy); }
