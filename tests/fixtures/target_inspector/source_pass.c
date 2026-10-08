#include <linux/refcount.h>
#include <linux/kref.h>
#include <linux/percpu-refcount.h>

struct foo { refcount_t refs; refcount_t secondary; struct kref ref; struct percpu_ref percpu; };

static inline void foo_inline_get(struct foo *obj) { refcount_inc(&obj->refs); }
void foo_dec(struct foo *obj) { refcount_dec_and_test(&obj->refs); }
void foo_kref_hold(struct foo *obj) { kref_get(&obj->ref); }
void foo_kref_drop(struct foo *obj) { kref_put(&obj->ref, foo_release); }
void foo_percpu_get(struct foo *obj) { percpu_ref_get(&obj->percpu); }
void foo_percpu_put(struct foo *obj) { percpu_ref_put(&obj->percpu); }
void foo_multiple_fields(struct foo *obj) {
    refcount_inc(&obj->refs);
    refcount_inc(&obj->secondary);
}
void foo_ambiguous_get(struct foo *left, struct foo *right) {
    refcount_inc(&left->refs);
    refcount_inc(&right->refs);
}
static void foo_ref_helper(struct foo *value) { refcount_inc(&value->refs); }
void foo_get_via_helper(struct foo *obj) { foo_ref_helper(obj); }

#define foo_macro_get(value) refcount_inc(&value->refs)
void foo_global_get(struct foo *obj) { refcount_inc(&global.refs); }
