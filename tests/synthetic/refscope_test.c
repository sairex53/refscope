#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/refcount.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
struct rs_object { refcount_t refs; };
static struct rs_object object;
static struct rs_object concurrent_object;
static DEFINE_MUTEX(run_lock);
static struct dentry *directory;
void rs_test_create(struct rs_object *obj, unsigned long reason);
void rs_test_get(struct rs_object *obj, unsigned long reason);
void rs_test_put(struct rs_object *obj, unsigned long reason);
void rs_test_free(struct rs_object *obj, unsigned long reason);
noinline void rs_test_create(struct rs_object *obj, unsigned long reason)
{ refcount_set(&obj->refs, 1); barrier(); }
noinline void rs_test_get(struct rs_object *obj, unsigned long reason)
{ refcount_inc(&obj->refs); barrier(); }
noinline void rs_test_put(struct rs_object *obj, unsigned long reason)
{ refcount_dec(&obj->refs); barrier(); }
noinline void rs_test_free(struct rs_object *obj, unsigned long reason)
{ WARN_ON(!refcount_dec_and_test(&obj->refs)); barrier(); }
static ssize_t run_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
    unsigned long cycles;
    int err = kstrtoul_from_user(buf, count, 10, &cycles);
    if (err) return err;
    if (!cycles || cycles > 1000000) return -EINVAL;
    if (!mutex_trylock(&run_lock)) return -EBUSY;
    for (unsigned long i = 0; i < cycles; i++) {
        rs_test_create(&object, 0);
        rs_test_get(&object, 1); rs_test_get(&object, 2);
        rs_test_put(&object, 2); rs_test_put(&object, 1);
        rs_test_free(&object, 0);
        cond_resched();
    }
    mutex_unlock(&run_lock);
    return count;
}
/* Independent writers share one atomic refcount with a permanent base ref.
 * No global lock serializes this workload. Each (TID, iteration, op) is unique. */
static ssize_t concurrent_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
    unsigned long cycles;
    int err = kstrtoul_from_user(buf, count, 10, &cycles);
    if (err) return err;
    if (!cycles || cycles > 1000000) return -EINVAL;
    for (unsigned long i = 0; i < cycles; i++) {
        unsigned long token = ((unsigned long)current->pid << 32) | i;
        rs_test_get(&concurrent_object, token);
        rs_test_put(&concurrent_object, token);
        if (!(i & 255)) cond_resched();
    }
    return count;
}
static const struct file_operations concurrent_ops = { .owner = THIS_MODULE, .write = concurrent_write };
static const struct file_operations ops = { .owner = THIS_MODULE, .write = run_write };
static int __init rs_init(void)
{
    refcount_set(&concurrent_object.refs, 1);
    directory = debugfs_create_dir("refscope_test", NULL);
    if (IS_ERR(directory)) return PTR_ERR(directory);
    debugfs_create_file("run", 0200, directory, NULL, &ops);
    debugfs_create_file("concurrent", 0200, directory, NULL, &concurrent_ops);
    return 0;
}
static void __exit rs_exit(void) { debugfs_remove_recursive(directory); }
module_init(rs_init); module_exit(rs_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Deterministic RefScope test fixture; debugfs write triggers six events per cycle");
