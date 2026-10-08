struct foo { refcount_t refs; };
void foo_put_tracker(struct foo *foo) { ref_tracker_alloc(&foo->refs, foo); }
