struct foo { int value; };
void foo_hold(struct foo *foo) { record_access(foo); }
void foo_release_hint(struct foo *foo) { record_access(foo); }
