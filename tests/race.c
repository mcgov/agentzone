/* TOCTOU on execve argv: one thread flips argv[1] between "benign" and
 * "EVIL!!" while another thread calls execve with it. Whatever a syscall-entry
 * hook reads may differ from what the kernel actually copies. */
#include <pthread.h>
#include <string.h>
#include <unistd.h>
static char buf[16] = "benign";
static volatile int sink;
static void spin(void) { for (volatile int i = 0; i < 200; i++) ; }
static void *flipper(void *_) {
    for (;;) { memcpy(buf, "EVIL!!", 7); spin(); memcpy(buf, "benign", 7); spin(); }
}
static void *execer(void *_) {
    static char path[] = "/bin/echo", name[] = "echo";   /* writable + touched */
    char *argv[] = { name, buf, NULL };
    sink = path[0] + name[0];
    execve(path, argv, (char *[]){ NULL });
    return 0;
}
int main(void) {
    pthread_t f, e;
    pthread_create(&f, 0, flipper, 0);
    usleep(200);
    pthread_create(&e, 0, execer, 0);
    pthread_join(e, 0);
    return 1;
}
