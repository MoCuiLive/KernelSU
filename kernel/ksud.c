#include <asm/current.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
#include <linux/input-event-codes.h>
#else
#include <uapi/linux/input.h>
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
#include <linux/aio.h>
#endif
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h> /* fatal_signal_pending */
#else
#include <linux/sched.h> /* fatal_signal_pending */
#endif

#include "allowlist.h"
#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#include "kernel_compat.h"
#include "selinux/selinux.h"

// we dont hhave a way to wait for "on post-fs-data"
// but we can check if /data/adb/ksud file exists
// if /data/adb/ksud exists, means this is "post-fs-data"

static const char SHELLSCRIPT_TEST[] =
	"#!/system/bin/sh\n"
	"while [ ! -f /data/adb/ksud ]; do sleep 1; done\n"
	"/data/adb/ksud post-fs-data\n"
	"if [ \"$(getprop ro.crypto.state)\" = \"unencrypted\" ]; then\n"
	"    /data/adb/ksud services\n"
	"else\n"
	"    until [ \"$(getprop vold.decrypt)\" = \"trigger_restart_framework\" ]; do sleep 1; done\n"
	"    /data/adb/ksud services\n"
	"fi\n"
	"until [ \"$(getprop sys.boot_completed)\" = \"1\" ]; do sleep 1; done\n"
	"/data/adb/ksud boot-completed\n";

// remember to unlink me once all tests are ok

static void stop_vfs_read_hook();
static void stop_execve_hook();
static void stop_input_hook();

bool ksu_vfs_read_hook __read_mostly = true;
bool ksu_execveat_hook __read_mostly = true;
bool ksu_input_hook __read_mostly = true;

u32 ksu_devpts_sid;

void on_post_fs_data(void)
{
	static bool done = false;
	if (done) {
		pr_info("on_post_fs_data already done\n");
		return;
	}
	done = true;
	pr_info("on_post_fs_data!\n");
	ksu_load_allow_list();
	// sanity check, this may influence the performance
	stop_input_hook();

	ksu_devpts_sid = ksu_get_devpts_sid();
	pr_info("devpts sid: %d\n", ksu_devpts_sid);
}

// since _ksud handler only uses argv and envp for comparisons
// this can probably work
// adapted from ksu_handle_execveat_ksud
static int ksu_handle_bprm_ksud(const char *filename, const char *argv1, const char *envp, size_t envp_len)
{
	static const char app_process[] = "/system/bin/app_process";
	static bool first_app_process = true;

	/* This applies to versions Android 10+ */
	static const char system_bin_init[] = "/system/bin/init";
	/* This applies to versions between Android 6 ~ 9  */
	static const char old_system_init[] = "/init";
	static bool init_second_stage_executed = false;

	// return early when disabled
	if (!ksu_execveat_hook)
		return 0;

	if (!filename)
		return 0;


	// debug! remove me!
	pr_info("%s: filename: %s argv1: %s envp_len: %zu\n", __func__, filename, argv1, envp_len);

	if (init_second_stage_executed)
		goto first_app_process;

	// /system/bin/init with argv1
	if (!init_second_stage_executed 
		&& (!memcmp(filename, system_bin_init, sizeof(system_bin_init) - 1))) {
		if (argv1 && !strcmp(argv1, "second_stage")) {
			pr_info("%s: /system/bin/init second_stage executed\n", __func__);
			apply_kernelsu_rules();
			init_second_stage_executed = true;
			ksu_android_ns_fs_check();
		}
	}

	// /init with argv1
	if (!init_second_stage_executed 
		&& (!memcmp(filename, old_system_init, sizeof(old_system_init) - 1))) {
		if (argv1 && !strcmp(argv1, "--second-stage")) {
			pr_info("%s: /init --second-stage executed\n", __func__);
			apply_kernelsu_rules();
			init_second_stage_executed = true;
			ksu_android_ns_fs_check();
		}
	}

	// /init without argv1/useless-argv1 but usable envp
	// untested! TODO: test and debug me!
	if (!init_second_stage_executed && (!memcmp(filename, old_system_init, sizeof(old_system_init) - 1))) {
		
		// we hunt for "INIT_SECOND_STAGE"
		const char *envp_n = envp;
		unsigned int envc = 1;
		do {
			if (strstarts(envp_n, "INIT_SECOND_STAGE"))
				break;
			envp_n += strlen(envp_n) + 1;
			envc++;
		} while (envp_n < envp + envp_len);
		pr_info("%s: envp[%d]: %s\n", __func__, envc, envp_n);
		
		if (!strcmp(envp_n, "INIT_SECOND_STAGE=1")
			|| !strcmp(envp_n, "INIT_SECOND_STAGE=true") ) {
			pr_info("%s: /init +envp: INIT_SECOND_STAGE executed\n", __func__);
			apply_kernelsu_rules();
			init_second_stage_executed = true;
			ksu_android_ns_fs_check();
		}
	}

first_app_process:
	if (first_app_process && !memcmp(filename, app_process, sizeof(app_process) - 1)) {
		first_app_process = false;
		pr_info("%s: exec app_process, /data prepared, second_stage: %d\n", __func__, init_second_stage_executed);
		on_post_fs_data();
		stop_execve_hook();
	}

	return 0;
}

int ksu_handle_pre_ksud(const char *filename)
{
	if (likely(!ksu_execveat_hook))
		return 0;

	// not /system/bin/init, not /init, not /system/bin/app_process (64/32 thingy)
	// return 0;
	if (likely(strcmp(filename, "/system/bin/init") && strcmp(filename, "/init")
		&& !strstarts(filename, "/system/bin/app_process") ))
		return 0;

	if (!current || !current->mm)
		return 0;

	// https://elixir.bootlin.com/linux/v4.14.1/source/include/linux/mm_types.h#L429
	// unsigned long arg_start, arg_end, env_start, env_end;
	unsigned long arg_start = current->mm->arg_start;
	unsigned long arg_end = current->mm->arg_end;
	unsigned long env_start = current->mm->env_start;
	unsigned long env_end = current->mm->env_end;

	size_t arg_len = arg_end - arg_start;
	size_t envp_len = env_end - env_start;

	if (arg_len <= 0 || envp_len <= 0) // this wont make sense, filter it
		return 0;

	#define ARGV_MAX 32  // this is enough for argv1
	#define ENVP_MAX 256  // this is enough for INIT_SECOND_STAGE
	char args[ARGV_MAX];
	size_t argv_copy_len = (arg_len > ARGV_MAX) ? ARGV_MAX : arg_len;
	char envp[ENVP_MAX];
	size_t envp_copy_len = (envp_len > ENVP_MAX) ? ENVP_MAX : envp_len;

	// we cant use strncpy on here, else it will truncate once it sees \0
	if (ksu_copy_from_user_retry(args, (void __user *)arg_start, argv_copy_len))
		return 0;

	if (ksu_copy_from_user_retry(envp, (void __user *)env_start, envp_copy_len))
		return 0;

	args[ARGV_MAX - 1] = '\0';
	envp[ENVP_MAX - 1] = '\0';

#ifdef CONFIG_KSU_DEBUG
	char *envp_n = envp;
	unsigned int envc = 1;
	do {
		pr_info("%s: envp[%d]: %s\n", __func__, envc, envp_n);
		envp_n += strlen(envp_n) + 1;
		envc++;
	} while (envp_n < envp + envp_copy_len);
#endif

	// we only need argv1 !
	// abuse strlen here since it only gets length up to \0
	char *argv1 = args + strlen(args) + 1;
	if (argv1 >= args + argv_copy_len) // out of bounds!
		argv1 = "";

	return ksu_handle_bprm_ksud(filename, argv1, envp, envp_copy_len);
}
// credits to execprog
// Copyright (c) 2019 Park Ju Hyung(arter97)
// https://github.com/arter97/android_kernel_nothing_sm8475/commit/9fec4068bb0b7f451c1b8ee28b1423eb0d73fdb3

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <linux/umh.h> 
#else
#include <linux/kmod.h> 
#endif
static int ksu_tiny_execprog_write(const char *filename, unsigned char *data, int length) {
	struct file *fp;
	int ret = 0;
	loff_t pos = 0;

	if (!filename || !data || length <= 0)
		return -1;

	fp = ksu_filp_open_compat(filename, O_RDWR | O_CREAT | O_TRUNC, 0755);
	if (IS_ERR(fp))
		return -1;

	while (pos < length) {
		size_t diff = length - pos;
		ret = ksu_kernel_write_compat(fp, data + pos, diff > 4096 ? 4096 : diff, &pos);
		pos += ret;
	}

	filp_close(fp, NULL);
	vfree(data); // TODO: maybe sys_sync? vfs_sync?

	pr_info("%s: wrote: %s (%d bytes)\n", __func__, filename, length);
	return 0;
}

#include <linux/kthread.h>
#include <linux/sched.h>
static struct task_struct *execprog_thread;

static int ksu_tiny_execprog_exec(void *data)
{
	// workaround for -ENOENT
	// just like how original execprog did it
	static unsigned int tries = 0;

	pr_info("execprog: executing /dev/ksud.sh\n");
	char *args[] = {"/system/bin/sh", "/dev/ksud.sh", NULL};

loop_start:
	rcu_barrier();
	int umh_ret = call_usermodehelper(args[0], args, NULL, UMH_WAIT_EXEC);
	pr_info("%s: umh returned %d\n", __func__, umh_ret);
	if (umh_ret < 0 && tries < 50 ) {
		pr_info("%s: retrying \n", __func__);
		msleep(100);
		tries++;
		goto loop_start;
	}
	else
		return 0;
	
}

static void ksu_tiny_execprog_thread()
{
	execprog_thread = kthread_run(ksu_tiny_execprog_exec, NULL, "execprog");
	if (IS_ERR(execprog_thread)) {
		execprog_thread = NULL;
		return;
	}
}

void ksu_exec_bootscript(struct file *file, const struct cred *cred)
{
	if (!ksu_vfs_read_hook)
		return;

	if (strcmp(current->comm, "init")) {
		// we are only interest in `init` process
		return;
	}

	const char *short_name = file->f_path.dentry->d_name.name;
	if (strcmp(short_name, "atrace.rc"))
		return; 

	char buf[384];

	char *path = d_path(&file->f_path, buf, sizeof(buf));
	if (!(path && path != buf)) 
		return;

	if (strcmp(path, "/system/etc/init/atrace.rc"))
		return;

	//static bool rc_inserted = false;
	//if (rc_inserted) {
	//	stop_vfs_read_hook();
	//	return;
	//}

	pr_info("ksu_file_open: matched target path: %s opened by: %s\n", path, current->comm);

	if (ksu_tiny_execprog_write("/dev/ksud.sh", (unsigned char *)SHELLSCRIPT_TEST, strlen(SHELLSCRIPT_TEST))) {
		pr_err("%s: failed writing ksud.sh\n", __func__);
		return;
	}

	ksu_tiny_execprog_thread();

	// rc_inserted = true;
	return;
}

int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr,
			size_t *count_ptr)
{
	return 0;
}

static unsigned int volumedown_pressed_count = 0;

static bool is_volumedown_enough(unsigned int count)
{
	return count >= 3;
}

int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code,
				  int *value)
{
	if (!ksu_input_hook) {
		return 0;
	}

	if (*type == EV_KEY && *code == KEY_VOLUMEDOWN) {
		int val = *value;
		pr_info("KEY_VOLUMEDOWN val: %d\n", val);
		if (val) {
			// key pressed, count it
			volumedown_pressed_count += 1;
			if (is_volumedown_enough(volumedown_pressed_count)) {
				stop_input_hook();
			}
		}
	}

	return 0;
}

bool ksu_is_safe_mode()
{
	static bool safe_mode = false;
	if (safe_mode) {
		// don't need to check again, userspace may call multiple times
		return true;
	}

	// stop hook first!
	stop_input_hook();

	pr_info("volumedown_pressed_count: %d\n", volumedown_pressed_count);
	if (is_volumedown_enough(volumedown_pressed_count)) {
		// pressed over 3 times
		pr_info("KEY_VOLUMEDOWN pressed max times, safe mode detected!\n");
		safe_mode = true;
		return true;
	}

	return false;
}

__maybe_unused int ksu_handle_execve_ksud(const char __user *filename_user,
			const char __user *const __user *__argv)
{
	return 0;
}

#if defined(CONFIG_COMPAT)
__maybe_unused int ksu_handle_compat_execve_ksud(const char __user *filename_user,
			const compat_uptr_t __user *__argv)
{
	return 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#include "objsec.h" // task_security_struct
bool is_ksu_transition(const struct task_security_struct *old_tsec,
			const struct task_security_struct *new_tsec)
{
	static u32 ksu_sid;
	char *secdata;
	u32 seclen;
	bool allowed = false;

	if (!ksu_sid)
		security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &ksu_sid);

	if (security_secid_to_secctx(old_tsec->sid, &secdata, &seclen))
		return false;

	allowed = (!strcmp("u:r:init:s0", secdata) && new_tsec->sid == ksu_sid);
	security_release_secctx(secdata, seclen);
	
	return allowed;
}
#endif

static void stop_vfs_read_hook()
{
	ksu_vfs_read_hook = false;
	pr_info("stop vfs_read_hook\n");
}

static void stop_execve_hook()
{
	ksu_execveat_hook = false;
	pr_info("stop execve_hook\n");
}

static void stop_input_hook()
{
	if (!ksu_input_hook) { return; }
	ksu_input_hook = false;
	pr_info("stop input_hook\n");
}

