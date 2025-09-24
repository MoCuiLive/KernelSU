#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/binfmts.h>
#include <linux/kthread.h>
#include <linux/sched.h>

static struct task_struct *unregister_thread;

#include "arch.h"
#include "klog.h"
#include "ksud.h"
#include "kernel_compat.h"

#if 0
static int sys_execve_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	const char __user *filename_user = (const char __user *)PT_REGS_PARM1(real_regs);
	const char __user *const __user *__argv = (const char __user *const __user *)PT_REGS_PARM2(real_regs);

	char path[32];

	if (!filename_user)
		return 0;

	if (ksu_copy_from_user_retry(path, filename_user, sizeof(path)))
		return 0;

	path[sizeof(path) - 1] = '\0';

	// not /system/bin/init, not /init, not /system/bin/app_process (64/32 thingy)
	// we dont care !!
	if (likely(strcmp(path, "/system/bin/init") && strcmp(path, "/init")
		&& !strstarts(path, "/system/bin/app_process") ))
		return 0;

// argv stage
	char argv1[32] = {0};
	// memzero_explicit(argv1, 32);
	if (__argv) {
		const char __user *arg1_user = NULL;
		// grab argv[1] pointer
		// this looks like
		/* 
		 * 0x1000 ./program << this is __argv
		 * 0x1001 -o 
		 * 0x1002 arg
		*/
		if (ksu_copy_from_user_retry(&arg1_user, __argv + 1, sizeof(arg1_user)))
			goto submit; // copy argv[1] pointer fail, probably no argv1 !!

		if (arg1_user)
			ksu_copy_from_user_retry(argv1, arg1_user, sizeof(argv1));
	}

submit:
	argv1[sizeof(argv1) - 1] = '\0';
	// pr_info("%s: filename: %s argv[1]:%s\n", __func__, path, argv1);

	return ksu_handle_bprm_ksud(path, argv1, NULL, NULL);
}


static struct kprobe execve_kp = {
	.symbol_name = SYS_EXECVE_SYMBOL,
	.pre_handler = sys_execve_handler_pre,
};
#endif

// bprm
static void kp_stop_bprm_check_hook();
extern int ksu_bprm_check(struct linux_binprm *bprm);

static int bprm_check_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct linux_binprm *bprm_local = (struct linux_binprm *)PT_REGS_PARM1(regs);

	return ksu_bprm_check(bprm_local);
};

// yes, we're hooking the LSM via kprobe. fite me.
static struct kprobe bprm_check_kp = {
	.symbol_name = "security_bprm_check",
	.pre_handler = bprm_check_handler_pre,
};

// vfs_read
static void kp_stop_vfs_read_hook();
extern int ksu_handle_vfs_read(struct file **file_ptr, char __user **buf_ptr,
			size_t *count_ptr, loff_t **pos);

static int vfs_read_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file **file_ptr = (struct file **)&PT_REGS_PARM1(regs);
	char __user **buf_ptr = (char **)&PT_REGS_PARM2(regs);
	size_t *count_ptr = (size_t *)&PT_REGS_PARM3(regs);
	loff_t **pos_ptr = (loff_t **)&PT_REGS_CCALL_PARM4(regs);

	return ksu_handle_vfs_read(file_ptr, buf_ptr, count_ptr, pos_ptr);
}

static struct kprobe vfs_read_kp = {
	.symbol_name = "vfs_read",
	.pre_handler = vfs_read_handler_pre,
};

// input_event
static void kp_stop_input_hook();
extern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value);

static int input_handle_event_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	unsigned int *type = (unsigned int *)&PT_REGS_PARM2(regs);
	unsigned int *code = (unsigned int *)&PT_REGS_PARM3(regs);
	int *value = (int *)&PT_REGS_CCALL_PARM4(regs);

	return ksu_handle_input_handle_event(type, code, value);

};

static struct kprobe input_event_kp = {
	.symbol_name = "input_event",
	.pre_handler = input_handle_event_handler_pre,
};

// key_permission
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
static void kp_stop_key_permission_hook();
extern int ksu_key_permission(key_ref_t key_ref, const struct cred *cred,
			      unsigned perm);

static int key_permission_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	key_ref_t key_ref_local = (key_ref_t)PT_REGS_PARM1(regs);
	const struct cred *cred_local = (const struct cred *)PT_REGS_PARM2(regs);
	unsigned int perm_local = (unsigned int)PT_REGS_PARM3(regs);

	return ksu_key_permission(key_ref_local, cred_local, perm_local);

};

static struct kprobe key_permission_kp = {
	.symbol_name = "security_key_permission",
	.pre_handler = key_permission_handler_pre,
};
#endif // key_permission

// security_bounded_transition - https://github.com/tiann/KernelSU/pull/1704
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#include "avc_ss.h"
#include "selinux/selinux.h"
static int bounded_transition_handler_pre(struct kprobe *p, struct pt_regs *regs) {
	u32 *old_sid = (u32 *)&PT_REGS_PARM1(regs);
	u32 *new_sid = (u32 *)&PT_REGS_PARM2(regs);

	u32 init_sid, su_sid;
	int error;

	if (!ss_initialized)
		return 0;

	/* domain unchanged */
	if (*old_sid == *new_sid)
		return 0;

	const char *init_domain = "u:r:init:s0";
	const char *su_domain = "u:r:su:s0";

	error = security_secctx_to_secid(init_domain, strlen(init_domain), &init_sid);
	if (error) {
		pr_info("%s: cannot get sid of init context, err %d\n", __func__, error);
		return 0;
	}

	error = security_secctx_to_secid(su_domain, strlen(su_domain), &su_sid);
	if (error) {
		pr_info("%s: cannot get sid of su context, err %d\n", __func__, error);
		return 0;
	}

	if (*old_sid == init_sid && *new_sid == su_sid) {
		pr_info("%s: init to su transition found\n", __func__);
		*old_sid = *new_sid;  // make the original func return 0
	}

	return 0;
}

static struct kprobe bounded_transition_kp = {
	.symbol_name = "security_bounded_transition",
	.pre_handler = bounded_transition_handler_pre,
};
#endif // security_bounded_transition

static void unregister_kprobe_logged(struct kprobe *kp, const char *name)
{
	if (!kp->addr) {
		pr_info("unregister_kprobe: %s not registered in the first place\n");
		return;
	}

	unregister_kprobe(kp); // this fucking shit has no return code
	pr_info("unregister_kprobe: %s ??\n", name);
}

static int unregister_kprobe_function(void *data)
{
	pr_info("kprobe_unregister: unregistering kprobes...\n");


#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
	unregister_kprobe_logged(&key_permission_kp, "key_permission_kp");
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0) 
	unregister_kprobe_logged(&bounded_transition_kp, "bounded_transition_kp");
#endif
	unregister_kprobe_logged(&input_event_kp, "input_event_kp");
	unregister_kprobe_logged(&bprm_check_kp, "bprm_check_kp");
	unregister_kprobe_logged(&vfs_read_kp, "vfs_read_kp");
	
	return 0;
}

void unregister_kprobe_thread()
{
	unregister_thread = kthread_run(unregister_kprobe_function, NULL, "kprobe_unregister");
	if (IS_ERR(unregister_thread)) {
		unregister_thread = NULL;
		return;
	}
}

static void register_kprobe_safer(struct kprobe *kp, const char *name)
{
	int ret;

	preempt_disable();
	ret = register_kprobe(kp);
	preempt_enable();

	pr_info("register_kprobe: %s ret: %d\n", name, ret);

}

void kp_ksud_init()
{
	register_kprobe_safer(&vfs_read_kp, "vfs_read_kp");
	register_kprobe_safer(&input_event_kp, "input_event_kp");
	register_kprobe_safer(&bprm_check_kp, "bprm_check_kp");

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0) 
	register_kprobe_safer(&bounded_transition_kp, "bounded_transition_kp");
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
	register_kprobe_safer(&key_permission_kp, "key_permission_kp");
#endif

}
