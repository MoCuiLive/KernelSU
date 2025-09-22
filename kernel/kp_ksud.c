#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/binfmts.h>
#include <linux/kthread.h>
#include <linux/sched.h>

#include "arch.h"
#include "klog.h"
#include "ksud.h"

static struct task_struct *unregister_thread;
extern volatile bool ksu_input_hook __read_mostly;

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

static int unregister_kprobe_function(void *data)
{
	pr_info("kprobe_unregister: thread started, ksu_input_hook: %d\n", ksu_input_hook);

loop_start:
	smp_rmb();
	if (ksu_input_hook) {
		msleep(500);
		goto loop_start;
	}

	pr_info("kprobe_unregister: ksu_input_hook: %d, unregistering kprobes...\n", ksu_input_hook);
	unregister_kprobe(&bprm_check_kp);
	unregister_kprobe(&vfs_read_kp);
	unregister_kprobe(&input_event_kp);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)	
	unregister_kprobe(&key_permission_kp);
#endif
	return 0;
}

static void unregister_kprobe_thread()
{
	unregister_thread = kthread_run(unregister_kprobe_function, NULL, "kprobe_unregister");
	if (IS_ERR(unregister_thread)) {
		unregister_thread = NULL;
		return;
	}
}

void kp_ksud_init()
{
	int ret;

	ret = register_kprobe(&bprm_check_kp);
	pr_info("%s: bprm_check_kp: %d\n", __func__, ret);

	ret = register_kprobe(&vfs_read_kp);
	pr_info("%s: vfs_read_kp: %d\n", __func__, ret);

	ret = register_kprobe(&input_event_kp);
	pr_info("%s: input_event_kp: %d\n", __func__, ret);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
	ret = register_kprobe(&key_permission_kp);
	pr_info("%s: key_permission_kp: %d\n", __func__, ret);
#endif

	unregister_kprobe_thread();
}
