#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
#include <linux/input-event-codes.h>
#else
#include <uapi/linux/input.h>
#endif
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <linux/binfmts.h>

#include "arch.h"
#include "klog.h"
#include "ksud.h"

// bprm
static void kp_stop_bprm_check_hook();
static struct work_struct stop_bprm_check_work;
extern bool ksu_execveat_hook __read_mostly;
extern int ksu_bprm_check(struct linux_binprm *bprm);

static int bprm_check_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct linux_binprm *bprm_local = (struct linux_binprm *)PT_REGS_PARM1(regs);

	if (!ksu_execveat_hook) {
		kp_stop_bprm_check_hook();
		return 0;
	}

	return ksu_bprm_check(bprm_local);
};

static struct kprobe bprm_check_kp = {
	.symbol_name = "security_bprm_check",
	.pre_handler = bprm_check_handler_pre,
};

static void do_stop_bprm_check_hook(struct work_struct *work)
{
	unregister_kprobe(&bprm_check_kp);
}

static void kp_stop_bprm_check_hook()
{
	bool ret = schedule_work(&stop_bprm_check_work);
	pr_info("unregister security_bprm_check kprobe: %d!\n", ret);
}

// vfs_read
static void kp_stop_vfs_read_hook();
static struct work_struct stop_vfs_read_work;
extern bool ksu_vfs_read_hook __read_mostly;
extern int ksu_handle_vfs_read(struct file **file_ptr, char __user **buf_ptr,
			size_t *count_ptr, loff_t **pos);

static int vfs_read_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file **file_ptr = (struct file **)&PT_REGS_PARM1(regs);
	char __user **buf_ptr = (char **)&PT_REGS_PARM2(regs);
	size_t *count_ptr = (size_t *)&PT_REGS_PARM3(regs);
	loff_t **pos_ptr = (loff_t **)&PT_REGS_CCALL_PARM4(regs);

	if (!ksu_vfs_read_hook) {
		kp_stop_vfs_read_hook();
		return 0;
	}

	return ksu_handle_vfs_read(file_ptr, buf_ptr, count_ptr, pos_ptr);
}

static struct kprobe vfs_read_kp = {
	.symbol_name = "vfs_read",
	.pre_handler = vfs_read_handler_pre,
};

static void do_stop_vfs_read_hook(struct work_struct *work)
{
	unregister_kprobe(&vfs_read_kp);
}

static void kp_stop_vfs_read_hook()
{
	bool ret = schedule_work(&stop_vfs_read_work);
	pr_info("unregister vfs_read kprobe: %d!\n", ret);
}

// input_event
static void kp_stop_input_hook();
static struct work_struct stop_input_hook_work;
extern bool ksu_input_hook __read_mostly;
extern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value);

static int input_handle_event_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	unsigned int *type = (unsigned int *)&PT_REGS_PARM2(regs);
	unsigned int *code = (unsigned int *)&PT_REGS_PARM3(regs);
	int *value = (int *)&PT_REGS_CCALL_PARM4(regs);

	if (!ksu_input_hook) {
		kp_stop_input_hook();
		return 0;
	}
	return ksu_handle_input_handle_event(type, code, value);

};

static struct kprobe input_event_kp = {
	.symbol_name = "input_event",
	.pre_handler = input_handle_event_handler_pre,
};

static void do_stop_input_hook(struct work_struct *work)
{
	unregister_kprobe(&input_event_kp);
}

static void kp_stop_input_hook()
{
	bool ret = schedule_work(&stop_input_hook_work);
	pr_info("unregister input_event kprobe: %d!\n", ret);
}

// key_permission
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
static void kp_stop_key_permission_hook();
static struct work_struct stop_key_permission_work;
extern int ksu_key_permission(key_ref_t key_ref, const struct cred *cred,
			      unsigned perm);

static int key_permission_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	key_ref_t key_ref_local = (key_ref_t)PT_REGS_PARM1(regs);
	const struct cred *cred_local = (const struct cred *)PT_REGS_PARM2(regs);
	unsigned int perm_local = (unsigned int)PT_REGS_PARM3(regs);

	// just unreg this hook once vfs_read hook is done
	// could be done earlier but I can't be bothered
	if (!ksu_vfs_read_hook) {
		kp_stop_key_permission_hook();
		return 0;
	}

	return ksu_key_permission(key_ref_local, cred_local, perm_local);

};

static struct kprobe key_permission_kp = {
	.symbol_name = "security_key_permission",
	.pre_handler = key_permission_handler_pre,
};

static void do_stop_key_permission_hook(struct work_struct *work)
{
	unregister_kprobe(&key_permission_kp);
}

static void kp_stop_key_permission_hook()
{
	bool ret = schedule_work(&stop_key_permission_work);
	pr_info("unregister key_permission kprobe: %d!\n", ret);
}
#endif

void kp_ksud_init()
{
	int ret;

	ret = register_kprobe(&bprm_check_kp);
	pr_info("%s: bprm_check_kp: %d\n", __func__, ret);
	INIT_WORK(&stop_bprm_check_work, do_stop_bprm_check_hook);

	ret = register_kprobe(&vfs_read_kp);
	pr_info("%s: vfs_read_kp: %d\n", __func__, ret);
	INIT_WORK(&stop_vfs_read_work, do_stop_vfs_read_hook);;

	ret = register_kprobe(&input_event_kp);
	pr_info("%s: input_event_kp: %d\n", __func__, ret);
	INIT_WORK(&stop_input_hook_work, do_stop_input_hook);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
	ret = register_kprobe(&key_permission_kp);
	pr_info("%s: key_permission_kp: %d\n", __func__, ret);
	INIT_WORK(&stop_key_permission_work, do_stop_key_permission_hook);
#endif
}
