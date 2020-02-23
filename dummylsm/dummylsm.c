// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Sample LSM based on selinux
 *
 *  This file contains the sample hook function implementations.
 *
 *  Authors:  Rahul Jadhav, <nyrahul@gmail.com>
 *
 *  Copyright (C) 2020 XXXXX Technologies
 */

#include <linux/init.h>
#include <linux/kd.h>
#include <linux/kernel.h>
#include <linux/tracehook.h>
#include <linux/errno.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/lsm_hooks.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tty.h>
#include <net/icmp.h>
#include <net/ip.h>		/* for local_port_range[] */
#include <net/tcp.h>		/* struct or_callable used in sock_rcv_skb */
#include <net/inet_connection_sock.h>
#include <net/net_namespace.h>
#include <net/netlabel.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>	/* for network interface checks */
#include <net/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/dccp.h>
#include <linux/sctp.h>
#include <net/sctp/structs.h>
#include <linux/quota.h>
#include <linux/un.h>		/* for Unix socket types */
#include <net/af_unix.h>	/* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/posix-timers.h>
#include <linux/syslog.h>
#include <linux/user_namespace.h>
#include <linux/export.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include <linux/bpf.h>
#include <linux/kernfs.h>
#include <linux/stringhash.h>	/* for hashlen_string() */
#include <uapi/linux/mount.h>

/* SECMARK reference count */
static atomic_t dummylsm_secmark_refcount = ATOMIC_INIT(0);

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
static int dummylsm_enforcing_boot;

static int __init enforcing_setup(char *str)
{
	unsigned long enforcing;
	if (!kstrtoul(str, 0, &enforcing))
		dummylsm_enforcing_boot = enforcing ? 1 : 0;
	return 1;
}
__setup("enforcing=", enforcing_setup);
#else
#define dummylsm_enforcing_boot 1
#endif

int dummylsm_enabled __lsm_ro_after_init = 1;
#ifdef CONFIG_SECURITY_SELINUX_BOOTPARAM
static int __init dummylsm_enabled_setup(char *str)
{
	unsigned long enabled;
	if (!kstrtoul(str, 0, &enabled))
		dummylsm_enabled = enabled ? 1 : 0;
	return 1;
}
__setup("dummylsm=", dummylsm_enabled_setup);
#endif

static int dummylsm_netcache_avc_callback(u32 event)
{
	return 0;
}

static int dummylsm_lsm_notifier_avc_callback(u32 event)
{
	return 0;
}

static int inode_alloc_security(struct inode *inode)
{
	return 0;
}

static void inode_free_security(struct inode *inode)
{
}

static int file_alloc_security(struct file *file)
{
	return 0;
}

static void dummylsm_free_mnt_opts(void *mnt_opts)
{
}

#define SEL_MOUNT_FAIL_MSG "DummyLSM:  duplicate or incompatible mount options\n"

/*
 * Allow filesystems with binary mount data to explicitly set mount point
 * labeling information.
 */
static int dummylsm_set_mnt_opts(struct super_block *sb,
				void *mnt_opts,
				unsigned long kern_flags,
				unsigned long *set_kern_flags)
{
	return 0;
}

static int dummylsm_cmp_sb_context(const struct super_block *oldsb,
				    const struct super_block *newsb)
{
	return 0;
}

static int dummylsm_sb_clone_mnt_opts(const struct super_block *oldsb,
					struct super_block *newsb,
					unsigned long kern_flags,
					unsigned long *set_kern_flags)
{
	return 0;
}

static int dummylsm_add_mnt_opt(const char *option, const char *val, int len,
			       void **mnt_opts)
{
	return 0;
}

static int dummylsm_sb_show_options(struct seq_file *m, struct super_block *sb)
{
	return 0;
}

/* The inode's security attributes must be initialized before first use. */
static int inode_doinit_with_dentry(struct inode *inode, struct dentry *opt_dentry)
{
	return 0;
}

#if CAP_LAST_CAP > 63
#error Fix DummyLSM to handle capabilities > 63.
#endif

#ifdef CONFIG_BPF_SYSCALL
static int bpf_fd_pass(struct file *file, u32 sid);
#endif

static int dummylsm_binder_set_context_mgr(struct task_struct *mgr)
{
	return 0;
}

static int dummylsm_binder_transaction(struct task_struct *from,
				      struct task_struct *to)
{
	return 0;
}

static int dummylsm_binder_transfer_binder(struct task_struct *from,
					  struct task_struct *to)
{
	return 0;
}

static int dummylsm_binder_transfer_file(struct task_struct *from,
					struct task_struct *to,
					struct file *file)
{
	return 0;
}

static int dummylsm_ptrace_access_check(struct task_struct *child,
				     unsigned int mode)
{
    return 0;
}

static int dummylsm_ptrace_traceme(struct task_struct *parent)
{
	return 0;
}

static int dummylsm_capget(struct task_struct *target, kernel_cap_t *effective,
			  kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	return 0;
}

static int dummylsm_capset(struct cred *new, const struct cred *old,
			  const kernel_cap_t *effective,
			  const kernel_cap_t *inheritable,
			  const kernel_cap_t *permitted)
{
	return 0;
}

static int dummylsm_capable(const struct cred *cred, struct user_namespace *ns,
			   int cap, unsigned int opts)
{
	return 0;
}

static int dummylsm_quotactl(int cmds, int type, int id, struct super_block *sb)
{
	return 0;
}

static int dummylsm_quota_on(struct dentry *dentry)
{
	return 0;
}

static int dummylsm_syslog(int type)
{
	return 0;
}

static int dummylsm_vm_enough_memory(struct mm_struct *mm, long pages)
{
	return 0;
}

static int dummylsm_bprm_set_creds(struct linux_binprm *bprm)
{
	return 0;
}

/*
 * Prepare a process for imminent new credential changes due to exec
 */
static void dummylsm_bprm_committing_creds(struct linux_binprm *bprm)
{
}

/*
 * Clean up the process immediately after the installation of new credentials
 * due to exec
 */
static void dummylsm_bprm_committed_creds(struct linux_binprm *bprm)
{
}

/* superblock security operations */

static int dummylsm_sb_alloc_security(struct super_block *sb)
{
	return 0;
}

static void dummylsm_sb_free_security(struct super_block *sb)
{
}

static int dummylsm_sb_eat_lsm_opts(char *options, void **mnt_opts)
{
	return 0;
}

static int dummylsm_sb_remount(struct super_block *sb, void *mnt_opts)
{
	return 0;
}

static int dummylsm_sb_kern_mount(struct super_block *sb)
{
	return 0;
}

static int dummylsm_sb_statfs(struct dentry *dentry)
{
	return 0;
}

static int dummylsm_mount(const char *dev_name,
			 const struct path *path,
			 const char *type,
			 unsigned long flags,
			 void *data)
{
    return 0;
}

static int dummylsm_umount(struct vfsmount *mnt, int flags)
{
	return 0;
}

static int dummylsm_fs_context_dup(struct fs_context *fc,
				  struct fs_context *src_fc)
{
	return 0;
}

static int dummylsm_fs_context_parse_param(struct fs_context *fc,
					  struct fs_parameter *param)
{
	return 0;
}

/* inode security operations */

static int dummylsm_inode_alloc_security(struct inode *inode)
{
	return 0;
}

static void dummylsm_inode_free_security(struct inode *inode)
{
}

static int dummylsm_dentry_init_security(struct dentry *dentry, int mode,
					const struct qstr *name, void **ctx,
					u32 *ctxlen)
{
	return 0;
}

static int dummylsm_dentry_create_files_as(struct dentry *dentry, int mode,
					  struct qstr *name,
					  const struct cred *old,
					  struct cred *new)
{
	return 0;
}

static int dummylsm_inode_init_security(struct inode *inode, struct inode *dir,
				       const struct qstr *qstr,
				       const char **name,
				       void **value, size_t *len)
{
	return 0;
}

static int dummylsm_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return 0;
}

static int dummylsm_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	return 0;
}

static int dummylsm_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	return 0;
}

static int dummylsm_inode_symlink(struct inode *dir, struct dentry *dentry, const char *name)
{
	return 0;
}

static int dummylsm_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mask)
{
	return 0;
}

static int dummylsm_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	return 0;
}

static int dummylsm_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	return 0;
}

static int dummylsm_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
				struct inode *new_inode, struct dentry *new_dentry)
{
	return 0;
}

static int dummylsm_inode_readlink(struct dentry *dentry)
{
	return 0;
}

static int dummylsm_inode_follow_link(struct dentry *dentry, struct inode *inode,
				     bool rcu)
{
	return 0;
}

static noinline int audit_inode_permission(struct inode *inode,
					   u32 perms, u32 audited, u32 denied,
					   int result,
					   unsigned flags)
{
	return 0;
}

static int dummylsm_inode_permission(struct inode *inode, int mask)
{
    return 0;
}

static int dummylsm_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
	return 0;
}

static int dummylsm_inode_getattr(const struct path *path)
{
	return 0;
}

static int dummylsm_inode_setxattr(struct dentry *dentry, const char *name,
				  const void *value, size_t size, int flags)
{
	return 0;
}

static void dummylsm_inode_post_setxattr(struct dentry *dentry, const char *name,
					const void *value, size_t size,
					int flags)
{
}

static int dummylsm_inode_getxattr(struct dentry *dentry, const char *name)
{
	return 0;
}

static int dummylsm_inode_listxattr(struct dentry *dentry)
{
	return 0;
}

static int dummylsm_inode_removexattr(struct dentry *dentry, const char *name)
{
	return 0;
}

/*
 * Copy the inode security context value to the user.
 *
 * Permission check is handled by dummylsm_inode_getxattr hook.
 */
static int dummylsm_inode_getsecurity(struct inode *inode, const char *name, void **buffer, bool alloc)
{
	return 0;
}

static int dummylsm_inode_setsecurity(struct inode *inode, const char *name,
				     const void *value, size_t size, int flags)
{
	return 0;
}

static int dummylsm_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size)
{
	const int len = sizeof(XATTR_NAME_SELINUX);
	if (buffer && len <= buffer_size)
		memcpy(buffer, XATTR_NAME_SELINUX, len);
	return len;
}

static void dummylsm_inode_getsecid(struct inode *inode, u32 *secid)
{
}

static int dummylsm_inode_copy_up(struct dentry *src, struct cred **new)
{
	return 0;
}

static int dummylsm_inode_copy_up_xattr(const char *name)
{
	return -EOPNOTSUPP;
}

/* kernfs node operations */

static int dummylsm_kernfs_init_security(struct kernfs_node *kn_dir,
					struct kernfs_node *kn)
{
	return 0;
}


/* file security operations */

static int dummylsm_revalidate_file_permission(struct file *file, int mask)
{
	return 0;
}

static int dummylsm_file_permission(struct file *file, int mask)
{
	return 0;
}

static int dummylsm_file_alloc_security(struct file *file)
{
	return 0;
}

/*
 * Check whether a task has the ioctl permission and cmd
 * operation to an inode.
 */
static int ioctl_has_perm(const struct cred *cred, struct file *file,
		u32 requested, u16 cmd)
{
	return 0;
}

static int dummylsm_file_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	return 0;
}

static int default_noexec;

static int file_map_prot_check(struct file *file, unsigned long prot, int shared)
{
	return 0;
}

static int dummylsm_mmap_addr(unsigned long addr)
{
	return 0;
}

static int dummylsm_mmap_file(struct file *file, unsigned long reqprot,
			     unsigned long prot, unsigned long flags)
{
	return 0;
}

static int dummylsm_file_mprotect(struct vm_area_struct *vma,
				 unsigned long reqprot,
				 unsigned long prot)
{
	return 0;
}

static int dummylsm_file_lock(struct file *file, unsigned int cmd)
{
	return 0;
}

static int dummylsm_file_fcntl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	return 0;
}

static void dummylsm_file_set_fowner(struct file *file)
{
}

static int dummylsm_file_send_sigiotask(struct task_struct *tsk,
				       struct fown_struct *fown, int signum)
{
	return 0;
}

static int dummylsm_file_receive(struct file *file)
{
	return 0;
}

static int dummylsm_file_open(struct file *file)
{
	return 0;
}

/* task security operations */

static int dummylsm_task_alloc(struct task_struct *task,
			      unsigned long clone_flags)
{
	return 0;
}

static int dummylsm_cred_prepare(struct cred *new, const struct cred *old,
				gfp_t gfp)
{
	return 0;
}

static void dummylsm_cred_transfer(struct cred *new, const struct cred *old)
{
}

static void dummylsm_cred_getsecid(const struct cred *c, u32 *secid)
{
}

/*
 * set the security data for a kernel service
 * - all the creation contexts are set to unlabelled
 */
static int dummylsm_kernel_act_as(struct cred *new, u32 secid)
{
	return 0;
}

/*
 * set the file creation context in a security record to the same as the
 * objective context of the specified inode
 */
static int dummylsm_kernel_create_files_as(struct cred *new, struct inode *inode)
{
	return 0;
}

static int dummylsm_kernel_module_request(char *kmod_name)
{
	return 0;
}

static int dummylsm_kernel_module_from_file(struct file *file)
{
	return 0;
}

static int dummylsm_kernel_read_file(struct file *file,
				    enum kernel_read_file_id id)
{
	return 0;
}

static int dummylsm_kernel_load_data(enum kernel_load_data_id id)
{
	return 0;
}

static int dummylsm_task_setpgid(struct task_struct *p, pid_t pgid)
{
	return 0;
}

static int dummylsm_task_getpgid(struct task_struct *p)
{
	return 0;
}

static int dummylsm_task_getsid(struct task_struct *p)
{
	return 0;
}

static void dummylsm_task_getsecid(struct task_struct *p, u32 *secid)
{
}

static int dummylsm_task_setnice(struct task_struct *p, int nice)
{
	return 0;
}

static int dummylsm_task_setioprio(struct task_struct *p, int ioprio)
{
	return 0;
}

static int dummylsm_task_getioprio(struct task_struct *p)
{
	return 0;
}

static int dummylsm_task_prlimit(const struct cred *cred, const struct cred *tcred,
				unsigned int flags)
{
	return 0;
}

static int dummylsm_task_setrlimit(struct task_struct *p, unsigned int resource,
		struct rlimit *new_rlim)
{
	return 0;
}

static int dummylsm_task_setscheduler(struct task_struct *p)
{
	return 0;
}

static int dummylsm_task_getscheduler(struct task_struct *p)
{
	return 0;
}

static int dummylsm_task_movememory(struct task_struct *p)
{
	return 0;
}

static int dummylsm_task_kill(struct task_struct *p, struct kernel_siginfo *info,
				int sig, const struct cred *cred)
{
	return 0;
}

static void dummylsm_task_to_inode(struct task_struct *p,
				  struct inode *inode)
{
}

static int dummylsm_socket_create(int family, int type,
				 int protocol, int kern)
{
	return 0;
}

static int dummylsm_socket_post_create(struct socket *sock, int family,
				      int type, int protocol, int kern)
{
	return 0;
}

static int dummylsm_socket_socketpair(struct socket *socka,
				     struct socket *sockb)
{
	return 0;
}

/* Range of port numbers used to automatically bind.
   Need to determine whether we should perform a name_bind
   permission check between the socket and the port number. */

static int dummylsm_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
	return 0;
}

/* This supports connect(2) and SCTP connect services such as sctp_connectx(3)
 * and sctp_sendmsg(3) as described in Documentation/security/SCTP.rst
 */
static int dummylsm_socket_connect_helper(struct socket *sock,
					 struct sockaddr *address, int addrlen)
{
	return 0;
}

/* Supports connect(2), see comments in dummylsm_socket_connect_helper() */
static int dummylsm_socket_connect(struct socket *sock,
				  struct sockaddr *address, int addrlen)
{
    return 0;
}

static int dummylsm_socket_listen(struct socket *sock, int backlog)
{
	return 0;
}

static int dummylsm_socket_accept(struct socket *sock, struct socket *newsock)
{
	return 0;
}

static int dummylsm_socket_sendmsg(struct socket *sock, struct msghdr *msg,
				  int size)
{
	return 0;
}

static int dummylsm_socket_recvmsg(struct socket *sock, struct msghdr *msg,
				  int size, int flags)
{
	return 0;
}

static int dummylsm_socket_getsockname(struct socket *sock)
{
	return 0;
}

static int dummylsm_socket_getpeername(struct socket *sock)
{
	return 0;
}

static int dummylsm_socket_setsockopt(struct socket *sock, int level, int optname)
{
	return 0;
}

static int dummylsm_socket_getsockopt(struct socket *sock, int level,
				     int optname)
{
	return 0;
}

static int dummylsm_socket_shutdown(struct socket *sock, int how)
{
	return 0;
}

static int dummylsm_socket_unix_stream_connect(struct sock *sock,
					      struct sock *other,
					      struct sock *newsk)
{
	return 0;
}

static int dummylsm_socket_unix_may_send(struct socket *sock,
					struct socket *other)
{
	return 0;
}

static int dummylsm_inet_sys_rcv_skb(struct net *ns, int ifindex,
				    char *addrp, u16 family, u32 peer_sid,
				    struct common_audit_data *ad)
{
	return 0;
}

static int dummylsm_sock_rcv_skb_compat(struct sock *sk, struct sk_buff *skb,
				       u16 family)
{
	return 0;
}

static int dummylsm_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

static int dummylsm_socket_getpeersec_stream(struct socket *sock, char __user *optval,
					    int __user *optlen, unsigned len)
{
	return 0;
}

static int dummylsm_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb, u32 *secid)
{
	return 0;
}

static int dummylsm_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
	return 0;
}

static void dummylsm_sk_free_security(struct sock *sk)
{
}

static void dummylsm_sk_clone_security(const struct sock *sk, struct sock *newsk)
{
}

static void dummylsm_sk_getsecid(struct sock *sk, u32 *secid)
{
}

static void dummylsm_sock_graft(struct sock *sk, struct socket *parent)
{
}

/* Called whenever SCTP receives an INIT chunk. This happens when an incoming
 * connect(2), sctp_connectx(3) or sctp_sendmsg(3) (with no association
 * already present).
 */
static int dummylsm_sctp_assoc_request(struct sctp_endpoint *ep,
				      struct sk_buff *skb)
{
	return 0;
}

/* Check if sctp IPv4/IPv6 addresses are valid for binding or connecting
 * based on their @optname.
 */
static int dummylsm_sctp_bind_connect(struct sock *sk, int optname,
				     struct sockaddr *address,
				     int addrlen)
{
	return 0;
}

/* Called whenever a new socket is created by accept(2) or sctp_peeloff(3). */
static void dummylsm_sctp_sk_clone(struct sctp_endpoint *ep, struct sock *sk,
				  struct sock *newsk)
{
}

static int dummylsm_inet_conn_request(struct sock *sk, struct sk_buff *skb,
				     struct request_sock *req)
{
	return 0;
}

static void dummylsm_inet_csk_clone(struct sock *newsk,
				   const struct request_sock *req)
{
}

static void dummylsm_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
}

static int dummylsm_secmark_relabel_packet(u32 sid)
{
	return 0;
}

static void dummylsm_secmark_refcount_inc(void)
{
}

static void dummylsm_secmark_refcount_dec(void)
{
}

static void dummylsm_req_classify_flow(const struct request_sock *req,
				      struct flowi *fl)
{
	fl->flowi_secid = req->secid;
}

static int dummylsm_tun_dev_alloc_security(void **security)
{
	return 0;
}

static void dummylsm_tun_dev_free_security(void *security)
{
}

static int dummylsm_tun_dev_create(void)
{
	return 0;
}

static int dummylsm_tun_dev_attach_queue(void *security)
{
	return 0;
}

static int dummylsm_tun_dev_attach(struct sock *sk, void *security)
{
	return 0;
}

static int dummylsm_tun_dev_open(void *security)
{
	return 0;
}

static int dummylsm_nlmsg_perm(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

static int dummylsm_netlink_send(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

static int msg_msg_alloc_security(struct msg_msg *msg)
{
	return 0;
}

static int ipc_has_perm(struct kern_ipc_perm *ipc_perms,
			u32 perms)
{
	return 0;
}

static int dummylsm_msg_msg_alloc_security(struct msg_msg *msg)
{
	return 0;
}

/* message queue security operations */
static int dummylsm_msg_queue_alloc_security(struct kern_ipc_perm *msq)
{
	return 0;
}

static int dummylsm_msg_queue_associate(struct kern_ipc_perm *msq, int msqflg)
{
	return 0;
}

static int dummylsm_msg_queue_msgctl(struct kern_ipc_perm *msq, int cmd)
{
	return 0;
}

static int dummylsm_msg_queue_msgsnd(struct kern_ipc_perm *msq, struct msg_msg *msg, int msqflg)
{
	return 0;
}

static int dummylsm_msg_queue_msgrcv(struct kern_ipc_perm *msq, struct msg_msg *msg,
				    struct task_struct *target,
				    long type, int mode)
{
	return 0;
}

/* Shared Memory security operations */
static int dummylsm_shm_alloc_security(struct kern_ipc_perm *shp)
{
	return 0;
}

static int dummylsm_shm_associate(struct kern_ipc_perm *shp, int shmflg)
{
	return 0;
}

/* Note, at this point, shp is locked down */
static int dummylsm_shm_shmctl(struct kern_ipc_perm *shp, int cmd)
{
	return 0;
}

static int dummylsm_shm_shmat(struct kern_ipc_perm *shp,
			     char __user *shmaddr, int shmflg)
{
	return 0;
}

/* Semaphore security operations */
static int dummylsm_sem_alloc_security(struct kern_ipc_perm *sma)
{
	return 0;
}

static int dummylsm_sem_associate(struct kern_ipc_perm *sma, int semflg)
{
	return 0;
}

/* Note, at this point, sma is locked down */
static int dummylsm_sem_semctl(struct kern_ipc_perm *sma, int cmd)
{
	return 0;
}

static int dummylsm_sem_semop(struct kern_ipc_perm *sma,
			     struct sembuf *sops, unsigned nsops, int alter)
{
	return 0;
}

static int dummylsm_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
	return 0;
}

static void dummylsm_ipc_getsecid(struct kern_ipc_perm *ipcp, u32 *secid)
{
}

static void dummylsm_d_instantiate(struct dentry *dentry, struct inode *inode)
{
}

static int dummylsm_getprocattr(struct task_struct *p,
			       char *name, char **value)
{
	return 0;
}

static int dummylsm_setprocattr(const char *name, void *value, size_t size)
{
	return 0;
}

static int dummylsm_ismaclabel(const char *name)
{
	return (strcmp(name, XATTR_SELINUX_SUFFIX) == 0);
}

static int dummylsm_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
	return 0;
}

static int dummylsm_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
{
	return 0;
}

static void dummylsm_release_secctx(char *secdata, u32 seclen)
{
}

static void dummylsm_inode_invalidate_secctx(struct inode *inode)
{
}

/*
 *	called with inode->i_mutex locked
 */
static int dummylsm_inode_notifysecctx(struct inode *inode, void *ctx, u32 ctxlen)
{
	return 0;
}

/*
 *	called with inode->i_mutex locked
 */
static int dummylsm_inode_setsecctx(struct dentry *dentry, void *ctx, u32 ctxlen)
{
	return 0;
}

static int dummylsm_inode_getsecctx(struct inode *inode, void **ctx, u32 *ctxlen)
{
	return 0;
}
#ifdef CONFIG_KEYS

static int dummylsm_key_alloc(struct key *k, const struct cred *cred,
			     unsigned long flags)
{
	return 0;
}

static void dummylsm_key_free(struct key *k)
{
}

static int dummylsm_key_permission(key_ref_t key_ref,
				  const struct cred *cred,
				  unsigned perm)
{
	return 0;
}

static int dummylsm_key_getsecurity(struct key *key, char **_buffer)
{
	return 0;
}
#endif

#ifdef CONFIG_SECURITY_INFINIBAND
static int dummylsm_ib_pkey_access(void *ib_sec, u64 subnet_prefix, u16 pkey_val)
{
	return 0;
}

static int dummylsm_ib_endport_manage_subnet(void *ib_sec, const char *dev_name,
					    u8 port_num)
{
	return 0;
}

static int dummylsm_ib_alloc_security(void **ib_sec)
{
	return 0;
}

static void dummylsm_ib_free_security(void *ib_sec)
{
}
#endif

#ifdef CONFIG_BPF_SYSCALL
static int dummylsm_bpf(int cmd, union bpf_attr *attr,
				     unsigned int size)
{
	return 0;
}

static int bpf_fd_pass(struct file *file, u32 sid)
{
	return 0;
}

static int dummylsm_bpf_map(struct bpf_map *map, fmode_t fmode)
{
	return 0;
}

static int dummylsm_bpf_prog(struct bpf_prog *prog)
{
	return 0;
}

static int dummylsm_bpf_map_alloc(struct bpf_map *map)
{
	return 0;
}

static void dummylsm_bpf_map_free(struct bpf_map *map)
{
}

static int dummylsm_bpf_prog_alloc(struct bpf_prog_aux *aux)
{
	return 0;
}

static void dummylsm_bpf_prog_free(struct bpf_prog_aux *aux)
{
}
#endif

static struct security_hook_list dummylsm_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(binder_set_context_mgr, dummylsm_binder_set_context_mgr),
	LSM_HOOK_INIT(binder_transaction, dummylsm_binder_transaction),
	LSM_HOOK_INIT(binder_transfer_binder, dummylsm_binder_transfer_binder),
	LSM_HOOK_INIT(binder_transfer_file, dummylsm_binder_transfer_file),

	LSM_HOOK_INIT(ptrace_access_check, dummylsm_ptrace_access_check),
	LSM_HOOK_INIT(ptrace_traceme, dummylsm_ptrace_traceme),
	LSM_HOOK_INIT(capget, dummylsm_capget),
	LSM_HOOK_INIT(capset, dummylsm_capset),
	LSM_HOOK_INIT(capable, dummylsm_capable),
	LSM_HOOK_INIT(quotactl, dummylsm_quotactl),
	LSM_HOOK_INIT(quota_on, dummylsm_quota_on),
	LSM_HOOK_INIT(syslog, dummylsm_syslog),
	LSM_HOOK_INIT(vm_enough_memory, dummylsm_vm_enough_memory),

	LSM_HOOK_INIT(netlink_send, dummylsm_netlink_send),

	LSM_HOOK_INIT(bprm_set_creds, dummylsm_bprm_set_creds),
	LSM_HOOK_INIT(bprm_committing_creds, dummylsm_bprm_committing_creds),
	LSM_HOOK_INIT(bprm_committed_creds, dummylsm_bprm_committed_creds),

	LSM_HOOK_INIT(fs_context_dup, dummylsm_fs_context_dup),
	LSM_HOOK_INIT(fs_context_parse_param, dummylsm_fs_context_parse_param),

	LSM_HOOK_INIT(sb_alloc_security, dummylsm_sb_alloc_security),
	LSM_HOOK_INIT(sb_free_security, dummylsm_sb_free_security),
	LSM_HOOK_INIT(sb_eat_lsm_opts, dummylsm_sb_eat_lsm_opts),
	LSM_HOOK_INIT(sb_free_mnt_opts, dummylsm_free_mnt_opts),
	LSM_HOOK_INIT(sb_remount, dummylsm_sb_remount),
	LSM_HOOK_INIT(sb_kern_mount, dummylsm_sb_kern_mount),
	LSM_HOOK_INIT(sb_show_options, dummylsm_sb_show_options),
	LSM_HOOK_INIT(sb_statfs, dummylsm_sb_statfs),
	LSM_HOOK_INIT(sb_mount, dummylsm_mount),
	LSM_HOOK_INIT(sb_umount, dummylsm_umount),
	LSM_HOOK_INIT(sb_set_mnt_opts, dummylsm_set_mnt_opts),
	LSM_HOOK_INIT(sb_clone_mnt_opts, dummylsm_sb_clone_mnt_opts),
	LSM_HOOK_INIT(sb_add_mnt_opt, dummylsm_add_mnt_opt),

	LSM_HOOK_INIT(dentry_init_security, dummylsm_dentry_init_security),
	LSM_HOOK_INIT(dentry_create_files_as, dummylsm_dentry_create_files_as),

	LSM_HOOK_INIT(inode_alloc_security, dummylsm_inode_alloc_security),
	LSM_HOOK_INIT(inode_free_security, dummylsm_inode_free_security),
	LSM_HOOK_INIT(inode_init_security, dummylsm_inode_init_security),
	LSM_HOOK_INIT(inode_create, dummylsm_inode_create),
	LSM_HOOK_INIT(inode_link, dummylsm_inode_link),
	LSM_HOOK_INIT(inode_unlink, dummylsm_inode_unlink),
	LSM_HOOK_INIT(inode_symlink, dummylsm_inode_symlink),
	LSM_HOOK_INIT(inode_mkdir, dummylsm_inode_mkdir),
	LSM_HOOK_INIT(inode_rmdir, dummylsm_inode_rmdir),
	LSM_HOOK_INIT(inode_mknod, dummylsm_inode_mknod),
	LSM_HOOK_INIT(inode_rename, dummylsm_inode_rename),
	LSM_HOOK_INIT(inode_readlink, dummylsm_inode_readlink),
	LSM_HOOK_INIT(inode_follow_link, dummylsm_inode_follow_link),
	LSM_HOOK_INIT(inode_permission, dummylsm_inode_permission),
	LSM_HOOK_INIT(inode_setattr, dummylsm_inode_setattr),
	LSM_HOOK_INIT(inode_getattr, dummylsm_inode_getattr),
	LSM_HOOK_INIT(inode_setxattr, dummylsm_inode_setxattr),
	LSM_HOOK_INIT(inode_post_setxattr, dummylsm_inode_post_setxattr),
	LSM_HOOK_INIT(inode_getxattr, dummylsm_inode_getxattr),
	LSM_HOOK_INIT(inode_listxattr, dummylsm_inode_listxattr),
	LSM_HOOK_INIT(inode_removexattr, dummylsm_inode_removexattr),
	LSM_HOOK_INIT(inode_getsecurity, dummylsm_inode_getsecurity),
	LSM_HOOK_INIT(inode_setsecurity, dummylsm_inode_setsecurity),
	LSM_HOOK_INIT(inode_listsecurity, dummylsm_inode_listsecurity),
	LSM_HOOK_INIT(inode_getsecid, dummylsm_inode_getsecid),
	LSM_HOOK_INIT(inode_copy_up, dummylsm_inode_copy_up),
	LSM_HOOK_INIT(inode_copy_up_xattr, dummylsm_inode_copy_up_xattr),

	LSM_HOOK_INIT(kernfs_init_security, dummylsm_kernfs_init_security),

	LSM_HOOK_INIT(file_permission, dummylsm_file_permission),
	LSM_HOOK_INIT(file_alloc_security, dummylsm_file_alloc_security),
	LSM_HOOK_INIT(file_ioctl, dummylsm_file_ioctl),
	LSM_HOOK_INIT(mmap_file, dummylsm_mmap_file),
	LSM_HOOK_INIT(mmap_addr, dummylsm_mmap_addr),
	LSM_HOOK_INIT(file_mprotect, dummylsm_file_mprotect),
	LSM_HOOK_INIT(file_lock, dummylsm_file_lock),
	LSM_HOOK_INIT(file_fcntl, dummylsm_file_fcntl),
	LSM_HOOK_INIT(file_set_fowner, dummylsm_file_set_fowner),
	LSM_HOOK_INIT(file_send_sigiotask, dummylsm_file_send_sigiotask),
	LSM_HOOK_INIT(file_receive, dummylsm_file_receive),

	LSM_HOOK_INIT(file_open, dummylsm_file_open),

	LSM_HOOK_INIT(task_alloc, dummylsm_task_alloc),
	LSM_HOOK_INIT(cred_prepare, dummylsm_cred_prepare),
	LSM_HOOK_INIT(cred_transfer, dummylsm_cred_transfer),
	LSM_HOOK_INIT(cred_getsecid, dummylsm_cred_getsecid),
	LSM_HOOK_INIT(kernel_act_as, dummylsm_kernel_act_as),
	LSM_HOOK_INIT(kernel_create_files_as, dummylsm_kernel_create_files_as),
	LSM_HOOK_INIT(kernel_module_request, dummylsm_kernel_module_request),
	LSM_HOOK_INIT(kernel_load_data, dummylsm_kernel_load_data),
	LSM_HOOK_INIT(kernel_read_file, dummylsm_kernel_read_file),
	LSM_HOOK_INIT(task_setpgid, dummylsm_task_setpgid),
	LSM_HOOK_INIT(task_getpgid, dummylsm_task_getpgid),
	LSM_HOOK_INIT(task_getsid, dummylsm_task_getsid),
	LSM_HOOK_INIT(task_getsecid, dummylsm_task_getsecid),
	LSM_HOOK_INIT(task_setnice, dummylsm_task_setnice),
	LSM_HOOK_INIT(task_setioprio, dummylsm_task_setioprio),
	LSM_HOOK_INIT(task_getioprio, dummylsm_task_getioprio),
	LSM_HOOK_INIT(task_prlimit, dummylsm_task_prlimit),
	LSM_HOOK_INIT(task_setrlimit, dummylsm_task_setrlimit),
	LSM_HOOK_INIT(task_setscheduler, dummylsm_task_setscheduler),
	LSM_HOOK_INIT(task_getscheduler, dummylsm_task_getscheduler),
	LSM_HOOK_INIT(task_movememory, dummylsm_task_movememory),
	LSM_HOOK_INIT(task_kill, dummylsm_task_kill),
	LSM_HOOK_INIT(task_to_inode, dummylsm_task_to_inode),

	LSM_HOOK_INIT(ipc_permission, dummylsm_ipc_permission),
	LSM_HOOK_INIT(ipc_getsecid, dummylsm_ipc_getsecid),

	LSM_HOOK_INIT(msg_msg_alloc_security, dummylsm_msg_msg_alloc_security),

	LSM_HOOK_INIT(msg_queue_alloc_security,
			dummylsm_msg_queue_alloc_security),
	LSM_HOOK_INIT(msg_queue_associate, dummylsm_msg_queue_associate),
	LSM_HOOK_INIT(msg_queue_msgctl, dummylsm_msg_queue_msgctl),
	LSM_HOOK_INIT(msg_queue_msgsnd, dummylsm_msg_queue_msgsnd),
	LSM_HOOK_INIT(msg_queue_msgrcv, dummylsm_msg_queue_msgrcv),

	LSM_HOOK_INIT(shm_alloc_security, dummylsm_shm_alloc_security),
	LSM_HOOK_INIT(shm_associate, dummylsm_shm_associate),
	LSM_HOOK_INIT(shm_shmctl, dummylsm_shm_shmctl),
	LSM_HOOK_INIT(shm_shmat, dummylsm_shm_shmat),

	LSM_HOOK_INIT(sem_alloc_security, dummylsm_sem_alloc_security),
	LSM_HOOK_INIT(sem_associate, dummylsm_sem_associate),
	LSM_HOOK_INIT(sem_semctl, dummylsm_sem_semctl),
	LSM_HOOK_INIT(sem_semop, dummylsm_sem_semop),

	LSM_HOOK_INIT(d_instantiate, dummylsm_d_instantiate),

	LSM_HOOK_INIT(getprocattr, dummylsm_getprocattr),
	LSM_HOOK_INIT(setprocattr, dummylsm_setprocattr),

	LSM_HOOK_INIT(ismaclabel, dummylsm_ismaclabel),
	LSM_HOOK_INIT(secid_to_secctx, dummylsm_secid_to_secctx),
	LSM_HOOK_INIT(secctx_to_secid, dummylsm_secctx_to_secid),
	LSM_HOOK_INIT(release_secctx, dummylsm_release_secctx),
	LSM_HOOK_INIT(inode_invalidate_secctx, dummylsm_inode_invalidate_secctx),
	LSM_HOOK_INIT(inode_notifysecctx, dummylsm_inode_notifysecctx),
	LSM_HOOK_INIT(inode_setsecctx, dummylsm_inode_setsecctx),
	LSM_HOOK_INIT(inode_getsecctx, dummylsm_inode_getsecctx),

	LSM_HOOK_INIT(unix_stream_connect, dummylsm_socket_unix_stream_connect),
	LSM_HOOK_INIT(unix_may_send, dummylsm_socket_unix_may_send),

	LSM_HOOK_INIT(socket_create, dummylsm_socket_create),
	LSM_HOOK_INIT(socket_post_create, dummylsm_socket_post_create),
	LSM_HOOK_INIT(socket_socketpair, dummylsm_socket_socketpair),
	LSM_HOOK_INIT(socket_bind, dummylsm_socket_bind),
	LSM_HOOK_INIT(socket_connect, dummylsm_socket_connect),
	LSM_HOOK_INIT(socket_listen, dummylsm_socket_listen),
	LSM_HOOK_INIT(socket_accept, dummylsm_socket_accept),
	LSM_HOOK_INIT(socket_sendmsg, dummylsm_socket_sendmsg),
	LSM_HOOK_INIT(socket_recvmsg, dummylsm_socket_recvmsg),
	LSM_HOOK_INIT(socket_getsockname, dummylsm_socket_getsockname),
	LSM_HOOK_INIT(socket_getpeername, dummylsm_socket_getpeername),
	LSM_HOOK_INIT(socket_getsockopt, dummylsm_socket_getsockopt),
	LSM_HOOK_INIT(socket_setsockopt, dummylsm_socket_setsockopt),
	LSM_HOOK_INIT(socket_shutdown, dummylsm_socket_shutdown),
	LSM_HOOK_INIT(socket_sock_rcv_skb, dummylsm_socket_sock_rcv_skb),
	LSM_HOOK_INIT(socket_getpeersec_stream,
			dummylsm_socket_getpeersec_stream),
	LSM_HOOK_INIT(socket_getpeersec_dgram, dummylsm_socket_getpeersec_dgram),
	LSM_HOOK_INIT(sk_alloc_security, dummylsm_sk_alloc_security),
	LSM_HOOK_INIT(sk_free_security, dummylsm_sk_free_security),
	LSM_HOOK_INIT(sk_clone_security, dummylsm_sk_clone_security),
	LSM_HOOK_INIT(sk_getsecid, dummylsm_sk_getsecid),
	LSM_HOOK_INIT(sock_graft, dummylsm_sock_graft),
	LSM_HOOK_INIT(sctp_assoc_request, dummylsm_sctp_assoc_request),
	LSM_HOOK_INIT(sctp_sk_clone, dummylsm_sctp_sk_clone),
	LSM_HOOK_INIT(sctp_bind_connect, dummylsm_sctp_bind_connect),
	LSM_HOOK_INIT(inet_conn_request, dummylsm_inet_conn_request),
	LSM_HOOK_INIT(inet_csk_clone, dummylsm_inet_csk_clone),
	LSM_HOOK_INIT(inet_conn_established, dummylsm_inet_conn_established),
	LSM_HOOK_INIT(secmark_relabel_packet, dummylsm_secmark_relabel_packet),
	LSM_HOOK_INIT(secmark_refcount_inc, dummylsm_secmark_refcount_inc),
	LSM_HOOK_INIT(secmark_refcount_dec, dummylsm_secmark_refcount_dec),
	LSM_HOOK_INIT(req_classify_flow, dummylsm_req_classify_flow),
	LSM_HOOK_INIT(tun_dev_alloc_security, dummylsm_tun_dev_alloc_security),
	LSM_HOOK_INIT(tun_dev_free_security, dummylsm_tun_dev_free_security),
	LSM_HOOK_INIT(tun_dev_create, dummylsm_tun_dev_create),
	LSM_HOOK_INIT(tun_dev_attach_queue, dummylsm_tun_dev_attach_queue),
	LSM_HOOK_INIT(tun_dev_attach, dummylsm_tun_dev_attach),
	LSM_HOOK_INIT(tun_dev_open, dummylsm_tun_dev_open),
#ifdef CONFIG_SECURITY_INFINIBAND
	LSM_HOOK_INIT(ib_pkey_access, dummylsm_ib_pkey_access),
	LSM_HOOK_INIT(ib_endport_manage_subnet,
		      dummylsm_ib_endport_manage_subnet),
	LSM_HOOK_INIT(ib_alloc_security, dummylsm_ib_alloc_security),
	LSM_HOOK_INIT(ib_free_security, dummylsm_ib_free_security),
#endif

#ifdef CONFIG_KEYS
	LSM_HOOK_INIT(key_alloc, dummylsm_key_alloc),
	LSM_HOOK_INIT(key_free, dummylsm_key_free),
	LSM_HOOK_INIT(key_permission, dummylsm_key_permission),
	LSM_HOOK_INIT(key_getsecurity, dummylsm_key_getsecurity),
#endif

#ifdef CONFIG_BPF_SYSCALL
	LSM_HOOK_INIT(bpf, dummylsm_bpf),
	LSM_HOOK_INIT(bpf_map, dummylsm_bpf_map),
	LSM_HOOK_INIT(bpf_prog, dummylsm_bpf_prog),
	LSM_HOOK_INIT(bpf_map_alloc_security, dummylsm_bpf_map_alloc),
	LSM_HOOK_INIT(bpf_prog_alloc_security, dummylsm_bpf_prog_alloc),
	LSM_HOOK_INIT(bpf_map_free_security, dummylsm_bpf_map_free),
	LSM_HOOK_INIT(bpf_prog_free_security, dummylsm_bpf_prog_free),
#endif
};

static __init int dummylsm_init(void)
{
	pr_info("DummyLSM:  Initializing.\n");

	default_noexec = !(VM_DATA_DEFAULT_FLAGS & VM_EXEC);

	security_add_hooks(dummylsm_hooks, ARRAY_SIZE(dummylsm_hooks), "dummylsm");

	if (dummylsm_enforcing_boot)
		pr_debug("DummyLSM:  Starting in enforcing mode\n");
	else
		pr_debug("DummyLSM:  Starting in permissive mode\n");

	return 0;
}

/* DummyLSM requires early initialization in order to label
   all processes and objects when they are created. */
DEFINE_LSM(dummylsm) = {
	.name = "dummylsm",
	.flags = LSM_FLAG_LEGACY_MAJOR | LSM_FLAG_EXCLUSIVE,
	.enabled = &dummylsm_enabled,
	.init = dummylsm_init,
};

#if 0
int dummylsm_disable(struct dummylsm_state *state)
{
	if (state->initialized) {
		/* Not permitted after initial policy load. */
		return -EINVAL;
	}

	if (state->disabled) {
		/* Only do this once. */
		return -EINVAL;
	}

	state->disabled = 1;

	pr_info("DummyLSM:  Disabled at runtime.\n");

	dummylsm_enabled = 0;

	security_delete_hooks(dummylsm_hooks, ARRAY_SIZE(dummylsm_hooks));

	return 0;
}
#endif
