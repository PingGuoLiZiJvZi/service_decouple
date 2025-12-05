#ifndef __REDIRECT_ERR_H__
#define __REDIRECT_ERR_H__
struct net_device /* same as kernel's struct net_device */
{
	int ifindex;
	struct dev_ifalias *ifalias;
};

struct bpf_prog
{
	u16 pages;								   /* Number of allocated pages */
	u16 jited : 1,							   /* Is our filter JIT'ed? */
		jit_requested : 1,					   /* archs need to JIT the prog */
		gpl_compatible : 1,					   /* Is filter GPL compatible? */
		cb_access : 1,						   /* Is control block accessed? */
		dst_needed : 1,						   /* Do we need dst entry? */
		blinded : 1,						   /* Was blinded */
		is_func : 1,						   /* program is a bpf function */
		kprobe_override : 1,				   /* Do we override a kprobe? */
		has_callchain_buf : 1,				   /* callchain buffer allocated? */
		enforce_expected_attach_type : 1,	   /* Enforce expected_attach_type checking at attach time */
		call_get_stack : 1,					   /* Do we call bpf_get_stack() or bpf_get_stackid() */
		call_get_func_ip : 1;				   /* Do we call get_func_ip() */
	enum bpf_prog_type type;				   /* Type of BPF program */
	enum bpf_attach_type expected_attach_type; /* For some prog types */
	u32 len;								   /* Number of filter blocks */
	u32 jited_len;							   /* Size of jited insns in bytes */
	u8 tag[BPF_TAG_SIZE];
	struct bpf_prog_stats __percpu *stats;
	int __percpu *active;
	unsigned int (*bpf_func)(const void *ctx,
							 const struct bpf_insn *insn);
	struct bpf_prog_aux *aux;		   /* Auxiliary fields */
	struct sock_fprog_kern *orig_prog; /* Original BPF program */
	/* Instructions for interpreter */
	struct sock_filter insns[0];
	struct bpf_insn insnsi[];
};

#endif // __REDIRECT_ERR_H__