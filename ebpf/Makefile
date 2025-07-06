KERN_TARGET := xdp_kern_feature_extract
USER_TARGET := xdp_user

all:
	@clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c $(KERN_TARGET).c -o $(KERN_TARGET).o
	@gcc $(USER_TARGET).c -lbpf -lm -lelf -o $(USER_TARGET)
