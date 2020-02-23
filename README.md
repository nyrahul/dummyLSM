# Dummy Linux Security Module (LSM) (for experimentation)

LSMs provide a way to enforce mandatory access controls (MAC) for the various
operations dependent on the kernel. Most of the operations typically depend on
kernel (at-least in case of monolithic kernels) and LSMs which provides hooks
right into the kernel allow you to write a (ideally generic) security module
and then policy-control it from the user-space.

While trying to implement a sample LSM, I figured out that there are no good
startup points. Thus I tried writing my own LSM (mostly copyiny hooks.c from
selinux) and then stripping off any selinux specific code.

Aim is to provide a barebone LSM for experimentation for someone to start off
with.

Compiled on:
* Kernel v5.3.0

Steps (target folder is `LINUX-KERNEL-SRC/security`):
1. Update `SRC/security/{Kconfig,Makefile}` entries for `dummylsm`. (Check sample Kconfig/Makefile).
2. Copy `dummylsm` folder to `SRC/security`
3. Run `make menuconfig` and enable `dummylsm`
4. `make -j $(nproc)`

