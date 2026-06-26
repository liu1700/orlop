#include <tunables/global>

# orlop-agent AppArmor profile.
#
# Diff from Docker's built-in `docker-default` profile: this one allows
# `mount fstype=fuse*` so the in-container orlop binary can FUSE-mount the
# user's Orlop disk at /workspace. Everything else docker-default forbids
# stays forbidden — in particular, all other mount types are implicitly
# denied because the profile lists explicit `mount` rules (AppArmor falls
# back to deny for any class of operation that has at least one explicit
# rule and no matching allow).
#
# Loaded on the host with:
#     sudo apparmor_parser -r /etc/apparmor.d/orlop-agent
#
# Applied to containers with:
#     docker run --security-opt apparmor=orlop-agent ...
#
# Audit: switching from `apparmor=unconfined` to this profile removes the
# ability to do `mount --bind`, `mount -t tmpfs`, `mount -t proc`, kernel
# module loading, `/proc/sys/kernel/*` writes, `/sys/firmware` access, and
# the other escape paths docker-default already covers. We keep capability,
# network, and file unrestricted to match docker-default's posture —
# tightening those further is a separate hardening pass.

profile orlop-agent flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  network,
  capability,
  file,
  umount,

  # /proc hardening (same as docker-default).
  deny @{PROC}/* w,
  deny @{PROC}/{[^1-9],[^1-9][^0-9],[^1-9/][^0-9]*,[^1-9][^0-9]/**} w,
  deny @{PROC}/sys/[^k]** w,
  deny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,
  deny @{PROC}/sysrq-trigger rwklx,
  deny @{PROC}/kcore rwklx,

  # /sys hardening (same as docker-default).
  deny /sys/[^f]*/** wklx,
  deny /sys/f[^s]*/** wklx,
  deny /sys/fs/[^c]*/** wklx,
  deny /sys/fs/c[^g]*/** wklx,
  deny /sys/fs/cg[^r]*/** wklx,
  deny /sys/firmware/** rwklx,
  deny /sys/kernel/security/** rwklx,

  # The Orlop-specific allow: FUSE mount only. Anything else needing the
  # mount syscall (bind, tmpfs, proc, overlay, ...) is implicitly denied.
  # Both bare `fuse` and `fuse.<subtype>` are covered; Linux kernels deliver
  # the type either way depending on libfuse version.
  mount fstype=fuse,
  mount fstype=fuse.*,

  # Lets `ps` / `top` work for processes inside the same profile.
  ptrace (trace,read,tracedby,readby) peer=orlop-agent,

  # Signal flow within the profile (`docker stop` → entrypoint SIGTERM, etc.)
  signal (send,receive) peer=orlop-agent,
}
